from __future__ import annotations

import logging
import hashlib
import hmac
import math
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path

from auto_trader.brokers.alpaca import AlpacaBroker
from auto_trader.brokers.simulated import SimulatedBroker
from auto_trader.config import BotConfig
from auto_trader.controls import merge_control_marker
from auto_trader.covariance_evidence import SignedCovarianceEvidenceProvider
from auto_trader.borrow_evidence import SignedBorrowEvidenceProvider
from auto_trader.deployment import (
    DeploymentApprovalVerification,
    target_plan_deployment_binding,
    verify_deployment_approval,
)
from auto_trader.engine import AutomationEngine
from auto_trader.emergency_journal import EmergencyJournal
from auto_trader.models import OrderSide, RoutineSubmissionContext
from auto_trader.plan_auth import is_strong_plan_authentication_key
from auto_trader.store import StateStore


def configure_logging(config: BotConfig) -> logging.Logger:
    config.log_path.parent.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("quant_auto_trader")
    logger.setLevel(logging.INFO)
    if logger.handlers:
        return logger
    formatter = logging.Formatter(
        "%(asctime)s %(levelname)s %(name)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )
    file_handler = RotatingFileHandler(
        config.log_path, maxBytes=5_000_000, backupCount=5, encoding="utf-8"
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    console = logging.StreamHandler()
    console.setFormatter(formatter)
    logger.addHandler(console)
    return logger


def build_engine(
    config: BotConfig,
    *,
    emergency_only: bool = False,
) -> AutomationEngine:
    """Build the trading engine, optionally for the risk-reducing kill path only.

    ``emergency_only`` never grants routine order authority: the Alpaca adapter is
    created without an approval deadline, so its ordinary submission method remains
    fail-closed. It only prevents an expired/corrupt approval from trapping exposure
    when a separate kill process must reconnect after the main daemon has stopped.
    """
    if emergency_only and config.broker == "alpaca":
        config.validate_emergency()
    else:
        config.validate()
    live_execution = (
        config.broker == "alpaca" and not config.alpaca_paper and config.execution_enabled
    )
    emergency_state_path: Path | None = None
    emergency_state_reason = ""
    if live_execution:
        database_path = Path(config.database_path).resolve(strict=False)
        identity_path = database_path.with_suffix(database_path.suffix + ".identity")
        missing = [str(path) for path in (database_path, identity_path) if not path.exists()]
        if missing:
            if emergency_only:
                # Never recreate the authoritative live database implicitly. A separate
                # recovery ledger lets a dedicated-account kill reconcile the broker
                # while ensuring a later normal startup still refuses the missing state.
                emergency_state_path = database_path.with_name(
                    database_path.name + ".emergency-recovery.sqlite3"
                )
                emergency_state_reason = "authoritative_live_state_unavailable"
            else:
                raise RuntimeError(
                    "Live execution refuses to initialize replacement state. Missing required "
                    "database/identity files: "
                    + ", ".join(missing)
                    + ". Restore and reconcile the prior state, or initialize and validate a "
                    "new state in paper/plan-only mode before enabling live orders."
                )
    recovery_state_authentication_key = hmac.new(
        config.emergency_authentication_key_bytes,
        b"quant-auto-trader-emergency-recovery-state-v2\0"
        + config.emergency_journal_scope.encode("ascii"),
        hashlib.sha256,
    ).digest()
    if emergency_only and not is_strong_plan_authentication_key(
        config.plan_authentication_key
    ):
        # Missing/corrupt routine secrets must not trap exposure, but must never cause
        # the authoritative ledger to be opened without authentication. The fixed
        # recovery ledger uses the independent, domain-separated emergency key. It
        # never reuses the plan key or derives control identity from broker secrets.
        database_path = Path(config.database_path).resolve(strict=False)
        emergency_state_path = database_path.with_name(
            database_path.name + ".emergency-recovery.sqlite3"
        )
        emergency_state_reason = "plan_authentication_key_unavailable"
        state_authentication_key = recovery_state_authentication_key
    else:
        state_authentication_key = config.plan_authentication_key_bytes
    if emergency_state_path is not None:
        state_authentication_key = recovery_state_authentication_key
    deployment_approval: DeploymentApprovalVerification | None = None
    account_verification: DeploymentApprovalVerification | None = None
    connected_account_id = ""
    routine_authorization_check = None
    alpaca_broker = None
    store: StateStore | None = None
    engine: AutomationEngine | None = None
    if config.broker == "alpaca" and config.execution_enabled and not emergency_only:
        deployment_approval = verify_deployment_approval(config)
        if not deployment_approval.verified:
            detail = "; ".join(deployment_approval.errors)
            raise RuntimeError(
                "Alpaca execution requires a valid signed deployment approval: " + detail
            )
        startup_approval_hash = deployment_approval.approval_hash
        startup_approval_id = deployment_approval.approval_id or ""

        def current_verified_approval(
            *,
            actual_account_id: str | None = None,
        ) -> DeploymentApprovalVerification:
            current = verify_deployment_approval(
                config,
                actual_account_id=actual_account_id,
            )
            if not current.verified:
                raise RuntimeError(
                    "Routine Alpaca authorization was revoked or changed: "
                    + "; ".join(current.errors)
                )
            approval_hash_changed = not hmac.compare_digest(
                current.approval_hash,
                startup_approval_hash,
            )
            approval_id_changed = not hmac.compare_digest(
                current.approval_id or "",
                startup_approval_id,
            )
            if approval_hash_changed or approval_id_changed:
                raise RuntimeError(
                    "Routine Alpaca authorization changed since engine startup; "
                    "approval rotation requires a clean restart and a newly generated plan."
                )
            return current

        def routine_authorization_check(
            symbol: str | None = None,
            qty: float | None = None,
            side: OrderSide | None = None,
            limit_price: float | None = None,
            submission_context: RoutineSubmissionContext | None = None,
        ) -> datetime | None:
            # This callback is invoked by AlpacaBroker after duplicate-ID lookup and
            # quote construction, immediately before its submit_order REST request.
            if config.kill_switch_path.exists():
                raise RuntimeError(
                    "Routine Alpaca submission was blocked by the filesystem kill switch."
                )
            if store is None:
                raise RuntimeError(
                    "Routine Alpaca submission has no authenticated state store."
                )
            if alpaca_broker is None:
                raise RuntimeError("Routine Alpaca submission has no authenticated broker.")
            if engine is None:
                raise RuntimeError("Routine Alpaca submission has no initialized engine.")

            # A no-economics call is a read-only governance probe used by deployment
            # diagnostics. AlpacaBroker itself always supplies all four final fields at
            # the mutation boundary below.
            if symbol is None or qty is None or side is None or limit_price is None:
                actual_account_id = alpaca_broker.get_account_identity()
                if not hmac.compare_digest(
                    actual_account_id.encode("utf-8"),
                    config.alpaca_account_id.encode("utf-8"),
                ) or not hmac.compare_digest(
                    actual_account_id.encode("utf-8"),
                    connected_account_id.encode("utf-8"),
                ):
                    raise RuntimeError(
                        "Routine Alpaca submission was blocked because the connected account "
                        "identity changed or no longer matches ALPACA_ACCOUNT_ID."
                    )
                current_verified_approval(actual_account_id=actual_account_id)
                store.verify_critical_integrity()
                halt = store.halt_state()
                if not halt or halt.get("active"):
                    raise RuntimeError(
                        "Routine Alpaca submission was blocked by a concurrent authenticated halt."
                    )
                if config.kill_switch_path.exists():
                    raise RuntimeError(
                        "Routine Alpaca submission was blocked by a concurrent kill switch."
                    )
                return None

            qty = float(qty)
            limit_price = float(limit_price)
            if (
                not math.isfinite(qty)
                or qty <= 0.0
                or not math.isfinite(limit_price)
                or limit_price <= 0.0
            ):
                raise RuntimeError("Routine Alpaca final economics are invalid.")
            child_authorization = None
            if submission_context is not None:
                if not isinstance(submission_context, RoutineSubmissionContext):
                    raise RuntimeError("Routine Alpaca submission context is invalid.")
                child_authorization = engine._require_active_routine_child_authorization(
                    client_order_id=submission_context.client_order_id,
                    symbol=str(symbol),
                    qty=qty,
                    side=side,
                )
                quote_timestamp = submission_context.quote_timestamp
                if (
                    quote_timestamp.tzinfo is None
                    or quote_timestamp.utcoffset() is None
                ):
                    raise RuntimeError("Routine Alpaca quote timestamp is not absolute.")
                quote_age = (
                    datetime.now(timezone.utc)
                    - quote_timestamp.astimezone(timezone.utc)
                ).total_seconds()
                if (
                    not math.isfinite(quote_age)
                    or quote_age < -5.0
                    or quote_age > config.max_execution_price_age_seconds
                ):
                    raise RuntimeError("Routine Alpaca quote aged out during authorization.")
                expected_limit = alpaca_broker._marketable_limit_price(
                    float(submission_context.midpoint),
                    side,
                )
                if not math.isclose(
                    expected_limit,
                    limit_price,
                    abs_tol=max(1e-8, abs(limit_price) * 1e-10),
                ):
                    raise RuntimeError("Routine Alpaca limit is not bound to its verified quote.")
            # Re-read all broker risk state after the final quote is known. This is the
            # last authorization boundary before the REST mutation.
            bounded_account_reader = getattr(
                alpaca_broker,
                "get_account_for_routine_authorization",
                None,
            )
            current_account = (
                bounded_account_reader()
                if callable(bounded_account_reader)
                else alpaca_broker.get_account()
            )
            current_positions = alpaca_broker.get_positions()
            account_open_orders = alpaca_broker.list_open_orders(None)
            foreign_orders = engine._foreign_dedicated_orders(account_open_orders)
            if config.dedicated_account and foreign_orders:
                reason = "unauthorized_dedicated_account_order"
                try:
                    control = merge_control_marker(
                        config.kill_switch_path,
                        reason,
                        flatten=True,
                    )
                    reason = control.reason
                finally:
                    # A control-volume failure must not prevent the independent
                    # authenticated halt latch from being attempted.
                    store.request_halt(reason, flatten=True)
                raise RuntimeError(
                    "Routine Alpaca submission was blocked by unauthorized "
                    "dedicated-account activity."
                )
            conflicts = list(account_open_orders)
            if conflicts:
                raise RuntimeError(
                    "Routine Alpaca submission was blocked by an account-wide open-order race."
                )

            child_symbol = str(symbol).upper()
            if child_authorization is not None:
                active_plan = engine._active_routine_plan
                if active_plan is None:
                    raise RuntimeError(
                        "Routine Alpaca submission lost its authenticated active plan."
                    )
                foreign_positions = engine._foreign_dedicated_positions(
                    active_plan,
                    current_positions,
                )
                if foreign_positions:
                    engine._persist_foreign_position_halt(
                        foreign_positions,
                        stage="alpaca_final_authorization",
                    )
                    engine._routine_emergency_triggered = True
                    engine.emergency_flatten(
                        "unauthorized_dedicated_account_position",
                        persist_halt=True,
                    )
                    raise RuntimeError(
                        "Routine Alpaca submission was blocked by a dedicated-account "
                        "position outside the authenticated plan."
                    )
            non_child_held_symbols: list[str] = []
            for position_symbol, position in current_positions.items():
                position_qty = float(position.qty)
                if not math.isfinite(position_qty):
                    raise RuntimeError(
                        "Routine Alpaca projected exposure cannot be valued safely."
                    )
                normalized_symbol = str(position_symbol).upper()
                if abs(position_qty) > 1e-10 and normalized_symbol != child_symbol:
                    non_child_held_symbols.append(normalized_symbol)
            fresh_position_prices: dict[str, float] = {}
            if non_child_held_symbols:
                fresh_position_prices = {
                    str(price_symbol).upper(): float(price)
                    for price_symbol, price in alpaca_broker.get_latest_prices(
                        sorted(set(non_child_held_symbols))
                    ).items()
                }
            missing_fresh_marks = sorted(
                symbol
                for symbol in set(non_child_held_symbols)
                if symbol not in fresh_position_prices
                or not math.isfinite(fresh_position_prices[symbol])
                or fresh_position_prices[symbol] <= 0.0
            )
            if missing_fresh_marks:
                raise RuntimeError(
                    "Routine Alpaca final authorization lacks fresh quote-compliant "
                    "prices for held positions: " + ", ".join(missing_fresh_marks)
                )

            equity = float(current_account.equity)
            buying_power = float(current_account.buying_power)
            if (
                not math.isfinite(equity)
                or equity <= 0.0
                or not math.isfinite(buying_power)
                or buying_power < 0.0
            ):
                raise RuntimeError(
                    "Routine Alpaca submission was blocked by invalid refreshed account risk."
                )
            current_position = current_positions.get(str(symbol).upper())
            current_qty = float(current_position.qty) if current_position is not None else 0.0
            if child_authorization is not None:
                engine._validate_child_target_progress(
                    current_qty=current_qty,
                    target_qty=child_authorization.target_qty,
                    side=side,
                    qty=qty,
                    phase=child_authorization.phase,
                    expected_current_qty=child_authorization.current_qty,
                )
            signed_qty = qty if side == OrderSide.BUY else -qty
            projected_qty = current_qty + signed_qty
            tolerance = max(1e-8, abs(current_qty) * 1e-8, qty * 1e-8)
            if (
                current_qty > tolerance and projected_qty < -tolerance
            ) or (
                current_qty < -tolerance and projected_qty > tolerance
            ):
                raise RuntimeError(
                    "Routine Alpaca submission was blocked because refreshed economics "
                    "would cross zero."
                )
            risk_reducing = abs(projected_qty) <= abs(current_qty) + tolerance
            final_notional = qty * limit_price
            if not risk_reducing:
                buffered_buying_power = max(
                    buying_power * (1.0 - config.buying_power_buffer), 0.0
                )
                child_cap = config.max_single_order_notional_pct * equity
                if final_notional > buffered_buying_power + 1e-6:
                    raise RuntimeError(
                        "Routine Alpaca final-limit notional exceeds refreshed buffered "
                        "buying power."
                    )
                if final_notional > child_cap + 1e-6:
                    raise RuntimeError(
                        "Routine Alpaca final-limit notional exceeds the refreshed child cap."
                    )

            current_gross = 0.0
            projected_gross = 0.0
            projected_max_position = 0.0
            seen_symbol = False
            for position_symbol, position in current_positions.items():
                position_qty = float(position.qty)
                if abs(position_qty) <= 1e-10:
                    continue
                normalized_symbol = str(position_symbol).upper()
                price = (
                    limit_price
                    if normalized_symbol == child_symbol
                    else fresh_position_prices[normalized_symbol]
                )
                if (
                    not math.isfinite(position_qty)
                    or not math.isfinite(price)
                    or price <= 0.0
                ):
                    raise RuntimeError(
                        "Routine Alpaca projected exposure cannot be valued safely."
                )
                current_gross += abs(position_qty * price)
                if normalized_symbol == child_symbol:
                    position_qty = projected_qty
                    seen_symbol = True
                projected_value = position_qty * price
                projected_gross += abs(projected_value)
                projected_max_position = max(
                    projected_max_position, abs(projected_value) / equity
                )
            if not seen_symbol:
                projected_value = projected_qty * limit_price
                projected_gross += abs(projected_value)
                projected_max_position = max(
                    projected_max_position, abs(projected_value) / equity
                )
            current_gross_ratio = current_gross / equity
            projected_gross_ratio = projected_gross / equity
            if risk_reducing:
                if projected_gross_ratio > current_gross_ratio + 1e-8:
                    raise RuntimeError(
                        "Routine Alpaca purported reduction increases refreshed gross exposure."
                    )
            else:
                gross_limit = (
                    config.strategy.portfolio.max_gross_leverage
                    + config.actual_gross_exposure_tolerance
                )
                if projected_gross_ratio > gross_limit + 1e-8:
                    raise RuntimeError(
                        "Routine Alpaca projected gross exposure exceeds the live limit."
                    )
                if (
                    projected_max_position
                    > config.strategy.portfolio.max_position_weight + 1e-8
                ):
                    raise RuntimeError(
                        "Routine Alpaca projected position exposure exceeds the live cap."
                    )
            if child_authorization is not None:
                transient_prices = dict(fresh_position_prices)
                transient_prices[child_symbol] = limit_price
                engine._validate_transient_child_exposure(
                    active_plan,
                    current_positions,
                    transient_prices,
                    account_equity=equity,
                    symbol=child_symbol,
                    side=side,
                    qty=qty,
                    target_qty=child_authorization.target_qty,
                    phase=child_authorization.phase,
                    expected_current_qty=child_authorization.current_qty,
                )
            current_decision = engine._evaluate_risk(
                current_account, current_account.timestamp
            )
            if (
                not current_decision.allow_new_risk
                or current_decision.flatten
                or current_decision.halt
            ):
                raise RuntimeError(
                    "Routine Alpaca submission was blocked by refreshed account risk: "
                    + current_decision.reason
                )
            actual_account_id = alpaca_broker.get_account_identity()
            if not hmac.compare_digest(
                actual_account_id.encode("utf-8"),
                config.alpaca_account_id.encode("utf-8"),
            ) or not hmac.compare_digest(
                actual_account_id.encode("utf-8"),
                connected_account_id.encode("utf-8"),
            ):
                raise RuntimeError(
                    "Routine Alpaca submission was blocked because the connected account "
                    "identity changed or no longer matches ALPACA_ACCOUNT_ID."
                )
            current_verified_approval(actual_account_id=actual_account_id)
            # Close halt races while the account and signed approval were being read.
            store.verify_critical_integrity()
            halt = store.halt_state()
            if not halt or halt.get("active"):
                raise RuntimeError(
                    "Routine Alpaca submission was blocked by a concurrent authenticated halt."
                )
            if config.kill_switch_path.exists():
                raise RuntimeError(
                    "Routine Alpaca submission was blocked by a concurrent kill switch."
                )
            # Borrow terms are reloaded at the last child boundary. This happens after
            # refreshed account/position economics and before the state-mutating REST
            # request, so a locate removal, recall, rate breach, or evidence rollback
            # cannot be hidden behind the snapshot validated before cancellation.
            borrow_positions = alpaca_broker.get_positions()
            if engine._position_quantities_changed(current_positions, borrow_positions):
                reason = "routine_position_changed_during_final_authorization"
                store.request_halt(reason, flatten=True)
                engine._routine_emergency_triggered = True
                engine.emergency_flatten(reason, persist_halt=True)
                raise RuntimeError(
                    "Routine Alpaca submission was blocked because position quantities "
                    "changed during final authorization; emergency reconciliation completed."
                )
            active_session = engine._active_routine_execution_date
            active_plan = engine._active_routine_plan
            if active_session is None or active_plan is None:
                raise RuntimeError(
                    "Routine Alpaca submission has no authenticated active plan/session."
                )
            boundary_clock = alpaca_broker.get_market_clock()
            engine._require_governed_execution_window(
                boundary_clock,
                intended_session=active_session,
                context="Final routine Alpaca authorization before borrow evidence",
            )
            boundary_position = borrow_positions.get(child_symbol)
            boundary_current_qty = (
                float(boundary_position.qty) if boundary_position is not None else 0.0
            )
            boundary_projected_qty = boundary_current_qty + signed_qty
            projected_shorts: list[str] = []
            projected_short_quantities: dict[str, float] = {}
            if side == OrderSide.SELL:
                # Any sell can become a short if an external fill races the last
                # snapshot. Require locate capacity through the deployment's full
                # per-name cap, not merely the apparently projected quantity.
                maximum_name_quantity = (
                    config.strategy.portfolio.max_position_weight
                    * equity
                    / limit_price
                )
                projected_shorts.append(child_symbol)
                projected_short_quantities[child_symbol] = max(
                    maximum_name_quantity + qty,
                    max(-boundary_projected_qty, 0.0),
                )
            elif boundary_projected_qty < -tolerance:
                projected_shorts.append(child_symbol)
                projected_short_quantities[child_symbol] = abs(
                    boundary_projected_qty
                )
            borrow_evidence = engine._enforce_governed_borrow_or_emergency_reduce(
                active_plan,
                intended_session=active_session,
                current_positions=borrow_positions,
                projected_short_symbols=projected_shorts,
                projected_short_quantities=projected_short_quantities,
                clock_timestamp=boundary_clock.timestamp,
                stage=f"final_child:{child_symbol}:{side.value}",
            )

            post_evidence_positions = alpaca_broker.get_positions()
            if engine._position_quantities_changed(
                borrow_positions, post_evidence_positions
            ):
                reason = "routine_position_changed_during_borrow_verification"
                store.request_halt(reason, flatten=True)
                engine._routine_emergency_triggered = True
                engine.emergency_flatten(reason, persist_halt=True)
                raise RuntimeError(
                    "Routine Alpaca submission was blocked because position quantities "
                    "changed during borrow verification; emergency reconciliation completed."
                )

            store.verify_critical_integrity()
            halt = store.halt_state()
            if not halt or halt.get("active"):
                raise RuntimeError(
                    "Routine Alpaca submission was blocked by a concurrent authenticated halt."
                )
            if config.kill_switch_path.exists():
                raise RuntimeError(
                    "Routine Alpaca submission was blocked by a concurrent kill switch."
                )
            # Evidence verification and authenticated audit writes are read-heavy. Make
            # the final broker-clock read and cheap per-term age recheck only after the
            # remaining state/marker reads, immediately before the REST mutation.
            boundary_clock = alpaca_broker.get_market_clock()
            deadline = engine._require_governed_execution_window(
                boundary_clock,
                intended_session=active_session,
                context="Final routine Alpaca authorization after borrow evidence",
            )
            boundary_wall_clock = (
                engine._enforce_governed_borrow_freshness_or_emergency_reduce(
                    active_plan,
                    borrow_evidence,
                    intended_session=active_session,
                    clock_timestamp=boundary_clock.timestamp,
                    stage=(
                        f"final_child:{child_symbol}:{side.value}:"
                        "post_verification_freshness"
                    ),
                )
            )
            if boundary_wall_clock >= deadline:
                raise RuntimeError(
                    "Routine Alpaca submission was blocked at the hard 09:35 "
                    "benchmark deadline."
                )
            if submission_context is not None and submission_context.final_commit:
                commit_positions = alpaca_broker.get_positions()
                if engine._position_quantities_changed(
                    post_evidence_positions,
                    commit_positions,
                ):
                    reason = "routine_position_changed_at_final_commit"
                    store.request_halt(reason, flatten=True)
                    engine._routine_emergency_triggered = True
                    engine.emergency_flatten(reason, persist_halt=True)
                    raise RuntimeError(
                        "Routine Alpaca submission was blocked because position quantities "
                        "changed at the final REST commit boundary."
                    )
                commit_position = commit_positions.get(child_symbol)
                commit_current_qty = (
                    float(commit_position.qty) if commit_position is not None else 0.0
                )
                engine._validate_child_target_progress(
                    current_qty=commit_current_qty,
                    target_qty=child_authorization.target_qty,
                    side=side,
                    qty=qty,
                    phase=child_authorization.phase,
                    expected_current_qty=child_authorization.current_qty,
                )
                foreign_commit_positions = engine._foreign_dedicated_positions(
                    active_plan,
                    commit_positions,
                )
                if foreign_commit_positions:
                    engine._persist_foreign_position_halt(
                        foreign_commit_positions,
                        stage="alpaca_final_commit",
                    )
                    raise RuntimeError(
                        "Routine Alpaca submission was blocked by a foreign position at commit."
                    )
                commit_orders = alpaca_broker.list_open_orders(None)
                foreign_commit_orders = engine._foreign_dedicated_orders(commit_orders)
                if foreign_commit_orders:
                    engine._persist_foreign_order_halt(
                        "unauthorized_dedicated_account_order",
                        foreign_commit_orders,
                        stage="alpaca_final_commit",
                    )
                    raise RuntimeError(
                        "Routine Alpaca submission was blocked by foreign activity at commit."
                    )
                if commit_orders:
                    raise RuntimeError(
                        "Routine Alpaca submission was blocked by an open-order race at commit."
                    )
                actual_account_id = alpaca_broker.get_account_identity()
                if not hmac.compare_digest(
                    actual_account_id.encode("utf-8"),
                    config.alpaca_account_id.encode("utf-8"),
                ) or not hmac.compare_digest(
                    actual_account_id.encode("utf-8"),
                    connected_account_id.encode("utf-8"),
                ):
                    raise RuntimeError(
                        "Routine Alpaca submission was blocked because account identity "
                        "changed at final commit."
                    )
                current_verified_approval(actual_account_id=actual_account_id)
                commit_clock = alpaca_broker.get_market_clock()
                deadline = engine._require_governed_execution_window(
                    commit_clock,
                    intended_session=active_session,
                    context="Final routine Alpaca REST commit",
                )
                store.verify_critical_integrity()
                halt = store.halt_state()
                if not halt or halt.get("active"):
                    raise RuntimeError(
                        "Routine Alpaca submission was blocked by a final authenticated halt."
                    )
                if config.kill_switch_path.exists():
                    raise RuntimeError(
                        "Routine Alpaca submission was blocked by a final kill switch."
                    )
                final_quote_age = (
                    datetime.now(timezone.utc)
                    - submission_context.quote_timestamp.astimezone(timezone.utc)
                ).total_seconds()
                if (
                    not math.isfinite(final_quote_age)
                    or final_quote_age < -5.0
                    or final_quote_age > config.max_execution_price_age_seconds
                ):
                    raise RuntimeError(
                        "Routine Alpaca quote aged out before the final REST commit."
                    )
                if datetime.now(timezone.utc) >= deadline:
                    raise RuntimeError(
                        "Routine Alpaca submission reached 09:35 before REST commit."
                    )
            return deadline
    logger = configure_logging(config)
    if config.broker == "simulated":
        store = StateStore(
            config.database_path,
            require_existing=False,
            authentication_key=state_authentication_key,
        )
        broker = SimulatedBroker(
            prices_path=config.simulated_prices_path,
            state_path=config.simulated_state_path,
            starting_cash=config.simulated_starting_cash,
            slippage_bps=config.simulated_slippage_bps,
            timezone=config.timezone,
            market_always_open=config.simulated_market_always_open,
        )
    else:
        alpaca_broker = AlpacaBroker(
            api_key=config.alpaca_api_key,
            secret_key=config.alpaca_secret_key,
            paper=config.alpaca_paper,
            data_feed=config.alpaca_data_feed,
            max_execution_price_age_seconds=config.max_execution_price_age_seconds,
            max_execution_spread_bps=config.max_execution_spread_bps,
            marketable_limit_collar_bps=config.marketable_limit_collar_bps,
            routine_execution_authorized_until=(
                deployment_approval.expires_at if deployment_approval is not None else None
            ),
            routine_authorization_check=routine_authorization_check,
            covariance_evidence_provider=SignedCovarianceEvidenceProvider(
                envelope_path=config.covariance_evidence_path,
                execution_prices_path=config.covariance_execution_prices_path,
                corporate_actions_path=config.covariance_corporate_actions_path,
                public_keys_path=config.covariance_public_keys_path,
                public_keys_sha256=config.covariance_public_keys_sha256,
                provider_id=config.covariance_provider_id,
                venue_id=config.covariance_venue_id,
                max_data_age_days=config.max_data_age_days,
            ),
            borrow_evidence_provider=(
                None
                if emergency_only
                else SignedBorrowEvidenceProvider(
                    envelope_path=config.borrow_evidence_path,
                    terms_path=config.borrow_terms_path,
                    public_keys_path=config.borrow_public_keys_path,
                    public_keys_sha256=config.borrow_public_keys_sha256,
                    provider_id=config.borrow_provider_id,
                    venue_id=config.borrow_venue_id,
                    account_id=config.alpaca_account_id,
                    max_term_age_seconds=config.borrow_max_term_age_seconds,
                )
            ),
        )
        broker = alpaca_broker
        if config.execution_enabled or emergency_only:
            connected_account_id = broker.get_account_identity()
            if not hmac.compare_digest(
                connected_account_id.encode("utf-8"),
                config.alpaca_account_id.encode("utf-8"),
            ):
                raise RuntimeError(
                    "Connected Alpaca account does not match the independently pinned "
                    "ALPACA_ACCOUNT_ID."
                )
        if deployment_approval is not None:
            account_verification = verify_deployment_approval(
                config,
                actual_account_id=connected_account_id,
            )
            if not account_verification.verified:
                detail = "; ".join(account_verification.errors)
                raise RuntimeError(
                    "Connected Alpaca account is not authorized for this deployment: "
                    + detail
                )
        # Authenticate the SQLite-independent idempotency boundary only after the
        # broker account pin succeeds, but before opening state or mutating orders.
        emergency_journal = EmergencyJournal(
            config.effective_emergency_journal_path,
            config.emergency_authentication_key_bytes,
            config.emergency_journal_scope,
        )
        emergency_journal.verify()
        # Do not create or mutate the strategy database until governance and the
        # connected broker account have both been authenticated.
        try:
            store = StateStore(
                emergency_state_path or config.database_path,
                require_existing=(live_execution or emergency_only)
                and emergency_state_path is None,
                authentication_key=state_authentication_key,
            )
        except Exception as authoritative_error:
            if not emergency_only:
                raise
            # Any missing/corrupt/MAC-invalid/lifecycle-mismatched authoritative DB
            # switches only the audit ledger. The marker UUID and authenticated order
            # journal remain unchanged across this path switch.
            database_path = Path(config.database_path).resolve(strict=False)
            preferred_recovery = database_path.with_name(
                database_path.name + ".emergency-recovery.sqlite3"
            )
            emergency_state_path = (
                preferred_recovery
                if emergency_state_path is None
                else database_path.with_name(
                    database_path.name
                    + ".emergency-recovery-"
                    + config.emergency_authentication_key_sha256[:12]
                    + ".sqlite3"
                )
            )
            emergency_state_reason = (
                "authoritative_state_open_or_authentication_failed:"
                f"{type(authoritative_error).__name__}"
            )
            state_authentication_key = recovery_state_authentication_key
            store = StateStore(
                emergency_state_path,
                require_existing=False,
                authentication_key=state_authentication_key,
            )
        if emergency_state_path is not None:
            store.record_event(
                "CRITICAL",
                "EMERGENCY_RECOVERY_STATE_CREATED",
                "Authoritative state was unavailable or could not be authenticated; "
                "broker risk reduction is using an isolated recovery ledger and normal "
                "live startup remains blocked.",
                {
                    "authoritative_database": str(config.database_path),
                    "recovery_database": str(emergency_state_path),
                    "recovery_reason": emergency_state_reason,
                },
            )
    engine = AutomationEngine(config=config, broker=broker, store=store, logger=logger)
    # The authenticated emergency journal is an independent startup interlock. A
    # missing/rewritten marker must never hide an unresolved broker mutation from a
    # normal daemon or one-shot command.
    engine.emergency_journal.verify()
    active_emergency_incident = engine.emergency_journal.active_incident_id()
    if active_emergency_incident is not None:
        control = merge_control_marker(
            config.kill_switch_path,
            "startup_recovery_active_emergency_incident",
            flatten=True,
            authoritative_incident_id=active_emergency_incident,
        )
        try:
            store.request_halt(control.reason, flatten=True)
        except Exception:
            # The durable marker and independent journal remain sufficient for the
            # daemon's broker-only recovery path when strategy state is unavailable.
            pass
    if deployment_approval is not None:
        def deployment_plan_binding_provider() -> dict[str, object]:
            current = current_verified_approval(
                actual_account_id=connected_account_id,
            )
            return target_plan_deployment_binding(
                config,
                current,
                authorized_account_id=connected_account_id,
            )

        engine.deployment_plan_binding_provider = deployment_plan_binding_provider
    elif not emergency_only:
        # Simulation has no routine signed approval to refresh. Approved execution
        # always uses the provider above and never a cached approval binding.
        engine.deployment_plan_binding = target_plan_deployment_binding(
            config,
            account_verification,
            authorized_account_id=connected_account_id,
        )
    return engine
