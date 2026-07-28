from __future__ import annotations

import hashlib
import hmac
import json
import logging
import math
import time as time_module
from collections import Counter
from dataclasses import asdict, replace
from datetime import date, datetime, timedelta, timezone
from typing import Callable, Iterable, Mapping
from zoneinfo import ZoneInfo

from auto_trader.brokers.base import Broker
from auto_trader.borrow_evidence import (
    BorrowEvidenceError,
    VerifiedBorrowEvidence,
    anchor_borrow_evidence,
)
from auto_trader.config import BotConfig
from auto_trader.covariance_evidence import (
    COVARIANCE_RETURN_SEMANTICS as SIGNED_EVIDENCE_RETURN_SEMANTICS,
)
from auto_trader.controls import merge_control_marker, remove_control_marker_if_unchanged
from auto_trader.emergency_journal import EmergencyJournal
from auto_trader.deployment import target_plan_deployment_binding
from auto_trader.models import (
    AccountSnapshot,
    AssetInfo,
    ExecutionSummary,
    OrderIntent,
    OrderPhase,
    OrderReceipt,
    OrderSide,
    PositionSnapshot,
    RiskDecision,
    RoutineChildAuthorization,
    TargetPlan,
    TERMINAL_ORDER_STATUSES,
)
from auto_trader.governed import (
    GOVERNED_EXECUTION_END,
    GOVERNED_EXECUTION_START,
    GOVERNED_MINIMUM_ASSETS,
    GOVERNED_TIMEZONE,
)
from auto_trader.risk import RiskManager
from auto_trader.store import StateStore
from auto_trader.strategy import (
    build_target_plan,
    PLAN_AUTHENTICATION_TAG_KEY,
    seal_target_plan,
    SEALED_COVARIANCE_RETURN_SEMANTICS,
    _price_hash,
    validate_target_plan_integrity,
)


class EmergencyPrimarySubmissionError(RuntimeError):
    """A primary emergency submission may exist and must retain its order IDs."""


class EmergencyFillProgressError(EmergencyPrimarySubmissionError):
    """A terminal emergency fill is not yet reflected safely in positions."""


_MONITOR_PLAN_STATUSES = frozenset(
    {
        "approved",
        "previewed",
        "partial",
        "executing",
        "executed",
        "dry_run",
        "failed",
        "halted",
        "expired",
    }
)
_MAX_GOVERNED_BROKER_CLOCK_SKEW_SECONDS = 5.0


class AutomationEngine:
    def __init__(
        self,
        config: BotConfig,
        broker: Broker,
        store: StateStore,
        logger: logging.Logger | None = None,
    ) -> None:
        self.config = config
        self.broker = broker
        self.store = store
        self.risk = RiskManager(config, store)
        self.logger = logger or logging.getLogger("quant_auto_trader")
        self.tz = ZoneInfo(config.timezone)
        self._progress_callback: Callable[[], None] | None = None
        self._active_routine_execution_date: date | None = None
        self._active_routine_plan: TargetPlan | None = None
        self._active_routine_child_authorization: RoutineChildAuthorization | None = None
        self._active_live_borrow_evidence: VerifiedBorrowEvidence | None = None
        self._routine_emergency_triggered = False
        self.emergency_journal = EmergencyJournal(
            config.effective_emergency_journal_path,
            config.emergency_authentication_key_bytes,
            config.emergency_journal_scope,
        )

    def set_progress_callback(self, callback: Callable[[], None] | None) -> None:
        self._progress_callback = callback
        setter = getattr(self.broker, "set_progress_callback", None)
        if callable(setter):
            setter(callback)

    def _mark_progress(self) -> None:
        if self._progress_callback is not None:
            self._progress_callback()

    def _best_effort_emergency_store(self, method: str, *args, **kwargs):
        """Attempt audit bookkeeping without letting strategy state trap exposure."""

        try:
            return getattr(self.store, method)(*args, **kwargs)
        except Exception as exc:
            self.logger.error("Emergency state bookkeeping %s failed: %s", method, exc)
            return None

    def _local_time(self, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=self.tz)
        return value.astimezone(self.tz)

    def _utc_wall_clock(self) -> datetime:
        """Return the independent process clock used to challenge broker timestamps."""

        provider = getattr(self, "_wall_clock_provider", None)
        value = provider() if callable(provider) else datetime.now(timezone.utc)
        if value.tzinfo is None or value.utcoffset() is None:
            raise BorrowEvidenceError("The independent wall clock is not absolute.")
        return value.astimezone(timezone.utc)

    def _require_governed_clock_alignment(
        self,
        broker_timestamp: datetime,
        *,
        context: str,
    ) -> datetime:
        if broker_timestamp.tzinfo is None or broker_timestamp.utcoffset() is None:
            raise BorrowEvidenceError(f"{context} requires an absolute broker clock.")
        wall_clock = self._utc_wall_clock()
        skew = abs(
            (
                broker_timestamp.astimezone(timezone.utc) - wall_clock
            ).total_seconds()
        )
        if skew > _MAX_GOVERNED_BROKER_CLOCK_SKEW_SECONDS:
            raise BorrowEvidenceError(
                f"{context} rejected broker/process clock skew of {skew:.3f} seconds; "
                f"the maximum is {_MAX_GOVERNED_BROKER_CLOCK_SKEW_SECONDS:.0f}."
            )
        return wall_clock

    def _governed_execution_enabled(self) -> bool:
        return bool(self.config.broker == "alpaca" and self.config.execution_enabled)

    @staticmethod
    def _parse_authenticated_date(value: object, *, field: str) -> date:
        if not isinstance(value, str) or len(value) != 10:
            raise RuntimeError(f"Authenticated plan {field} is missing or malformed.")
        try:
            parsed = date.fromisoformat(value)
        except ValueError as exc:
            raise RuntimeError(
                f"Authenticated plan {field} is not an exact YYYY-MM-DD date."
            ) from exc
        if parsed.isoformat() != value:
            raise RuntimeError(f"Authenticated plan {field} is not canonical.")
        return parsed

    @staticmethod
    def _parse_authenticated_timestamp(value: object, *, field: str) -> datetime:
        if not isinstance(value, str) or not value.strip():
            raise RuntimeError(f"Authenticated plan {field} is missing or malformed.")
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise RuntimeError(
                f"Authenticated plan {field} is not a valid ISO-8601 timestamp."
            ) from exc
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise RuntimeError(
                f"Authenticated plan {field} must include an explicit UTC offset."
            )
        return parsed.astimezone(timezone.utc)

    def _governed_benchmark_deadline(self, session: date) -> datetime:
        return datetime.combine(
            session,
            GOVERNED_EXECUTION_END,
            tzinfo=ZoneInfo(GOVERNED_TIMEZONE),
        ).astimezone(timezone.utc)

    @staticmethod
    def _routine_child_authorization_payload(
        authorization: RoutineChildAuthorization,
    ) -> dict[str, object]:
        return {
            "schema_version": 1,
            "plan_id": authorization.plan_id,
            "plan_authentication_hmac_sha256": (
                authorization.plan_authentication_hmac_sha256
            ),
            "intended_session": authorization.intended_session.isoformat(),
            "phase": authorization.phase.value,
            "client_order_id": authorization.client_order_id,
            "symbol": authorization.symbol,
            "side": authorization.side.value,
            "qty": authorization.qty,
            "current_qty": authorization.current_qty,
            "target_qty": authorization.target_qty,
            "not_after": authorization.not_after.astimezone(timezone.utc).isoformat(),
        }

    def _activate_routine_child_authorization(
        self,
        plan: TargetPlan,
        intent: OrderIntent,
    ) -> RoutineChildAuthorization:
        """Mint a one-use HMAC capability for the exact refreshed child economics."""

        if self._active_routine_child_authorization is not None:
            raise RuntimeError("A routine child authorization is already active.")
        intended_session = self._active_routine_execution_date
        if intended_session is None or self._active_routine_plan is None:
            raise RuntimeError("Routine child authorization has no active plan/session.")
        if self._active_routine_plan.plan_id != plan.plan_id:
            raise RuntimeError("Routine child authorization plan identity changed.")
        plan_tag = plan.metadata.get(PLAN_AUTHENTICATION_TAG_KEY)
        if not isinstance(plan_tag, str) or len(plan_tag) != 64:
            raise RuntimeError("Routine child authorization lacks the authenticated plan tag.")
        deadline = self._governed_benchmark_deadline(intended_session)
        unsigned = RoutineChildAuthorization(
            plan_id=plan.plan_id,
            plan_authentication_hmac_sha256=plan_tag,
            intended_session=intended_session,
            phase=intent.phase,
            client_order_id=intent.client_order_id,
            symbol=str(intent.symbol).upper(),
            side=intent.side,
            qty=float(intent.qty),
            current_qty=float(intent.current_qty),
            target_qty=float(intent.target_qty),
            not_after=deadline,
            authorization_hmac_sha256="",
        )
        payload = json.dumps(
            self._routine_child_authorization_payload(unsigned),
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        authentication = hmac.new(
            self.config.plan_authentication_key_bytes,
            b"routine-child-authorization-v1\0" + payload,
            hashlib.sha256,
        ).hexdigest()
        authorization = replace(
            unsigned,
            authorization_hmac_sha256=authentication,
        )
        self._active_routine_child_authorization = authorization
        return authorization

    def _require_active_routine_child_authorization(
        self,
        *,
        client_order_id: str,
        symbol: str,
        qty: float,
        side: OrderSide,
    ) -> RoutineChildAuthorization:
        """Verify the active child capability and its authenticated plan/session binding."""

        authorization = self._active_routine_child_authorization
        plan = self._active_routine_plan
        intended_session = self._active_routine_execution_date
        if authorization is None or plan is None or intended_session is None:
            raise RuntimeError("Routine Alpaca submission has no active child authorization.")
        validate_target_plan_integrity(
            plan,
            self._current_plan_binding(),
            self.config.plan_authentication_key_bytes,
        )
        active_tag = plan.metadata.get(PLAN_AUTHENTICATION_TAG_KEY)
        if (
            not isinstance(active_tag, str)
            or not hmac.compare_digest(
                active_tag,
                authorization.plan_authentication_hmac_sha256,
            )
            or not hmac.compare_digest(plan.plan_id, authorization.plan_id)
            or intended_session != authorization.intended_session
        ):
            raise RuntimeError("Routine child authorization is not bound to the active plan/session.")
        payload = json.dumps(
            self._routine_child_authorization_payload(authorization),
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        expected = hmac.new(
            self.config.plan_authentication_key_bytes,
            b"routine-child-authorization-v1\0" + payload,
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(
            expected,
            authorization.authorization_hmac_sha256,
        ):
            raise RuntimeError("Routine child authorization failed keyed authentication.")
        normalized_symbol = str(symbol).upper()
        tolerance = max(1e-10, abs(float(qty)) * 1e-10)
        if (
            not hmac.compare_digest(str(client_order_id), authorization.client_order_id)
            or not hmac.compare_digest(normalized_symbol, authorization.symbol)
            or side != authorization.side
            or not math.isclose(float(qty), authorization.qty, abs_tol=tolerance)
        ):
            raise RuntimeError("Routine order economics do not match the active child authorization.")
        if datetime.now(timezone.utc) >= authorization.not_after.astimezone(timezone.utc):
            raise RuntimeError("Routine child authorization expired at the 09:35 deadline.")
        return authorization

    def _clear_routine_child_authorization(
        self,
        authorization: RoutineChildAuthorization,
    ) -> None:
        if self._active_routine_child_authorization is authorization:
            self._active_routine_child_authorization = None
            return
        self._active_routine_child_authorization = None
        raise RuntimeError("Routine child authorization identity changed during submission.")

    @staticmethod
    def _validate_child_target_progress(
        *,
        current_qty: float,
        target_qty: float,
        side: OrderSide,
        qty: float,
        phase: OrderPhase,
        expected_current_qty: float | None = None,
    ) -> float:
        values = (current_qty, target_qty, qty)
        if not all(math.isfinite(float(value)) for value in values) or qty <= 0.0:
            raise RuntimeError("Routine child target economics are invalid.")
        tolerance = max(
            1e-8,
            abs(current_qty) * 1e-8,
            abs(target_qty) * 1e-8,
            abs(qty) * 1e-8,
        )
        if expected_current_qty is not None and not math.isclose(
            current_qty,
            expected_current_qty,
            abs_tol=tolerance,
        ):
            raise RuntimeError(
                "Routine child position changed after authorization; stale quantity was blocked."
            )
        signed_qty = qty if side == OrderSide.BUY else -qty
        remaining = target_qty - current_qty
        projected_qty = current_qty + signed_qty
        if abs(remaining) <= tolerance or remaining * signed_qty <= 0.0:
            raise RuntimeError("Routine child does not move monotonically toward its target.")
        if abs(signed_qty) > abs(remaining) + tolerance:
            raise RuntimeError("Routine child would overshoot its authenticated target quantity.")
        if abs(target_qty - projected_qty) > abs(remaining) + tolerance:
            raise RuntimeError("Routine child increases its distance from the authenticated target.")
        if phase == OrderPhase.REDUCE and abs(projected_qty) > abs(current_qty) + tolerance:
            raise RuntimeError("Routine reduction would increase absolute position exposure.")
        if (
            phase == OrderPhase.REDUCE
            and current_qty * projected_qty < -tolerance * tolerance
        ):
            raise RuntimeError("Routine reduction would cross zero.")
        if phase not in {OrderPhase.REDUCE, OrderPhase.INCREASE}:
            raise RuntimeError("Routine child has an invalid rebalance phase.")
        return projected_qty

    def _require_governed_execution_window(
        self,
        clock,
        *,
        intended_session: date | None,
        context: str,
    ) -> datetime:
        if clock.timestamp.tzinfo is None or clock.timestamp.utcoffset() is None:
            raise RuntimeError(f"{context} requires an absolute broker clock timestamp.")
        local = clock.timestamp.astimezone(ZoneInfo(GOVERNED_TIMEZONE))
        if intended_session is None or local.date() != intended_session:
            raise RuntimeError(
                f"{context} is restricted to the plan's exact signed next exchange session."
            )
        start = datetime.combine(
            intended_session,
            GOVERNED_EXECUTION_START,
            tzinfo=ZoneInfo(GOVERNED_TIMEZONE),
        )
        end = datetime.combine(
            intended_session,
            GOVERNED_EXECUTION_END,
            tzinfo=ZoneInfo(GOVERNED_TIMEZONE),
        )
        if not clock.is_open or local < start or local >= end:
            raise RuntimeError(
                f"{context} is allowed only while the market is open in the signed "
                "09:30<=time<09:35 America/New_York benchmark window."
            )
        return end.astimezone(timezone.utc)

    def _governed_plan_contract(
        self,
        plan: TargetPlan,
    ) -> tuple[date, dict[str, str], list[str]]:
        metadata = plan.metadata
        intended = self._parse_authenticated_date(
            metadata.get("intended_execution_date"),
            field="intended_execution_date",
        )
        if intended <= plan.as_of:
            raise RuntimeError(
                "Authenticated plan intended_execution_date must follow plan as_of."
            )
        if metadata.get("research_covariance_parity_certified") is not True:
            raise RuntimeError("Governed execution requires certified research covariance parity.")
        if metadata.get("covariance_corporate_action_accounting_certified") is not True:
            raise RuntimeError(
                "Governed execution requires certified covariance corporate-action accounting."
            )
        if metadata.get("covariance_return_semantics") != SEALED_COVARIANCE_RETURN_SEMANTICS:
            raise RuntimeError("Governed execution plan has the wrong covariance semantics.")
        if metadata.get("covariance_return_count") != 251:
            raise RuntimeError("Governed execution plan has the wrong covariance return count.")
        raw_provenance = metadata.get("covariance_evidence_provenance")
        if not isinstance(raw_provenance, Mapping) or not raw_provenance:
            raise RuntimeError("Governed execution plan lacks signed covariance provenance.")
        provenance: dict[str, str] = {}
        for key, value in raw_provenance.items():
            if not isinstance(key, str) or not isinstance(value, str) or not value:
                raise RuntimeError("Governed covariance provenance is malformed.")
            provenance[key] = value
        required = {
            "issued_at",
            "expires_at",
            "latest_session",
            "next_session",
            "return_semantics",
        }
        missing = sorted(required.difference(provenance))
        if missing:
            raise RuntimeError(
                "Governed covariance provenance is missing: " + ", ".join(missing) + "."
            )
        if provenance["latest_session"] != plan.as_of.isoformat():
            raise RuntimeError(
                "Governed covariance latest_session does not equal the plan as_of session."
            )
        if provenance["next_session"] != intended.isoformat():
            raise RuntimeError(
                "Governed covariance next_session does not equal the intended execution date."
            )
        if provenance["return_semantics"] != SIGNED_EVIDENCE_RETURN_SEMANTICS:
            raise RuntimeError("Governed covariance signed return semantics are invalid.")
        expires = self._parse_authenticated_timestamp(
            provenance["expires_at"], field="covariance expires_at"
        )
        if expires <= self._governed_benchmark_deadline(intended):
            raise RuntimeError(
                "Governed covariance evidence expires before the signed 09:35 endpoint."
            )
        raw_symbols = metadata.get("covariance_evidence_symbols")
        if (
            not isinstance(raw_symbols, list)
            or len(raw_symbols) < GOVERNED_MINIMUM_ASSETS
            or any(not isinstance(symbol, str) or not symbol for symbol in raw_symbols)
            or len(set(raw_symbols)) != len(raw_symbols)
        ):
            raise RuntimeError(
                "Governed execution requires at least 20 unique authenticated evidence symbols."
            )
        return intended, provenance, list(raw_symbols)

    def _revalidate_governed_covariance_evidence(
        self,
        plan: TargetPlan,
        *,
        intended_session: date,
        provenance: dict[str, str],
        evidence_symbols: list[str],
        clock_timestamp: datetime,
    ) -> None:
        expires = self._parse_authenticated_timestamp(
            provenance["expires_at"], field="covariance expires_at"
        )
        if clock_timestamp.tzinfo is None or clock_timestamp.utcoffset() is None:
            raise RuntimeError("Execution covariance revalidation requires an absolute clock.")
        if clock_timestamp.astimezone(timezone.utc) >= expires:
            raise RuntimeError("Governed covariance evidence has expired before execution.")
        current = self.broker.get_governed_covariance_evidence(
            evidence_symbols,
            self.config.history_bars,
            plan.as_of,
        )
        if current is None:
            raise RuntimeError("Governed covariance evidence is unavailable at execution.")
        if current.intended_execution_date != intended_session:
            raise RuntimeError(
                "Revalidated covariance evidence changed the signed next exchange session."
            )
        current_provenance = dict(current.provenance)
        if current_provenance != provenance:
            raise RuntimeError(
                "Revalidated covariance evidence does not match the authenticated plan provenance."
            )
        plan_assets = plan.metadata.get("assets")
        if not isinstance(plan_assets, list) or any(
            not isinstance(symbol, str) for symbol in plan_assets
        ):
            raise RuntimeError("Authenticated plan assets are malformed.")
        if any(symbol not in current.execution_prices.columns for symbol in plan_assets):
            raise RuntimeError("Revalidated covariance evidence is missing plan assets.")
        current_prices = current.execution_prices.reindex(columns=plan_assets)
        current_splits = current.split_ratios.reindex_like(current_prices)
        current_cash = current.cash_distributions.reindex_like(current_prices)
        expected_hashes = (
            ("covariance_price_hash", _price_hash(current_prices)),
            ("covariance_split_ratio_hash", _price_hash(current_splits)),
            ("covariance_cash_distribution_hash", _price_hash(current_cash)),
        )
        for field, actual in expected_hashes:
            if plan.metadata.get(field) != actual:
                raise RuntimeError(
                    f"Revalidated covariance evidence no longer matches plan {field}."
                )
        # Re-anchor the currently verified signed identity. This closes replay of an
        # older still-valid snapshot and generation-age + plan-age compounding.
        self.store.anchor_covariance_evidence(current_provenance)

    def _revalidate_governed_borrow_evidence(
        self,
        plan: TargetPlan,
        *,
        intended_session: date,
        current_positions: Mapping[str, PositionSnapshot],
        projected_short_symbols: Iterable[str] = (),
        projected_short_quantities: Mapping[str, float] | None = None,
        clock_timestamp: datetime,
        stage: str,
    ) -> VerifiedBorrowEvidence:
        """Authenticate and persist exact-session borrow terms before routine risk.

        The signed artifact covers the complete deployment universe, while policy is
        evaluated against every plan short, every currently held short (including a
        foreign dedicated-account symbol), and the final projected child economics.
        Re-reading the files on every call makes recall/locate/rate changes fail closed;
        the authenticated monotonic anchor rejects a publisher rollback.
        """

        self._active_live_borrow_evidence = None
        if clock_timestamp.tzinfo is None or clock_timestamp.utcoffset() is None:
            raise BorrowEvidenceError(
                "Live borrow evidence revalidation requires an absolute broker clock."
            )
        wall_clock = self._require_governed_clock_alignment(
            clock_timestamp,
            context="Live borrow evidence revalidation",
        )
        current = self.broker.get_governed_borrow_evidence(
            list(self.config.symbols),
            intended_session,
            now=clock_timestamp,
        )
        if current is None:
            raise BorrowEvidenceError(
                "Authenticated exact-session live borrow evidence is unavailable."
            )
        if current.intended_session != intended_session:
            raise BorrowEvidenceError(
                "Live borrow evidence changed the routine execution session."
            )

        # A cryptographically valid adverse snapshot must advance the authenticated
        # anchor before policy rejects it. Otherwise an operator could resume and replay
        # the older favorable snapshot that preceded a recall or rate/quantity breach.
        self._active_live_borrow_evidence = current
        provenance = dict(current.provenance)
        anchor_borrow_evidence(self.store, provenance)
        verified_payload = {
            "plan_id": plan.plan_id,
            "intended_session": intended_session.isoformat(),
            "stage": str(stage),
            "verification_status": "cryptographically_verified",
            "validated_at": clock_timestamp.astimezone(timezone.utc).isoformat(),
            "wall_clock_checked_at": wall_clock.isoformat(),
            "provenance": provenance,
        }
        self.store.set_state("latest_live_borrow_verification", verified_payload)
        self.store.record_event(
            "INFO",
            "LIVE_BORROW_EVIDENCE_VERIFIED",
            "Signed live borrow evidence was authenticated and anti-rollback anchored.",
            verified_payload,
        )

        short_symbols = {
            str(symbol).upper()
            for symbol, weight in plan.target_weights.items()
            if float(weight) < -1e-12
        }
        required_short_quantities: dict[str, float] = {}
        for symbol, position in current_positions.items():
            quantity = float(position.qty)
            if not math.isfinite(quantity):
                raise BorrowEvidenceError(
                    f"Current position quantity for {symbol} is non-finite."
                )
            if quantity < -1e-10:
                normalized_symbol = str(symbol).upper()
                short_symbols.add(normalized_symbol)
                required_short_quantities[normalized_symbol] = max(
                    required_short_quantities.get(normalized_symbol, 0.0),
                    abs(quantity),
                )
        short_symbols.update(str(symbol).upper() for symbol in projected_short_symbols)
        for symbol, raw_quantity in (projected_short_quantities or {}).items():
            normalized_symbol = str(symbol).upper()
            try:
                quantity = float(raw_quantity)
            except (TypeError, ValueError) as exc:
                raise BorrowEvidenceError(
                    f"Projected short quantity for {normalized_symbol} is invalid."
                ) from exc
            if not math.isfinite(quantity) or quantity < 0.0:
                raise BorrowEvidenceError(
                    f"Projected short quantity for {normalized_symbol} is invalid."
                )
            short_symbols.add(normalized_symbol)
            required_short_quantities[normalized_symbol] = max(
                required_short_quantities.get(normalized_symbol, 0.0),
                quantity,
            )
        current.require_eligible_shorts(
            sorted(short_symbols),
            max_annual_rate=self.config.max_live_annual_borrow_rate,
            required_quantities=required_short_quantities,
        )

        audit_payload = {
            "plan_id": plan.plan_id,
            "intended_session": intended_session.isoformat(),
            "stage": str(stage),
            "validated_at": clock_timestamp.astimezone(timezone.utc).isoformat(),
            "wall_clock_checked_at": wall_clock.isoformat(),
            "authorization_status": "authorized",
            "short_symbols": sorted(short_symbols),
            "required_short_quantities": dict(sorted(required_short_quantities.items())),
            "max_live_annual_borrow_rate": self.config.max_live_annual_borrow_rate,
            "provenance": provenance,
        }
        # State, events, and runs are all committed by StateStore's external keyed
        # inventory, so execution provenance remains tamper-evident after restart.
        self.store.set_state("active_live_borrow_execution", audit_payload)
        self.store.record_event(
            "INFO",
            "LIVE_BORROW_EVIDENCE_REVALIDATED",
            "Authenticated live borrow terms authorized the current routine boundary.",
            audit_payload,
        )
        return current

    def _raise_governed_borrow_incident(
        self,
        plan: TargetPlan,
        *,
        intended_session: date,
        stage: str,
        error: Exception,
    ) -> None:
        """Persist one borrow incident and enter evidence-independent liquidation."""

        self._routine_emergency_triggered = True
        reason = "authenticated_live_borrow_policy_incident"
        incident_payload = {
            "plan_id": plan.plan_id,
            "intended_session": intended_session.isoformat(),
            "stage": str(stage),
            "error_type": type(error).__name__,
            "error": str(error),
            "policy_violations": dict(getattr(error, "violations", {})),
            "verified_provenance": (
                dict(self._active_live_borrow_evidence.provenance)
                if self._active_live_borrow_evidence is not None
                else None
            ),
        }
        self._best_effort_emergency_store("request_halt", reason, flatten=True)
        self._best_effort_emergency_store(
            "record_event",
            "CRITICAL",
            "LIVE_BORROW_POLICY_INCIDENT",
            str(error),
            incident_payload,
        )
        self._best_effort_emergency_store(
            "set_state",
            "active_live_borrow_execution",
            {
                **incident_payload,
                "authorization_status": "rejected",
            },
        )
        # Emergency orders never consult the routine borrow provider. A missing,
        # expired, recalled, or newly stale locate can stop risk creation while still
        # buying in shorts and removing the rest of the dedicated-account exposure.
        try:
            self.emergency_flatten(reason, persist_halt=True)
        except Exception as flatten_exc:
            raise RuntimeError(
                "Live borrow policy failed and emergency exposure reduction did not "
                "reconcile; durable halt controls remain active."
            ) from flatten_exc
        raise RuntimeError(
            "Routine execution was blocked by authenticated live borrow policy; "
            "the durable halt is active and emergency exposure reduction completed."
        ) from error

    def _enforce_governed_borrow_or_emergency_reduce(
        self,
        plan: TargetPlan,
        *,
        intended_session: date,
        current_positions: Mapping[str, PositionSnapshot],
        projected_short_symbols: Iterable[str] = (),
        projected_short_quantities: Mapping[str, float] | None = None,
        clock_timestamp: datetime,
        stage: str,
    ) -> VerifiedBorrowEvidence:
        """Fail closed into the evidence-independent emergency liquidation path."""

        try:
            return self._revalidate_governed_borrow_evidence(
                plan,
                intended_session=intended_session,
                current_positions=current_positions,
                projected_short_symbols=projected_short_symbols,
                projected_short_quantities=projected_short_quantities,
                clock_timestamp=clock_timestamp,
                stage=stage,
            )
        except Exception as exc:
            self._raise_governed_borrow_incident(
                plan,
                intended_session=intended_session,
                stage=stage,
                error=exc,
            )
            raise AssertionError("borrow incident handler must raise")

    def _enforce_governed_borrow_freshness_or_emergency_reduce(
        self,
        plan: TargetPlan,
        evidence: VerifiedBorrowEvidence,
        *,
        intended_session: date,
        clock_timestamp: datetime,
        stage: str,
    ) -> datetime:
        """Recheck already-authenticated term clocks at the last mutation instant."""

        try:
            wall_clock = self._require_governed_clock_alignment(
                clock_timestamp,
                context="Final live borrow freshness authorization",
            )
            freshness_clock = max(
                clock_timestamp.astimezone(timezone.utc),
                wall_clock,
            )
            evidence.require_fresh(
                now=freshness_clock,
                max_term_age_seconds=self.config.borrow_max_term_age_seconds,
            )
            return wall_clock
        except Exception as exc:
            self._raise_governed_borrow_incident(
                plan,
                intended_session=intended_session,
                stage=stage,
                error=exc,
            )

    def _managed_symbols(self, plan: TargetPlan | None = None) -> list[str]:
        symbols = set(self.config.symbols)
        if plan is not None:
            # Callers may use plan metadata to expand the broker mutation scope only
            # after keyed content and current-deployment validation.  Historical raw
            # database rows are deliberately not trusted for this purpose.
            validate_target_plan_integrity(
                plan,
                self._current_plan_binding(),
                self.config.plan_authentication_key_bytes,
            )
            symbols.update(plan.target_weights)
            assets = plan.metadata.get("assets", [])
            if isinstance(assets, list):
                symbols.update(str(item) for item in assets)
        if self.config.dedicated_account:
            try:
                symbols.update(self.broker.get_positions().keys())
            except Exception:
                # Do not hide the original operation if the broker is temporarily unavailable.
                pass
        return sorted(symbols)

    def _latest_allowed_date(self, clock_timestamp: datetime, market_is_open: bool) -> date:
        local = self._local_time(clock_timestamp)
        if market_is_open or local.time() < self.config.plan_time:
            return local.date() - timedelta(days=1)
        return local.date()

    def _evaluate_risk(self, account: AccountSnapshot, clock_timestamp: datetime) -> RiskDecision:
        return self.risk.evaluate_and_record(account, self._local_time(clock_timestamp).date())

    def _short_eligible(self, info: AssetInfo) -> bool:
        return bool(
            info.shortable
            and info.marginable
            and (info.easy_to_borrow or not self.config.require_easy_to_borrow)
        )

    def doctor(self) -> dict:
        checks: dict[str, object] = {
            "mode": self.config.mode_label,
            "configuration": "ok",
            "database": str(self.config.database_path),
        }
        self.config.database_path.parent.mkdir(parents=True, exist_ok=True)
        self.store.set_state("doctor_last_run", datetime.utcnow().isoformat())
        account = self.broker.get_account()
        clock = self.broker.get_market_clock()
        checks["broker_account"] = {
            "equity": account.equity,
            "buying_power": account.buying_power,
            "trading_blocked": account.trading_blocked,
            "shorting_enabled": account.shorting_enabled,
        }
        checks["market_clock"] = {
            "timestamp": clock.timestamp.isoformat(),
            "is_open": clock.is_open,
            "next_open": clock.next_open.isoformat(),
            "next_close": clock.next_close.isoformat(),
        }
        latest_allowed = self._latest_allowed_date(clock.timestamp, clock.is_open)
        prices = self.broker.get_daily_prices(
            list(self.config.symbols),
            min(self.config.history_bars, 220),
            latest_allowed,
        )
        checks["market_data"] = {
            "rows": len(prices),
            "assets": list(prices.columns),
            "latest": str(prices.index[-1].date()) if not prices.empty else None,
        }
        if prices.empty:
            raise RuntimeError("Broker connectivity succeeded but no daily bars were returned.")
        asset_info = self.broker.get_asset_info(list(prices.columns))
        eligible = [
            symbol
            for symbol, info in asset_info.items()
            if info.tradable and (not self.config.allow_shorting or self._short_eligible(info))
        ]
        checks["eligible_assets"] = eligible
        if len(eligible) < min(self.config.minimum_assets, len(prices.columns)):
            raise RuntimeError(
                f"Only {len(eligible)} assets pass tradable/shortable checks. "
                "Use a larger eligible universe."
            )
        return checks

    def generate_plan(self, force: bool = False) -> TargetPlan:
        run_id = self.store.start_run("plan", {"force": force, "mode": self.config.mode_label})
        try:
            clock = self.broker.get_market_clock()
            account = self.broker.get_account()
            risk = self._evaluate_risk(account, clock.timestamp)
            if risk.flatten:
                self.emergency_flatten(risk.reason, persist_halt=risk.halt)
            if risk.halt:
                raise RuntimeError(f"Planning blocked by risk shutdown: {risk.reason}")

            latest_allowed = self._latest_allowed_date(clock.timestamp, clock.is_open)
            raw_prices = self.broker.get_daily_prices(
                list(self.config.symbols), self.config.history_bars, latest_allowed
            )
            if raw_prices.empty:
                raise RuntimeError("No completed daily bars were returned by the data provider.")

            as_of = raw_prices.index[-1].date()
            data_age = 0 if self.config.broker == "simulated" else (latest_allowed - as_of).days
            if data_age > self.config.max_data_age_days:
                raise RuntimeError(
                    f"Latest completed data is {data_age} calendar days old ({as_of}); "
                    "planning is blocked as stale."
                )
            existing = self.store.get_plan_by_as_of(as_of)
            if existing and not force:
                validate_target_plan_integrity(
                    existing,
                    self._current_plan_binding(),
                    self.config.plan_authentication_key_bytes,
                )
                self.store.finish_run(run_id, "skipped", f"Plan {existing.plan_id} already exists.")
                return existing

            asset_info = self.broker.get_asset_info(list(raw_prices.columns))
            eligible = [
                symbol
                for symbol in raw_prices.columns
                if asset_info.get(symbol)
                and asset_info[symbol].tradable
                and (
                    not self.config.allow_shorting
                    or self._short_eligible(asset_info[symbol])
                )
            ]
            if len(eligible) < self.config.minimum_assets:
                raise RuntimeError(
                    f"Only {len(eligible)} assets are both tradable and eligible for the "
                    f"configured market-neutral strategy; {self.config.minimum_assets} required."
                )

            remaining = self.risk.advance_cooldown(as_of)
            if remaining > 0:
                risk = RiskDecision(
                    allow_new_risk=False,
                    flatten=True,
                    halt=False,
                    reason=f"cooldown_{remaining}_sessions_remaining",
                    drawdown=risk.drawdown,
                    daily_return=risk.daily_return,
                    five_day_return=risk.five_day_return,
                )

            require_research_covariance_parity = bool(
                self.config.broker == "alpaca" and self.config.execution_enabled
            )
            covariance_evidence = (
                self.broker.get_governed_covariance_evidence(
                    eligible,
                    self.config.history_bars,
                    as_of,
                )
                if require_research_covariance_parity
                else None
            )
            intended_execution_date = (
                covariance_evidence.intended_execution_date
                if covariance_evidence is not None
                else None
            )
            covariance_execution_prices = (
                covariance_evidence.execution_prices
                if covariance_evidence is not None
                else None
            )
            if covariance_evidence is not None:
                if clock.next_open.tzinfo is None or clock.next_open.utcoffset() is None:
                    raise RuntimeError(
                        "Governed planning requires an absolute broker next_open timestamp."
                    )
                broker_next_session = clock.next_open.astimezone(
                    ZoneInfo(GOVERNED_TIMEZONE)
                ).date()
                if intended_execution_date != broker_next_session:
                    raise RuntimeError(
                        "Signed covariance next_session does not match the broker's exact "
                        "next exchange session."
                    )
                if intended_execution_date <= as_of:
                    raise RuntimeError(
                        "Signed covariance next_session must follow the signal as_of session."
                    )
                # Persist the verified signed identity before constructing a plan.
                # This HMAC-authenticated monotonic anchor rejects replay of an older
                # still-valid snapshot, including same-session issue-time rollback.
                self.store.anchor_covariance_evidence(
                    dict(covariance_evidence.provenance)
                )
            plan = build_target_plan(
                prices=raw_prices[eligible],
                config=self.config.strategy,
                risk=risk,
                minimum_assets=self.config.minimum_assets,
                account_equity=account.equity,
                covariance_execution_prices=covariance_execution_prices,
                covariance_corporate_action_split_ratios=(
                    covariance_evidence.split_ratios
                    if covariance_evidence is not None
                    else None
                ),
                covariance_corporate_action_cash_distributions=(
                    covariance_evidence.cash_distributions
                    if covariance_evidence is not None
                    else None
                ),
                covariance_evidence_metadata=(
                    covariance_evidence.provenance
                    if covariance_evidence is not None
                    else None
                ),
                intended_execution_date=intended_execution_date,
                covariance_return_semantics=(
                    SEALED_COVARIANCE_RETURN_SEMANTICS
                    if covariance_execution_prices is not None
                    else "daily_close_proxy"
                ),
                require_research_covariance_parity=(
                    require_research_covariance_parity
                ),
            )
            plan = seal_target_plan(
                plan,
                self._current_plan_binding(),
                self.config.plan_authentication_key_bytes,
            )
            inserted = self.store.save_plan(plan)
            if not inserted:
                existing = self.store.get_plan_by_as_of(plan.as_of)
                if existing:
                    validate_target_plan_integrity(
                        existing,
                        self._current_plan_binding(),
                        self.config.plan_authentication_key_bytes,
                    )
                    plan = existing
            self.store.record_event(
                "INFO",
                "PLAN_CREATED",
                f"Plan {plan.plan_id} created for completed session {plan.as_of}.",
                plan.to_dict(),
            )
            self.store.finish_run(run_id, "success", f"Created plan {plan.plan_id}.", plan.to_dict())
            return plan
        except Exception as exc:
            self.store.record_event("ERROR", "PLAN_FAILED", str(exc))
            self.store.finish_run(run_id, "failed", str(exc))
            raise

    def _current_plan_binding(self) -> dict[str, object]:
        provider = getattr(self, "deployment_plan_binding_provider", None)
        if callable(provider):
            provided = provider()
            if not isinstance(provided, dict):
                raise RuntimeError("Deployment plan-binding provider returned invalid data.")
            return dict(provided)
        configured = getattr(self, "deployment_plan_binding", None)
        if isinstance(configured, dict):
            return dict(configured)
        return target_plan_deployment_binding(self.config)

    def _actual_exposure_breach(
        self,
        account: AccountSnapshot,
    ) -> tuple[str | None, dict[str, float]]:
        """Check broker positions independently of the newest target plan."""
        if not math.isfinite(account.equity) or account.equity <= 0.0:
            return "actual_exposure_nonpositive_equity", {}
        positions = self.broker.get_positions()
        latest_plan, plan_integrity_issues = self._validated_monitor_plan()
        # The detailed numeric checks below classify malformed broker snapshots. For
        # metadata-integrity purposes, any reported position row is already risk usage;
        # do not parse an attacker-controlled/non-finite quantity before failing closed.
        has_positions = bool(positions)
        if plan_integrity_issues and has_positions:
            return "actual_plan_metadata_integrity_breach", {
                "invalid_plan_count": float(len(plan_integrity_issues)),
                "position_count": float(len(positions)),
            }
        planned_assets = (
            {str(symbol) for symbol in latest_plan.metadata.get("assets", [])}
            if latest_plan is not None
            else set()
        )
        if self.config.dedicated_account and latest_plan is None and any(
            abs(float(position.qty)) > 1e-12 for position in positions.values()
        ):
            return "actual_position_without_plan_breach", {
                "unmodeled_position_count": float(len(positions))
            }
        if self.config.dedicated_account and latest_plan is not None:
            unmodeled = sorted(
                symbol
                for symbol, position in positions.items()
                if abs(float(position.qty)) > 1e-12 and symbol not in planned_assets
            )
            if unmodeled:
                return "actual_unmodeled_position_breach", {
                    "unmodeled_position_count": float(len(unmodeled))
                }
        if self.config.dedicated_account:
            in_scope = set(positions)
        else:
            # Current approved symbols are an independently authenticated deployment
            # boundary.  A validated plan may narrow/expand within that boundary, but
            # unverified historical metadata must never decide which shared-account
            # positions the bot measures or liquidates.
            in_scope = set(self.config.symbols)
            if latest_plan is not None:
                in_scope.update(latest_plan.target_weights)
                assets = latest_plan.metadata.get("assets", [])
                if isinstance(assets, list):
                    in_scope.update(str(symbol) for symbol in assets)
        weights: dict[str, float] = {}
        for symbol, position in positions.items():
            if symbol not in in_scope:
                continue
            qty = float(position.qty)
            if not math.isfinite(qty):
                return "actual_exposure_nonfinite_quantity", {
                    "invalid_position_count": 1.0
                }
            if abs(qty) <= 1e-12:
                continue
            market_value = float(position.market_value)
            if not math.isfinite(market_value):
                return "actual_exposure_nonfinite_market_value", {"symbol_count": float(len(weights))}
            current_price = float(position.current_price)
            if not math.isfinite(current_price) or current_price <= 0.0:
                return "actual_exposure_invalid_current_price", {
                    "invalid_position_count": 1.0
                }
            if market_value == 0.0 or math.copysign(1.0, market_value) != math.copysign(1.0, qty):
                return "actual_exposure_invalid_market_value_sign", {
                    "invalid_position_count": 1.0
                }
            expected_market_value = qty * current_price
            if abs(market_value - expected_market_value) > max(
                1.0, abs(expected_market_value) * 0.01
            ):
                return "actual_exposure_inconsistent_market_value", {
                    "invalid_position_count": 1.0
                }
            weights[symbol] = market_value / account.equity

        gross = float(sum(abs(weight) for weight in weights.values()))
        net = float(sum(weights.values()))
        maximum_position = float(max((abs(weight) for weight in weights.values()), default=0.0))
        metrics = {
            "gross_exposure": gross,
            "net_exposure": net,
            "maximum_position_weight": maximum_position,
            "position_count": float(len(weights)),
        }
        portfolio = self.config.strategy.portfolio
        beta_map = (
            latest_plan.metadata.get("asset_beta", {})
            if latest_plan is not None
            else {}
        )
        beta_values: dict[str, float] = {}
        missing_beta_count = 0
        invalid_beta_count = 0
        if portfolio.beta_neutral and weights:
            if not isinstance(beta_map, dict):
                missing_beta_count = len(weights)
            else:
                for symbol in weights:
                    if symbol not in beta_map:
                        missing_beta_count += 1
                        continue
                    try:
                        beta_value = float(beta_map[symbol])
                    except (TypeError, ValueError):
                        invalid_beta_count += 1
                        continue
                    if not math.isfinite(beta_value):
                        invalid_beta_count += 1
                        continue
                    beta_values[symbol] = beta_value
        actual_beta = (
            float(
                sum(weight * beta_values[symbol] for symbol, weight in weights.items())
            )
            if weights and len(beta_values) == len(weights)
            else 0.0
        )
        if len(beta_values) == len(weights):
            metrics["beta_exposure"] = actual_beta
        if missing_beta_count:
            metrics["missing_beta_count"] = float(missing_beta_count)
        if invalid_beta_count:
            metrics["invalid_beta_count"] = float(invalid_beta_count)
        if gross > portfolio.max_gross_leverage + self.config.actual_gross_exposure_tolerance:
            return "actual_gross_exposure_breach", metrics
        if (
            portfolio.dollar_neutral
            and abs(net) > self.config.actual_net_exposure_limit
        ):
            return "actual_net_exposure_breach", metrics
        if portfolio.beta_neutral and weights and (
            missing_beta_count or invalid_beta_count
        ):
            return "actual_beta_metadata_breach", metrics
        if (
            portfolio.beta_neutral
            and abs(actual_beta) > self.config.actual_beta_exposure_limit
        ):
            return "actual_beta_exposure_breach", metrics
        if maximum_position > (
            portfolio.max_position_weight + self.config.actual_position_weight_tolerance
        ):
            return "actual_position_concentration_breach", metrics
        return None, metrics

    def _validated_monitor_plan(self) -> tuple[TargetPlan | None, list[str]]:
        """Select the newest authenticated plan without trusting a forged head row.

        The store verifies lifecycle MACs separately from immutable plan-content
        verification. Both layers are mandatory: status tampering cannot hide an older
        executable/terminal plan, while plan HMAC validation prevents forged economics.
        """

        issues: list[str] = []
        lifecycle_reader = getattr(self.store, "monitor_plan_candidates", None)
        candidates: list[TargetPlan] = []
        if callable(lifecycle_reader):
            try:
                verified, invalid = lifecycle_reader(limit=250)
                candidates = list(verified)
                issues.extend(str(item) for item in invalid)
            except (RuntimeError, TypeError, ValueError, OverflowError) as exc:
                issues.append(f"plan_lifecycle_verification:{type(exc).__name__}")
        else:
            issues.append("authenticated_plan_lifecycle_reader_unavailable")

        latest_valid: TargetPlan | None = None
        for candidate in candidates:
            if candidate.status not in _MONITOR_PLAN_STATUSES:
                issues.append(f"{candidate.plan_id}:invalid_lifecycle_status")
                continue
            try:
                validate_target_plan_integrity(
                    candidate,
                    self._current_plan_binding(),
                    self.config.plan_authentication_key_bytes,
                )
            except (RuntimeError, TypeError, ValueError, OverflowError) as exc:
                issues.append(
                    f"{candidate.plan_id}:content_or_binding:{type(exc).__name__}"
                )
                continue
            assets = candidate.metadata.get("assets")
            if (
                not isinstance(assets, list)
                or not assets
                or any(not isinstance(symbol, str) or not symbol for symbol in assets)
                or len(set(assets)) != len(assets)
            ):
                issues.append(f"{candidate.plan_id}:invalid_asset_metadata")
                continue
            if latest_valid is None:
                latest_valid = candidate
        return latest_valid, issues

    def monitor(self) -> RiskDecision:
        run_id = self.store.start_run("monitor")
        try:
            clock = self.broker.get_market_clock()
            account = self.broker.get_account()
            decision = self._evaluate_risk(account, clock.timestamp)

            # Once objective risk requires liquidation, no unrelated inspection may
            # delay it. Emergency reconciliation already cancels every relevant order.
            if decision.flatten:
                self.emergency_flatten(decision.reason, persist_halt=decision.halt)
                self.store.finish_run(run_id, "success", decision.reason, asdict(decision))
                return decision

            stale_seconds = max(self.config.order_fill_timeout_seconds * 2, 120)
            now = self._local_time(clock.timestamp)
            open_orders = self.broker.list_open_orders(
                None if self.config.dedicated_account else self._managed_symbols()
            )
            self._mark_progress()
            managed_orders, unauthorized, managed_records, ownership_failures = (
                self._partition_authenticated_managed_orders(open_orders)
            )
            if unauthorized:
                reason = (
                    "unauthorized_dedicated_account_order"
                    if self.config.dedicated_account
                    else "unowned_shared_account_strategy_order"
                )
                if not self.config.dedicated_account:
                    # An unowned order on a strategy symbol can change bot-managed
                    # exposure, but a shared-account process has no authority to cancel
                    # it.  Latch a halt and require human reconciliation.
                    self._persist_unowned_shared_order_halt(
                        unauthorized,
                        ownership_failures,
                        stage="monitor",
                    )
                    decision = RiskDecision(
                        allow_new_risk=False,
                        flatten=False,
                        halt=True,
                        reason=reason,
                        drawdown=decision.drawdown,
                        daily_return=decision.daily_return,
                        five_day_return=decision.five_day_return,
                    )
                    self.store.finish_run(run_id, "success", reason, asdict(decision))
                    return decision
                # Persist the mandatory incident before the first cancellation call.
                # If the broker call blocks or fails, a replacement process still sees
                # an account-wide flatten requirement rather than a routine halt.
                self.store.request_halt(reason, flatten=True)
                self.broker.cancel_orders_and_wait(
                    None,
                    client_prefix=None,
                    timeout_seconds=self.config.order_fill_timeout_seconds,
                    poll_seconds=self.config.order_poll_seconds,
                )
                self._mark_progress()
                self.store.record_event(
                    "CRITICAL",
                    "UNAUTHORIZED_ACCOUNT_ORDER",
                    "An order outside the automation client-ID namespace was found "
                    "in the dedicated account; all account orders were canceled and "
                    "exposure reconciliation was required.",
                    {
                        "order_count": len(unauthorized),
                        "symbols": sorted({order.symbol for order in unauthorized}),
                        "ownership_failures": ownership_failures,
                    },
                )
                decision = RiskDecision(
                    allow_new_risk=False,
                    flatten=True,
                    halt=True,
                    reason=reason,
                    drawdown=decision.drawdown,
                    daily_return=decision.daily_return,
                    five_day_return=decision.five_day_return,
                )
                self.emergency_flatten(reason, persist_halt=True)
                self.store.finish_run(run_id, "success", reason, asdict(decision))
                return decision

            for order in managed_orders:
                submitted = self._local_time(order.submitted_at)
                if (now - submitted).total_seconds() > stale_seconds:
                    try:
                        canceled = self.broker.cancel_order_and_wait(
                            order.broker_order_id,
                            timeout_seconds=self.config.order_fill_timeout_seconds,
                            poll_seconds=self.config.order_poll_seconds,
                        )
                        self._mark_progress()
                        self._validate_order_receipt(
                            canceled,
                            symbol=order.symbol,
                            qty=order.qty,
                            side=OrderSide(str(order.side).lower()),
                            client_order_id=order.client_order_id,
                        )
                        if canceled.status.lower() not in TERMINAL_ORDER_STATUSES:
                            raise RuntimeError(
                                "Stale authenticated order cancellation did not reach a "
                                f"terminal state for {order.client_order_id}."
                            )
                    except Exception as cancel_exc:
                        reason = "stale_managed_order_cancellation_unconfirmed"
                        marker_error: Exception | None = None
                        try:
                            merge_control_marker(
                                self.config.kill_switch_path,
                                reason,
                                flatten=self.config.dedicated_account,
                            )
                        except Exception as exc:
                            marker_error = exc
                        self.store.request_halt(
                            reason,
                            flatten=self.config.dedicated_account,
                        )
                        self.store.record_event(
                            "CRITICAL",
                            "STALE_ORDER_CANCELLATION_UNCONFIRMED",
                            str(cancel_exc),
                            {
                                "client_order_id": order.client_order_id,
                                "broker_order_id": order.broker_order_id,
                                "dedicated_account": self.config.dedicated_account,
                                "control_marker_error": (
                                    type(marker_error).__name__
                                    if marker_error is not None
                                    else ""
                                ),
                            },
                        )
                        if self.config.dedicated_account:
                            decision = RiskDecision(
                                allow_new_risk=False,
                                flatten=True,
                                halt=True,
                                reason=reason,
                                drawdown=decision.drawdown,
                                daily_return=decision.daily_return,
                                five_day_return=decision.five_day_return,
                            )
                            self.emergency_flatten(reason, persist_halt=True)
                            self.store.finish_run(
                                run_id, "success", reason, asdict(decision)
                            )
                            return decision
                        raise RuntimeError(
                            "Stale authenticated order cancellation was not confirmed; "
                            "the shared-account halt remains active."
                        ) from cancel_exc
                    record = managed_records[order.client_order_id]
                    self.store.record_order(
                        record.get("plan_id")
                        if isinstance(record.get("plan_id"), str)
                        else None,
                        str(record["phase"]),
                        canceled,
                    )
                    self.store.record_event(
                        "WARNING",
                        "STALE_ORDER_CANCELED",
                        f"Canceled stale managed order {order.client_order_id}.",
                    )

            if not decision.flatten:
                exposure_reason, exposure_metrics = self._actual_exposure_breach(account)
                if exposure_reason is not None:
                    self._best_effort_emergency_store(
                        "request_halt", exposure_reason, flatten=True
                    )
                    self._best_effort_emergency_store(
                        "record_event",
                        "CRITICAL",
                        "ACTUAL_EXPOSURE_BREACH",
                        exposure_reason,
                        exposure_metrics,
                    )
                    decision = RiskDecision(
                        allow_new_risk=False,
                        flatten=True,
                        halt=True,
                        reason=exposure_reason,
                        drawdown=decision.drawdown,
                        daily_return=decision.daily_return,
                        five_day_return=decision.five_day_return,
                    )

            if decision.flatten:
                self.emergency_flatten(decision.reason, persist_halt=decision.halt)
            self.store.finish_run(run_id, "success", decision.reason, asdict(decision))
            return decision
        except Exception as exc:
            self.store.record_event("ERROR", "MONITOR_FAILED", str(exc))
            self.store.finish_run(run_id, "failed", str(exc))
            raise

    def execute_latest_plan(self, force: bool = False) -> ExecutionSummary:
        run_id = self.store.start_run("execute", {"force": force, "mode": self.config.mode_label})
        self._routine_emergency_triggered = False
        self._active_live_borrow_evidence = None
        plan: TargetPlan | None = None
        submitted = 0
        filled = 0
        submitted_intents: list[OrderIntent] = []
        exposure_change_started = False
        flatten_attempted = False
        plan_status_set = False
        try:
            clock = self.broker.get_market_clock()
            local_date = self._local_time(clock.timestamp).date()
            if not clock.is_open and not (force and self.config.broker == "simulated"):
                raise RuntimeError("Execution is blocked while the broker market clock is closed.")

            plan = self.store.latest_plan(
                statuses=("approved", "previewed", "partial"),
                before_date=None if force else local_date,
            )
            if plan is None:
                raise RuntimeError("No approved, unexecuted target plan is available.")
            # Reject stale, legacy, cross-universe, cross-account, or logically
            # modified plans before any broker order/cancel operation can occur.
            validate_target_plan_integrity(
                plan,
                self._current_plan_binding(),
                self.config.plan_authentication_key_bytes,
            )
            self._active_routine_plan = plan
            if self._governed_execution_enabled():
                intended_session, provenance, evidence_symbols = (
                    self._governed_plan_contract(plan)
                )
                if local_date != intended_session:
                    if local_date > intended_session:
                        self.store.mark_plan_status(
                            plan.plan_id,
                            "expired",
                            "Plan missed its exact signed next exchange session.",
                        )
                        plan_status_set = True
                    raise RuntimeError(
                        f"Plan {plan.plan_id} is executable only on its exact signed "
                        f"next exchange session {intended_session.isoformat()}; broker "
                        f"session is {local_date.isoformat()}."
                    )
                self._require_governed_execution_window(
                    clock,
                    intended_session=intended_session,
                    context="Governed execution",
                )
                self._revalidate_governed_covariance_evidence(
                    plan,
                    intended_session=intended_session,
                    provenance=provenance,
                    evidence_symbols=evidence_symbols,
                    clock_timestamp=clock.timestamp,
                )
                # Evidence reload/anchoring is read-heavy. Re-read the broker clock so
                # a call that crossed 09:35 cannot continue into routine mutations.
                clock = self.broker.get_market_clock()
                self._require_governed_execution_window(
                    clock,
                    intended_session=intended_session,
                    context="Governed execution after evidence revalidation",
                )
                self._active_routine_execution_date = intended_session
            else:
                plan_age = (local_date - plan.as_of).days
                if plan_age > self.config.max_plan_age_days and not (
                    force and self.config.broker == "simulated"
                ):
                    self.store.mark_plan_status(
                        plan.plan_id, "expired", "Plan exceeded maximum age."
                    )
                    plan_status_set = True
                    raise RuntimeError(
                        f"Plan {plan.plan_id} is {plan_age} days old and was expired."
                    )

            account = self.broker.get_account()
            decision = self._evaluate_risk(account, clock.timestamp)
            if not decision.allow_new_risk or decision.flatten:
                if decision.flatten:
                    flatten_attempted = True
                    self.emergency_flatten(decision.reason, persist_halt=decision.halt)
                self.store.mark_plan_status(plan.plan_id, "halted", decision.reason)
                plan_status_set = True
                raise RuntimeError(f"Execution blocked by risk control: {decision.reason}")

            plan_symbols = self._plan_symbols(plan)
            positions = self.broker.get_positions()
            foreign_positions = self._foreign_dedicated_positions(plan, positions)
            if foreign_positions:
                self._persist_foreign_position_halt(
                    foreign_positions,
                    stage="execution_initial_snapshot",
                )
                if self.config.execution_enabled:
                    flatten_attempted = True
                    self._routine_emergency_triggered = True
                    self.emergency_flatten(
                        "unauthorized_dedicated_account_position",
                        persist_halt=True,
                    )
                raise RuntimeError(
                    "Execution found a dedicated-account position outside the "
                    "authenticated plan universe."
                )
            symbols = self._reconciliation_symbols(plan, positions)
            prices = self._execution_prices(symbols, positions)
            available_plan_prices = sum(
                1 for symbol in plan_symbols if float(prices.get(symbol, 0.0)) > 0
            )
            if available_plan_prices < self.config.minimum_assets:
                raise RuntimeError(
                    f"Only {available_plan_prices} live plan prices are available; execution requires "
                    f"at least {self.config.minimum_assets}."
                )
            asset_info = self.broker.get_asset_info(plan_symbols)
            target_quantities = self._target_quantities(plan, account, prices, asset_info)
            self._add_flatten_targets(target_quantities, positions, plan)
            reduction_intents, increase_intents = self._build_order_intents(
                plan,
                positions,
                target_quantities,
                prices,
                current_account_equity=account.equity,
            )
            all_intents = reduction_intents + increase_intents
            if len(all_intents) > self.config.max_orders_per_cycle:
                raise RuntimeError(
                    f"Rebalance requires {len(all_intents)} child orders, exceeding "
                    f"MAX_ORDERS_PER_CYCLE={self.config.max_orders_per_cycle}."
                )

            self._validate_projected_portfolio(plan, target_quantities, prices, account)
            if not self.config.execution_enabled:
                self.store.mark_plan_status(plan.plan_id, "previewed", "Execution disabled; no orders submitted.")
                self.store.record_event(
                    "INFO",
                    "EXECUTION_PREVIEW",
                    f"Previewed {len(all_intents)} orders for plan {plan.plan_id}; execution is disabled.",
                    {"intents": [intent.to_dict() for intent in all_intents]},
                )
                summary = ExecutionSummary(
                    plan_id=plan.plan_id,
                    status="previewed",
                    submitted_orders=0,
                    filled_orders=0,
                    residual_notional=self._residual_notional(target_quantities, positions, prices),
                    message="Execution is disabled. No broker orders were submitted.",
                    intents=all_intents,
                )
                self.store.finish_run(run_id, "success", summary.message, asdict(summary))
                return summary

            self.store.mark_plan_status(plan.plan_id, "executing", "Two-phase rebalance started.")

            # Snapshot before cancellation only to detect a fill/cancel race. Replacement
            # intents are always rebuilt from the post-cancellation broker state.
            positions_before_cancel = positions
            # Monitor and execute are separate broker snapshots. An unowned order can
            # appear after monitor returns but before this cancellation boundary. Scan
            # both dedicated and shared scopes and never infer ownership from a prefix.
            pre_cancel_orders = self.broker.list_open_orders(
                None if self.config.dedicated_account else self._managed_symbols(plan)
            )
            (
                authenticated_pre_cancel_orders,
                foreign_orders,
                _,
                pre_cancel_ownership_failures,
            ) = self._partition_authenticated_managed_orders(pre_cancel_orders)
            if foreign_orders:
                if self.config.dedicated_account:
                    reason = "unauthorized_dedicated_account_order"
                    self._persist_foreign_order_halt(
                        reason,
                        foreign_orders,
                        stage="execution_pre_cancel",
                    )
                    self.store.mark_plan_status(plan.plan_id, "halted", reason)
                    plan_status_set = True
                    flatten_attempted = True
                    self.emergency_flatten(reason, persist_halt=True)
                    raise RuntimeError(
                        "Execution found an unauthorized dedicated-account order; "
                        "the mandatory halt was persisted and the account was reconciled."
                    )
                self._persist_unowned_shared_order_halt(
                    foreign_orders,
                    pre_cancel_ownership_failures,
                    stage="execution_pre_cancel",
                )
                self.store.mark_plan_status(
                    plan.plan_id,
                    "halted",
                    "unowned_shared_account_strategy_order",
                )
                plan_status_set = True
                raise RuntimeError(
                    "Execution found an unowned order on a shared-account strategy "
                    "symbol; it was not canceled and routine execution was halted."
                )
            if self._governed_execution_enabled():
                # This is the last read-only boundary before account-order
                # cancellation. Reload both broker positions and the broker clock so
                # an old preflight timestamp cannot admit stale locate terms.
                borrow_positions = self.broker.get_positions()
                borrow_clock = self.broker.get_market_clock()
                self._require_governed_execution_window(
                    borrow_clock,
                    intended_session=intended_session,
                    context="Live borrow evidence before first routine mutation",
                )
                try:
                    borrow_evidence = self._enforce_governed_borrow_or_emergency_reduce(
                        plan,
                        intended_session=intended_session,
                        current_positions=borrow_positions,
                        projected_short_symbols=(
                            symbol
                            for symbol, quantity in target_quantities.items()
                            if float(quantity) < -1e-10
                        ),
                        projected_short_quantities={
                            str(symbol).upper(): abs(float(quantity))
                            for symbol, quantity in target_quantities.items()
                            if float(quantity) < -1e-10
                        },
                        clock_timestamp=borrow_clock.timestamp,
                        stage="before_first_routine_mutation",
                    )
                except Exception:
                    flatten_attempted = True
                    self._best_effort_emergency_store(
                        "mark_plan_status",
                        plan.plan_id,
                        "halted",
                        "Authenticated live borrow policy blocked routine execution.",
                    )
                    plan_status_set = True
                    raise
                # Evidence verification, RSA work, anchoring, and audit commits can
                # consume the remainder of the five-minute benchmark. Recheck both
                # independent clocks after that work and before the first cancellation.
                post_borrow_clock = self.broker.get_market_clock()
                post_borrow_deadline = self._require_governed_execution_window(
                    post_borrow_clock,
                    intended_session=intended_session,
                    context="Governed execution after live borrow authorization",
                )
                post_borrow_wall = (
                    self._enforce_governed_borrow_freshness_or_emergency_reduce(
                        plan,
                        borrow_evidence,
                        intended_session=intended_session,
                        clock_timestamp=post_borrow_clock.timestamp,
                        stage="before_first_routine_mutation:post_verification_freshness",
                    )
                )
                if post_borrow_wall >= post_borrow_deadline:
                    raise RuntimeError(
                        "Routine cancellation was blocked at the hard 09:35 benchmark deadline."
                    )
            cancellation_timeout = float(self.config.order_fill_timeout_seconds)
            routine_cancellation_deadline: datetime | None = None
            if self._governed_execution_enabled():
                routine_cancellation_deadline = post_borrow_deadline
                remaining = self._routine_deadline_remaining_seconds(
                    routine_cancellation_deadline
                )
                if remaining <= 0.0:
                    self._latch_routine_deadline_failure(
                        "routine_pre_execution_cancellation_deadline_unproven"
                    )
                    raise RuntimeError(
                        "Routine order cancellation could not start with time remaining "
                        "to prove terminality before 09:35."
                    )
                cancellation_timeout = min(cancellation_timeout, remaining)
            try:
                if self.config.dedicated_account:
                    canceled_orders = self.broker.cancel_orders_and_wait(
                        None,
                        client_prefix=None,
                        timeout_seconds=cancellation_timeout,
                        poll_seconds=self.config.order_poll_seconds,
                    )
                else:
                    canceled_orders, newly_unowned, ownership_failures = (
                        self._cancel_authenticated_managed_orders(
                            authenticated_pre_cancel_orders,
                            timeout_seconds=cancellation_timeout,
                        )
                    )
                    if newly_unowned:
                        self._persist_unowned_shared_order_halt(
                            newly_unowned,
                            ownership_failures,
                            stage="execution_cancel_reauthentication",
                        )
                        raise RuntimeError(
                            "Authenticated order ownership changed before cancellation."
                        )
            except Exception:
                self.store.request_halt("managed_order_cancellation_unconfirmed", flatten=False)
                raise
            if (
                routine_cancellation_deadline is not None
                and self._routine_deadline_remaining_seconds(
                    routine_cancellation_deadline
                ) <= 0.0
            ):
                self._latch_routine_deadline_failure(
                    "routine_pre_execution_cancellation_terminality_unproven",
                    canceled_orders,
                )
                raise RuntimeError(
                    "Broker cancellation returned at or after 09:35; pre-deadline "
                    "terminality was not proven."
                )

            foreign_canceled = self._foreign_dedicated_orders(canceled_orders)
            if foreign_canceled:
                # This covers an order that raced the read-only pre-scan. Cancellation
                # has already made it terminal, but no positions or new strategy orders
                # are handled until the mandatory incident is durably latched.
                reason = "unauthorized_dedicated_account_order"
                self._persist_foreign_order_halt(
                    reason,
                    foreign_canceled,
                    stage="execution_cancel_race",
                )
                self.store.mark_plan_status(plan.plan_id, "halted", reason)
                plan_status_set = True
                flatten_attempted = True
                self.emergency_flatten(reason, persist_halt=True)
                raise RuntimeError(
                    "Execution cancellation exposed an unauthorized dedicated-account "
                    "order; the mandatory halt was persisted and the account was reconciled."
                )

            # A new order can race either cancellation implementation. Dedicated
            # accounts fail into account-wide reconciliation; shared accounts leave
            # unowned orders untouched and require human review.
            post_cancel_orders = self.broker.list_open_orders(
                None if self.config.dedicated_account else self._managed_symbols(plan)
            )
            if post_cancel_orders:
                (
                    _,
                    post_cancel_unowned,
                    _,
                    post_cancel_failures,
                ) = self._partition_authenticated_managed_orders(post_cancel_orders)
                if self.config.dedicated_account:
                    reason = (
                        "unauthorized_dedicated_account_order"
                        if post_cancel_unowned
                        else "concurrent_authenticated_order_after_cancellation"
                    )
                    if post_cancel_unowned:
                        self._persist_foreign_order_halt(
                            reason,
                            post_cancel_unowned,
                            stage="execution_post_cancel",
                        )
                    else:
                        marker_error: Exception | None = None
                        try:
                            merge_control_marker(
                                self.config.kill_switch_path,
                                reason,
                                flatten=True,
                            )
                        except Exception as exc:
                            marker_error = exc
                        self.store.request_halt(reason, flatten=True)
                        self.store.record_event(
                            "CRITICAL",
                            "CONCURRENT_AUTHENTICATED_ORDER",
                            "An authenticated order appeared after the account-wide "
                            "cancellation boundary; the dedicated account entered "
                            "mandatory emergency reconciliation.",
                            {
                                "stage": "execution_post_cancel",
                                "client_order_ids": sorted(
                                    order.client_order_id
                                    for order in post_cancel_orders
                                ),
                            },
                        )
                        if marker_error is not None:
                            self.logger.error(
                                "The authenticated halt was persisted for a post-cancel "
                                "order race, but the first independent marker write failed: %s",
                                marker_error,
                            )
                    self.store.mark_plan_status(plan.plan_id, "halted", reason)
                    plan_status_set = True
                    flatten_attempted = True
                    self.emergency_flatten(reason, persist_halt=True)
                    raise RuntimeError(
                        "Execution observed an order after cancellation; "
                        "the dedicated account entered mandatory reconciliation."
                    )
                if not self.config.dedicated_account and post_cancel_unowned:
                    self._persist_unowned_shared_order_halt(
                        post_cancel_unowned,
                        post_cancel_failures,
                        stage="execution_post_cancel",
                    )
                if not post_cancel_unowned:
                    reason = "managed_order_cancellation_unconfirmed"
                    marker_error = None
                    try:
                        merge_control_marker(
                            self.config.kill_switch_path,
                            reason,
                            flatten=False,
                        )
                    except Exception as exc:
                        marker_error = exc
                    self.store.request_halt(reason, flatten=False)
                    if marker_error is not None:
                        raise RuntimeError(
                            "Shared-account cancellation was unconfirmed and the "
                            "independent halt marker could not be persisted."
                        ) from marker_error
                raise RuntimeError(
                    "Open strategy-scope orders remained after the cancellation boundary."
                )

            positions = self.broker.get_positions()
            if self._position_quantities_changed(positions_before_cancel, positions):
                exposure_change_started = True
            foreign_positions = self._foreign_dedicated_positions(plan, positions)
            if foreign_positions:
                self._persist_foreign_position_halt(
                    foreign_positions,
                    stage="execution_post_cancel_snapshot",
                )
                raise RuntimeError(
                    "Execution found a dedicated-account position outside the "
                    "authenticated plan after cancellation."
                )

            account = self.broker.get_account()
            decision = self._evaluate_risk(account, clock.timestamp)
            if not decision.allow_new_risk or decision.flatten:
                if decision.flatten:
                    flatten_attempted = True
                    self.emergency_flatten(decision.reason, persist_halt=decision.halt)
                self.store.mark_plan_status(plan.plan_id, "halted", decision.reason)
                plan_status_set = True
                raise RuntimeError(
                    "Execution blocked by risk control after order cancellation: "
                    f"{decision.reason}"
                )

            symbols = self._reconciliation_symbols(plan, positions)
            prices = self._execution_prices(symbols, positions)
            available_plan_prices = sum(
                1 for symbol in plan_symbols if float(prices.get(symbol, 0.0)) > 0
            )
            if available_plan_prices < self.config.minimum_assets:
                raise RuntimeError(
                    f"Only {available_plan_prices} live plan prices remain after cancellation; "
                    f"execution requires at least {self.config.minimum_assets}."
                )
            asset_info = self.broker.get_asset_info(plan_symbols)
            target_quantities = self._target_quantities(plan, account, prices, asset_info)
            self._add_flatten_targets(target_quantities, positions, plan)
            reduction_intents, increase_intents = self._build_order_intents(
                plan,
                positions,
                target_quantities,
                prices,
                current_account_equity=account.equity,
            )
            all_intents = reduction_intents + increase_intents
            if len(all_intents) > self.config.max_orders_per_cycle:
                raise RuntimeError(
                    f"Rebalance requires {len(all_intents)} child orders after cancellation, "
                    f"exceeding MAX_ORDERS_PER_CYCLE={self.config.max_orders_per_cycle}."
                )
            self._validate_projected_portfolio(plan, target_quantities, prices, account)

            reduction_intents = self._order_intents_for_transient_limits(
                plan,
                reduction_intents,
                positions,
                prices,
                account_equity=account.equity,
            )

            if reduction_intents:
                exposure_change_started = True
            reduction_receipts = self._submit_and_wait(plan, reduction_intents)
            submitted += len(reduction_receipts)
            filled += sum(receipt.status == "filled" for receipt in reduction_receipts)
            submitted_intents.extend(reduction_intents)

            # Reconcile after risk-reducing fills before allowing any new exposure.
            account_after_reductions = self.broker.get_account()
            decision_after_reductions = self._evaluate_risk(account_after_reductions, clock.timestamp)
            if not decision_after_reductions.allow_new_risk or decision_after_reductions.flatten:
                if decision_after_reductions.flatten:
                    flatten_attempted = True
                    self.emergency_flatten(
                        decision_after_reductions.reason,
                        persist_halt=decision_after_reductions.halt,
                    )
                raise RuntimeError(
                    "Risk controls blocked the increase phase after reductions: "
                    f"{decision_after_reductions.reason}"
                )
            refreshed_positions = self.broker.get_positions()
            refreshed_symbols = self._reconciliation_symbols(plan, refreshed_positions)
            refreshed_prices = self._execution_prices(
                set(refreshed_symbols) | set(target_quantities),
                refreshed_positions,
            )
            # Targets for existing plan assets remain fixed for this rebalance, while a
            # newly observed dedicated-account position is explicitly targeted to zero.
            self._add_flatten_targets(target_quantities, refreshed_positions, plan)
            remaining_reductions, refreshed_increases = self._build_order_intents(
                plan,
                refreshed_positions,
                target_quantities,
                refreshed_prices,
                current_account_equity=account_after_reductions.equity,
            )
            if (
                submitted + len(remaining_reductions) + len(refreshed_increases)
                > self.config.max_orders_per_cycle
            ):
                raise RuntimeError(
                    "Post-reduction reconciliation exceeds the remaining order budget."
                )
            if remaining_reductions:
                remaining_reductions = self._order_intents_for_transient_limits(
                    plan,
                    remaining_reductions,
                    refreshed_positions,
                    refreshed_prices,
                    account_equity=account_after_reductions.equity,
                )
                exposure_change_started = True
                follow_up_reductions = self._submit_and_wait(plan, remaining_reductions)
                submitted += len(follow_up_reductions)
                filled += sum(receipt.status == "filled" for receipt in follow_up_reductions)
                submitted_intents.extend(remaining_reductions)
                refreshed_positions = self.broker.get_positions()
                refreshed_symbols = self._reconciliation_symbols(plan, refreshed_positions)
                refreshed_prices = self._execution_prices(
                    set(refreshed_symbols) | set(target_quantities),
                    refreshed_positions,
                )
                self._add_flatten_targets(target_quantities, refreshed_positions, plan)
                account_after_reductions = self.broker.get_account()
                still_reducing, refreshed_increases = self._build_order_intents(
                    plan,
                    refreshed_positions,
                    target_quantities,
                    refreshed_prices,
                    current_account_equity=account_after_reductions.equity,
                )
                if (
                    submitted + len(still_reducing) + len(refreshed_increases)
                    > self.config.max_orders_per_cycle
                ):
                    raise RuntimeError(
                        "Follow-up reconciliation exceeds the remaining order budget."
                    )
                if still_reducing:
                    raise RuntimeError(
                        "Risk-reducing orders did not reconcile before the increase phase."
                    )
                decision_after_reductions = self._evaluate_risk(
                    account_after_reductions, clock.timestamp
                )
                if (
                    not decision_after_reductions.allow_new_risk
                    or decision_after_reductions.flatten
                ):
                    if decision_after_reductions.flatten:
                        flatten_attempted = True
                        self.emergency_flatten(
                            decision_after_reductions.reason,
                            persist_halt=decision_after_reductions.halt,
                        )
                    raise RuntimeError(
                        "Risk controls blocked increases after follow-up reductions: "
                        f"{decision_after_reductions.reason}"
                    )
            self._validate_projected_portfolio(
                plan,
                target_quantities,
                refreshed_prices,
                account_after_reductions,
            )
            opening_notional = sum(intent.estimated_notional for intent in refreshed_increases)
            available = max(account_after_reductions.buying_power * (1.0 - self.config.buying_power_buffer), 0.0)
            if opening_notional > available + 1e-6:
                raise RuntimeError(
                    f"Opening notional {opening_notional:,.2f} exceeds buffered buying power "
                    f"{available:,.2f}."
                )

            if refreshed_increases:
                refreshed_increases = self._order_intents_for_transient_limits(
                    plan,
                    refreshed_increases,
                    refreshed_positions,
                    refreshed_prices,
                    account_equity=account_after_reductions.equity,
                )
                exposure_change_started = True
            increase_receipts = self._submit_and_wait(plan, refreshed_increases)
            submitted += len(increase_receipts)
            filled += sum(receipt.status == "filled" for receipt in increase_receipts)
            submitted_intents.extend(refreshed_increases)

            final_positions = self._await_stable_routine_broker_state(
                plan,
                context="Final execution reconciliation",
            )
            self._add_flatten_targets(target_quantities, final_positions, plan)
            final_symbols = sorted(set(target_quantities) | set(final_positions))
            final_prices = self._execution_prices(
                final_symbols,
                final_positions,
                # Use the newest quote set validated during this run. This includes a
                # dedicated-account position first observed after initial cancellation.
                fallback=refreshed_prices,
            )
            residual = self._residual_notional(target_quantities, final_positions, final_prices)
            if residual > self.config.residual_notional_tolerance:
                raise RuntimeError(
                    f"Final residual notional {residual:,.2f} exceeds the reconciliation "
                    f"tolerance {self.config.residual_notional_tolerance:,.2f}."
                )
            status = "executed"
            message = f"Plan executed with residual notional {residual:,.2f}."
            self.store.mark_plan_status(plan.plan_id, status, message)
            self.store.record_event(
                "INFO",
                "EXECUTION_COMPLETE",
                message,
                {"plan_id": plan.plan_id, "submitted": submitted, "filled": filled},
            )
            summary = ExecutionSummary(
                plan_id=plan.plan_id,
                status=status,
                submitted_orders=submitted,
                filled_orders=filled,
                residual_notional=residual,
                message=message,
                intents=submitted_intents,
            )
            self.store.finish_run(
                run_id,
                "success",
                message,
                asdict(summary),
            )
            return summary
        except Exception as exc:
            if plan is not None and not plan_status_set:
                terminal_status = (
                    "halted" if self._routine_emergency_triggered else "failed"
                )
                self._best_effort_emergency_store(
                    "mark_plan_status", plan.plan_id, terminal_status, str(exc)
                )
            self._best_effort_emergency_store(
                "record_event", "ERROR", "EXECUTION_FAILED", str(exc)
            )
            if (
                self.config.execution_enabled
                and self.config.flatten_on_execution_error
                and exposure_change_started
                and not flatten_attempted
                and not self._routine_emergency_triggered
            ):
                try:
                    self.emergency_flatten(f"execution_error:{exc}", persist_halt=True)
                except Exception as flatten_exc:
                    self._best_effort_emergency_store(
                        "record_event",
                        "CRITICAL",
                        "EMERGENCY_FLATTEN_FAILED",
                        str(flatten_exc),
                    )
            elif (
                exposure_change_started
                and not flatten_attempted
                and not self._routine_emergency_triggered
            ):
                # If automatic flattening is disabled, an execution-path failure still
                # persists a halt. Human reconciliation is required before any new risk.
                self._best_effort_emergency_store(
                    "request_halt",
                    f"execution_state_requires_reconciliation:{exc}", flatten=False
                )
            self._best_effort_emergency_store(
                "finish_run", run_id, "failed", str(exc)
            )
            raise
        finally:
            self._active_routine_execution_date = None
            self._active_routine_plan = None
            self._active_routine_child_authorization = None
            self._active_live_borrow_evidence = None

    def recover_incomplete_execution(self) -> bool:
        """Fail closed when a prior process stopped during a rebalance.

        Reconstructing the exact exchange state after an abrupt process death can be
        ambiguous. The unattended-safe action is to halt, cancel managed orders, and
        flatten managed positions before requiring manual review.
        """
        plan = self.store.latest_plan(statuses=("executing",))
        if plan is None:
            return False
        reason = f"startup_recovery_incomplete_execution:{plan.plan_id}"
        self.store.request_halt(reason, flatten=True)
        self.store.record_event(
            "CRITICAL",
            "INCOMPLETE_EXECUTION_RECOVERY",
            f"Found plan {plan.plan_id} in executing state; failing closed.",
        )
        self.emergency_flatten(reason, persist_halt=True)
        self.store.mark_plan_status(
            plan.plan_id,
            "failed",
            "Daemon recovered an interrupted execution and flattened managed positions.",
        )
        return True

    def emergency_flatten(self, reason: str, persist_halt: bool = True) -> list[OrderReceipt]:
        control = merge_control_marker(
            self.config.kill_switch_path,
            reason,
            flatten=True,
        )
        if control.incident_id is None:
            raise RuntimeError("Emergency control marker has no stable incident UUID.")
        incident_id = self.emergency_journal.resolve_incident(control.incident_id)
        if incident_id != control.incident_id:
            control = merge_control_marker(
                self.config.kill_switch_path,
                control.reason,
                flatten=True,
                authoritative_incident_id=incident_id,
            )
        reason = control.reason
        if persist_halt:
            self._best_effort_emergency_store("request_halt", reason, flatten=True)
        managed_symbols = self._managed_symbols()
        # The marker/journal UUID is the cross-process attempt identity. SQLite's
        # flatten-attempt row is optional audit bookkeeping only.
        attempt_id: str = incident_id
        persisted_attempt = self._best_effort_emergency_store(
            "begin_flatten_attempt", reason
        )
        store_attempt_id = (
            persisted_attempt
            if isinstance(persisted_attempt, str) and persisted_attempt
            else incident_id
        )
        receipts: list[OrderReceipt] = []

        # Multiple rounds are needed because a cancel can race with a fill and because a
        # market order can be partially filled before becoming terminal. Each round starts
        # by proving there are no live orders that can mutate the next position snapshot.
        max_submission_rounds = 3
        max_reconciliation_rounds = max_submission_rounds + 2
        submission_round = 0
        submission_may_have_occurred = False
        submitted_client_order_ids: list[str] = []
        flat_position_snapshots: list[dict[str, float]] = []
        flat_order_snapshots: list[list[str]] = []
        try:
            for reconciliation_round in range(max_reconciliation_rounds):
                if self.config.dedicated_account:
                    canceled = self.broker.cancel_orders_and_wait(
                        None,
                        client_prefix=None,
                        timeout_seconds=self.config.order_fill_timeout_seconds,
                        poll_seconds=self.config.order_poll_seconds,
                    )
                else:
                    scoped_open = self.broker.list_open_orders(managed_symbols)
                    canceled, unowned, ownership_failures = (
                        self._cancel_authenticated_managed_orders(
                            scoped_open,
                            timeout_seconds=self.config.order_fill_timeout_seconds,
                            best_effort_persistence=True,
                        )
                    )
                    if unowned and reconciliation_round == 0:
                        self._persist_unowned_shared_order_halt(
                            unowned,
                            ownership_failures,
                            stage="emergency_flatten",
                        )
                self._mark_progress()
                if canceled:
                    flat_position_snapshots.clear()
                    flat_order_snapshots.clear()
                    self._best_effort_emergency_store(
                        "record_event",
                        "WARNING",
                        "SHUTDOWN_ORDERS_CANCELED",
                        f"Reconciled {len(canceled)} open orders before emergency flattening.",
                        {
                            "dedicated_account": self.config.dedicated_account,
                            "round": reconciliation_round + 1,
                        },
                    )

                positions = self.broker.get_positions()
                self._mark_progress()
                if self.config.dedicated_account:
                    managed = dict(positions)
                else:
                    managed_set = set(managed_symbols)
                    managed = {
                        symbol: position
                        for symbol, position in positions.items()
                        if symbol in managed_set
                    }
                nonfinite_symbols = sorted(
                    symbol
                    for symbol, position in managed.items()
                    if not math.isfinite(float(position.qty))
                )
                if nonfinite_symbols:
                    raise RuntimeError(
                        "Emergency flatten cannot prove exposure from non-finite position "
                        "quantities: " + ", ".join(nonfinite_symbols)
                    )
                managed_quantities = {
                    symbol: float(position.qty)
                    for symbol, position in managed.items()
                }
                managed = {
                    symbol: position
                    for symbol, position in managed.items()
                    if abs(float(position.qty)) > 1e-10
                }

                # A second open-order query makes completion contingent on both sides of
                # the broker state: zero positions and zero relevant live orders.
                remaining_open = self._relevant_open_orders(managed_symbols)
                if not managed and not remaining_open:
                    # Position APIs can lag a terminal cancel/fill response. Require a
                    # second independent zero-position/zero-order snapshot before an
                    # emergency incident is acknowledged as flat.
                    flat_position_snapshots.append(managed_quantities)
                    flat_order_snapshots.append(
                        [order.client_order_id for order in remaining_open]
                    )
                    if len(flat_position_snapshots) < 2:
                        if self.config.broker != "simulated":
                            time_module.sleep(
                                min(max(float(self.config.order_poll_seconds), 0.05), 1.0)
                            )
                        continue
                    # The SQLite-independent journal is the authoritative idempotency
                    # boundary and must be completed before optional strategy-state
                    # bookkeeping can fail.
                    self.emergency_journal.complete_incident(
                        incident_id,
                        flat_position_snapshots[-2:],
                        flat_order_snapshots[-2:],
                    )
                    self._best_effort_emergency_store(
                        "finish_active_flatten_attempt",
                        "completed", "No relevant positions or open orders remain."
                    )
                    self._best_effort_emergency_store(
                        "record_event",
                        "CRITICAL" if receipts else "WARNING",
                        "PORTFOLIO_FLATTENED" if receipts else "FLATTEN_NO_POSITIONS",
                        (
                            f"Reconciled emergency flatten after {len(receipts)} order(s): {reason}"
                            if receipts
                            else reason
                        ),
                        {"flatten_attempt_id": attempt_id} if attempt_id else {},
                    )
                    return receipts

                flat_position_snapshots.clear()
                flat_order_snapshots.clear()
                if remaining_open:
                    # A concurrently submitted order was observed after cancellation.
                    # The next bounded round will cancel it before another snapshot.
                    continue

                if not self.config.execution_enabled:
                    raise RuntimeError(
                        "Risk shutdown requires flattening, but execution is disabled; "
                        f"remaining positions: {self._position_summary(managed)}"
                    )
                if submission_round >= max_submission_rounds:
                    break

                round_receipts: list[OrderReceipt] = []
                before_quantities: dict[str, float] = {}
                round_submitted = False
                for symbol, position in sorted(managed.items()):
                    qty = abs(float(position.qty))
                    side = OrderSide.SELL if position.qty > 0 else OrderSide.BUY
                    prepared = self.emergency_journal.prepare_submission(
                        incident_id,
                        symbol=symbol,
                        current_qty=float(position.qty),
                        side=side.value,
                        qty=qty,
                    )
                    baseline_tolerance = max(
                        1e-8, abs(float(prepared.baseline_qty)) * 1e-8
                    )
                    if prepared.reused and not math.isclose(
                        float(position.qty),
                        float(prepared.baseline_qty),
                        abs_tol=baseline_tolerance,
                    ):
                        receipt = self._resolve_stale_emergency_intent(
                            prepared,
                            current_qty=float(position.qty),
                            managed_symbols=managed_symbols,
                        )
                        if receipt is None:
                            # The obsolete client ID was authoritatively absent. A new
                            # current-position intent is prepared only after the next
                            # cancel/position/order reconciliation boundary.
                            continue
                        before_quantities[symbol] = prepared.baseline_qty
                        submission_may_have_occurred = True
                        round_receipts.append(receipt)
                        continue
                    # A restarted process can be reconciling a prior ambiguous order.
                    # Use the journal's original baseline/economics until broker history
                    # proves that intent safe, never the lagging snapshot as a new order.
                    before_quantities[symbol] = prepared.baseline_qty
                    qty = prepared.qty
                    side = OrderSide(prepared.side)
                    client_order_id = prepared.client_order_id
                    # A transport failure can happen after the broker accepted the
                    # request but before it returned a receipt. From this line onward,
                    # broker-only fallback IDs are forbidden for the incident.
                    submission_may_have_occurred = True
                    submitted_client_order_ids.append(client_order_id)
                    receipt = self.broker.submit_emergency_market_order(
                        symbol, qty, side, client_order_id
                    )
                    round_submitted = True
                    self._validate_order_receipt(
                        receipt,
                        symbol=symbol,
                        qty=qty,
                        side=side,
                        client_order_id=client_order_id,
                    )
                    # Persist the broker result in the independent journal before any
                    # authoritative SQLite write can fail after submission.
                    self.emergency_journal.record_receipt(incident_id, receipt)
                    self._best_effort_emergency_store(
                        "record_order", None, OrderPhase.FLATTEN.value, receipt
                    )
                    round_receipts.append(receipt)
                    self._mark_progress()
                if round_submitted:
                    submission_round += 1
                if not round_receipts:
                    continue
                final_receipts = self._wait_for_receipts(
                    None,
                    OrderPhase.FLATTEN,
                    round_receipts,
                    require_filled=False,
                    best_effort_store=True,
                )
                for receipt in final_receipts:
                    self.emergency_journal.record_receipt(incident_id, receipt)
                receipts.extend(final_receipts)
                positions_after = self.broker.get_positions()
                self._mark_progress()
                self._require_emergency_fill_progress(
                    before_quantities,
                    positions_after,
                    final_receipts,
                )

            positions = self.broker.get_positions()
            if self.config.dedicated_account:
                residual_positions = positions
            else:
                managed_set = set(managed_symbols)
                residual_positions = {
                    symbol: position
                    for symbol, position in positions.items()
                    if symbol in managed_set and abs(float(position.qty)) > 1e-10
                }
            remaining_open = self._relevant_open_orders(managed_symbols)
            raise RuntimeError(
                "Emergency flatten did not reconcile within the bounded retry limit; "
                f"positions={self._position_summary(residual_positions)}, "
                f"open_orders={[order.client_order_id for order in remaining_open]}"
            )
        except EmergencyFillProgressError as exc:
            # Keep the attempt in progress so the same deterministic client IDs are
            # reconciled on retry. Marking it failed would mint replacement IDs and
            # could over-liquidate while the broker position API is lagging.
            try:
                self.store.request_halt(reason, flatten=True)
            except Exception:
                pass
            try:
                self.store.record_event(
                    "CRITICAL",
                    "EMERGENCY_FILL_PROGRESS_AMBIGUOUS",
                    str(exc),
                    {"flatten_attempt_id": attempt_id} if attempt_id else {},
                )
            except Exception:
                pass
            raise
        except Exception as exc:
            if submission_may_have_occurred:
                # Do not mark the attempt failed: a retry must resolve the same
                # deterministic primary IDs. Every store write here is best effort so
                # the original persistence failure cannot be masked or trigger a new
                # qauto-oob liquidation namespace in the daemon.
                try:
                    self.store.request_halt(reason, flatten=True)
                except Exception:
                    pass
                try:
                    self.store.record_event(
                        "CRITICAL",
                        "EMERGENCY_PRIMARY_SUBMISSION_AMBIGUOUS",
                        str(exc),
                        {
                            "flatten_attempt_id": attempt_id,
                            "client_order_ids": submitted_client_order_ids,
                        },
                    )
                except Exception:
                    pass
                raise EmergencyPrimarySubmissionError(
                    "A primary emergency order may have been submitted; refusing a "
                    "broker-only fallback and preserving deterministic primary IDs."
                ) from exc
            self._best_effort_emergency_store(
                "finish_flatten_attempt", store_attempt_id, "failed", str(exc)
            )
            self._best_effort_emergency_store(
                "request_halt", f"flatten_failed:{reason}", flatten=True
            )
            self._best_effort_emergency_store(
                "record_event",
                "CRITICAL",
                "EMERGENCY_FLATTEN_FAILED",
                str(exc),
                {"flatten_attempt_id": attempt_id},
            )
            raise

    def _resolve_stale_emergency_intent(
        self,
        prepared,
        *,
        current_qty: float,
        managed_symbols: list[str],
    ) -> OrderReceipt | None:
        """Resolve, but never resubmit, replay economics from a different baseline.

        A manual fill, partial fill, or lag correction can change the position after an
        emergency intent was durably prepared. Reusing its client ID is necessary, but
        calling the ordinary submit API would allow a broker 404 to dispatch the old
        quantity. Two authoritative absences plus a stable position/order snapshot
        retire that intent; a later reconciliation round then prepares current economics.
        """

        tolerance = max(1e-8, abs(float(prepared.baseline_qty)) * 1e-8)
        if not prepared.reused or math.isclose(
            float(current_qty), float(prepared.baseline_qty), abs_tol=tolerance
        ):
            raise ValueError("Stale emergency resolver requires a changed replay baseline.")

        existing = self.broker.get_order_by_client_id(prepared.client_order_id)
        self._mark_progress()
        if existing is not None:
            side = OrderSide(prepared.side)
            self._validate_order_receipt(
                existing,
                symbol=prepared.symbol,
                qty=prepared.qty,
                side=side,
                client_order_id=prepared.client_order_id,
            )
            self.emergency_journal.record_receipt(prepared.incident_id, existing)
            return existing

        if self.config.broker != "simulated":
            time_module.sleep(
                min(max(float(self.config.order_poll_seconds), 0.05), 1.0)
            )
        refreshed_positions = self.broker.get_positions()
        self._mark_progress()
        refreshed_qty = float(
            refreshed_positions.get(
                prepared.symbol,
                PositionSnapshot(prepared.symbol, 0.0, 0.0, 0.0),
            ).qty
        )
        if not math.isfinite(refreshed_qty) or not math.isclose(
            refreshed_qty, float(current_qty), abs_tol=max(tolerance, 1e-8)
        ):
            raise EmergencyPrimarySubmissionError(
                "Emergency position changed while stale client-ID absence was being "
                "confirmed; no obsolete quantity was submitted."
            )
        remaining_open = self._relevant_open_orders(managed_symbols)
        if remaining_open:
            raise EmergencyPrimarySubmissionError(
                "An order appeared while stale emergency economics were being "
                "reconciled; no obsolete quantity was submitted."
            )
        existing = self.broker.get_order_by_client_id(prepared.client_order_id)
        self._mark_progress()
        if existing is not None:
            side = OrderSide(prepared.side)
            self._validate_order_receipt(
                existing,
                symbol=prepared.symbol,
                qty=prepared.qty,
                side=side,
                client_order_id=prepared.client_order_id,
            )
            self.emergency_journal.record_receipt(prepared.incident_id, existing)
            return existing
        self.emergency_journal.record_not_found(
            prepared.incident_id, prepared.client_order_id
        )
        return None

    @staticmethod
    def _require_emergency_fill_progress(
        before_quantities: dict[str, float],
        positions_after: dict[str, PositionSnapshot],
        receipts: list[OrderReceipt],
    ) -> None:
        """Require reported fills to be reflected before replacement liquidation."""

        filled_by_symbol: dict[str, float] = {}
        for receipt in receipts:
            filled = float(receipt.filled_qty)
            tolerance = max(1e-10, abs(float(receipt.qty)) * 1e-8)
            if receipt.status.lower() == "filled" and filled <= tolerance:
                filled = float(receipt.qty)
            if filled > tolerance:
                filled_by_symbol[receipt.symbol] = (
                    filled_by_symbol.get(receipt.symbol, 0.0) + filled
                )

        for symbol, reported_fill in filled_by_symbol.items():
            if symbol not in before_quantities:
                raise EmergencyFillProgressError(
                    f"Emergency fill for {symbol} has no matching pre-submit position."
                )
            before = float(before_quantities[symbol])
            after = float(positions_after[symbol].qty) if symbol in positions_after else 0.0
            tolerance = max(1e-8, abs(before) * 1e-8)
            required = min(abs(before), reported_fill)
            if before > tolerance:
                safe = after >= -tolerance and after <= before - required + tolerance
            elif before < -tolerance:
                safe = after <= tolerance and after >= before + required - tolerance
            else:
                safe = False
            if not safe:
                raise EmergencyFillProgressError(
                    "Broker reported an emergency fill, but the position snapshot did not "
                    f"show sufficient directional progress for {symbol}; refusing a "
                    "replacement liquidation while broker state is ambiguous."
                )

    def request_kill(self, reason: str = "manual_kill_switch", flatten: bool = True) -> None:
        control_request = merge_control_marker(
            self.config.kill_switch_path,
            reason,
            flatten=flatten,
        )
        flatten = control_request.flatten
        self.store.request_halt(control_request.reason, flatten=flatten)
        self.store.record_event(
            "CRITICAL",
            "MANUAL_KILL_REQUESTED",
            control_request.reason,
            {"flatten_requested": flatten},
        )
        if flatten:
            self.emergency_flatten(control_request.reason, persist_halt=True)
        else:
            managed_symbols = self._managed_symbols()
            if self.config.dedicated_account:
                canceled = self.broker.cancel_orders_and_wait(
                    None,
                    client_prefix=None,
                    timeout_seconds=self.config.order_fill_timeout_seconds,
                    poll_seconds=self.config.order_poll_seconds,
                )
            else:
                scoped_open = self.broker.list_open_orders(managed_symbols)
                canceled, unowned, ownership_failures = (
                    self._cancel_authenticated_managed_orders(
                        scoped_open,
                        timeout_seconds=self.config.order_fill_timeout_seconds,
                    )
                )
                if unowned:
                    self._persist_unowned_shared_order_halt(
                        unowned,
                        ownership_failures,
                        stage="halt_only",
                    )
            self._mark_progress()
            remaining = self._relevant_open_orders(managed_symbols)
            if remaining:
                # Escalate the persisted incident because an order can still mutate
                # exposure despite the requested halt-only boundary.
                self.store.request_halt(
                    f"halt_only_order_cancellation_unconfirmed:{reason}",
                    flatten=True,
                )
                raise RuntimeError(
                    "Halt-only cancellation returned while relevant orders remained open."
                )
            self.store.record_event(
                "WARNING",
                "HALT_ONLY_ORDERS_CANCELED",
                f"Halt-only control confirmed {len(canceled)} order cancellation(s).",
            )

    def _double_account_flat_order_free_snapshots(
        self,
        *,
        stage: str,
    ) -> tuple[list[dict[str, float]], list[list[str]]]:
        """Prove the whole brokerage account is flat and order-free twice.

        Alpaca submission is permitted only for dedicated accounts, so manual release
        deliberately uses account scope rather than a strategy-symbol approximation.
        This also makes simulation exercise the production invariant.
        """

        position_snapshots: list[dict[str, float]] = []
        order_snapshots: list[list[str]] = []
        for confirmation_pass in range(2):
            positions = self.broker.get_positions()
            self._mark_progress()
            open_orders = self.broker.list_open_orders(None)
            self._mark_progress()
            quantities: dict[str, float] = {}
            nonflat: list[str] = []
            for symbol, position in positions.items():
                quantity = float(position.qty)
                quantities[str(symbol).upper()] = quantity
                if not math.isfinite(quantity) or abs(quantity) > 1e-10:
                    nonflat.append(str(symbol).upper())
            if nonflat or open_orders:
                raise RuntimeError(
                    f"Manual resume {stage} requires two consecutive broker-flat and "
                    "order-free snapshots (account-flat and order-free); observed "
                    f"positions={sorted(nonflat)}, orders="
                    f"{sorted(str(order.client_order_id) for order in open_orders)}."
                )
            position_snapshots.append(dict(sorted(quantities.items())))
            order_snapshots.append([])
            if confirmation_pass == 0 and self.config.broker != "simulated":
                time_module.sleep(
                    min(max(float(self.config.order_poll_seconds), 0.05), 1.0)
                )
        return position_snapshots, order_snapshots

    def _latch_resume_reconciliation_failure(self, reason: str) -> None:
        active_incident = self.emergency_journal.active_incident_id()
        marker_error: Exception | None = None
        try:
            merge_control_marker(
                self.config.kill_switch_path,
                reason,
                flatten=True,
                authoritative_incident_id=active_incident,
            )
        except Exception as exc:
            marker_error = exc
        # The independently authenticated halt must still escalate when the control
        # volume is unavailable; neither persistence channel gates the other.
        self.store.request_halt(reason, flatten=True)
        if marker_error is not None:
            raise RuntimeError(
                "Manual resume reconciliation failed and the independent control "
                "marker could not be escalated; the authenticated flatten halt remains."
            ) from marker_error

    def resume(self) -> None:
        active_incident = self.emergency_journal.active_incident_id()
        if active_incident is not None:
            merge_control_marker(
                self.config.kill_switch_path,
                "manual_resume_blocked_active_emergency_incident",
                flatten=True,
                authoritative_incident_id=active_incident,
            )

        # Capture the exact authenticated halt under review before any remote broker
        # or risk calls.  A concurrent replacement must make the final CAS fail.
        expected_halt = self.store.halt_state()
        try:
            expected_control_marker = self.config.kill_switch_path.read_bytes()
        except FileNotFoundError:
            expected_control_marker = None
        except OSError as exc:
            raise RuntimeError(
                "Manual resume could not authenticate the current control marker state."
            ) from exc

        try:
            position_snapshots, order_snapshots = (
                self._double_account_flat_order_free_snapshots(stage="pre-review")
            )
        except Exception:
            self._latch_resume_reconciliation_failure(
                "manual_resume_blocked_account_not_flat_or_order_free"
            )
            raise

        if active_incident is not None:
            self.emergency_journal.complete_incident(
                active_incident,
                position_snapshots,
                order_snapshots,
            )
            if self.emergency_journal.active_incident_id() is not None:
                raise RuntimeError(
                    "Manual resume could not complete the authenticated emergency incident."
                )
        if not expected_halt or expected_halt.get("active") is not True:
            raise RuntimeError(
                "Manual resume requires an exact active authenticated halt to review."
            )

        account = self.broker.get_account()
        # Ignore only the operator halt/cooldown being reviewed. Objective account,
        # drawdown, and loss controls must still pass against the preserved historical
        # high-water mark before the kill marker is removed.
        decision = self.risk.evaluate_and_record(
            account,
            self._local_time(account.timestamp).date(),
            ignore_operator_controls=True,
        )
        if not decision.allow_new_risk or decision.flatten or decision.halt:
            self.store.request_halt(f"resume_blocked:{decision.reason}", flatten=True)
            self.store.record_event(
                "CRITICAL",
                "MANUAL_RESUME_BLOCKED",
                f"Manual resume was blocked by objective risk control: {decision.reason}.",
                asdict(decision),
            )
            raise RuntimeError(
                f"Manual resume blocked by objective risk control: {decision.reason}."
            )
        # Risk evaluation can span remote/account and durable-state calls. A watchdog
        # or independent emergency may publish a new incident during that interval;
        # never unlink a marker or clear a halt that is not the exact reviewed state.
        concurrent_incident = self.emergency_journal.active_incident_id()
        if concurrent_incident is not None:
            merge_control_marker(
                self.config.kill_switch_path,
                "resume_blocked_concurrent_emergency_incident",
                flatten=True,
                authoritative_incident_id=concurrent_incident,
            )
            self.store.request_halt(
                "resume_blocked_concurrent_emergency_incident", flatten=True
            )
            raise RuntimeError(
                "Manual resume blocked by an emergency incident created during review."
            )

        # Broker state may change while objective risk and authenticated history are
        # evaluated.  Re-prove the full account immediately before releasing controls.
        try:
            self._double_account_flat_order_free_snapshots(stage="final-review")
        except Exception:
            self._latch_resume_reconciliation_failure(
                "manual_resume_blocked_account_changed_during_review"
            )
            raise
        if self.emergency_journal.active_incident_id() is not None:
            self._latch_resume_reconciliation_failure(
                "resume_blocked_concurrent_emergency_incident"
            )
            raise RuntimeError(
                "Manual resume blocked by an emergency incident created during final review."
            )

        # Clear only the exact authenticated halt captured above.  This CAS is the
        # durable-state counterpart to the marker's locked compare-and-unlink.
        if not self.store.clear_halt_if_unchanged(expected_halt):
            merge_control_marker(
                self.config.kill_switch_path,
                "resume_authenticated_halt_changed",
                flatten=True,
            )
            raise RuntimeError(
                "Manual resume blocked because the authenticated halt changed during review."
            )
        if not remove_control_marker_if_unchanged(
            self.config.kill_switch_path, expected_control_marker
        ):
            self.store.request_halt("resume_control_marker_changed", flatten=True)
            raise RuntimeError(
                "Manual resume blocked because the control marker changed during review."
            )
        # If a new authenticated halt was published after our successful CAS but did
        # not update the filesystem marker, restore the redundant marker before exit.
        post_clear_halt = self.store.halt_state()
        if post_clear_halt.get("active") is True:
            merge_control_marker(
                self.config.kill_switch_path,
                str(post_clear_halt.get("reason") or "concurrent_authenticated_halt"),
                flatten=bool(post_clear_halt.get("flatten", True)),
            )
            raise RuntimeError(
                "Manual resume was superseded by a concurrent authenticated halt."
            )
        self.store.set_state("cooldown_remaining", 0)
        # Health/watchdog threshold state is deliberately persistent across automatic
        # restart. Only this explicit, independently risk-checked human resume may
        # acknowledge it and allow the next daemon to start from a clean streak.
        self.store.set_state("daemon_consecutive_failures", 0)
        self.config.daemon_health_path.unlink(missing_ok=True)
        self.store.record_event(
            "WARNING",
            "MANUAL_RESUME",
            "Automated trading was manually resumed after objective risk checks passed; "
            "the historical high-water mark was preserved.",
        )

    @staticmethod
    def _plan_symbols(plan: TargetPlan) -> list[str]:
        raw = plan.metadata.get("assets", list(plan.target_weights))
        symbols = [str(symbol) for symbol in raw] if isinstance(raw, list) else []
        if not symbols:
            symbols = [str(symbol) for symbol in plan.target_weights]
        return list(dict.fromkeys(symbols))

    def _reconciliation_symbols(
        self,
        plan: TargetPlan,
        positions: dict[str, PositionSnapshot],
    ) -> list[str]:
        """Return every symbol whose position belongs in this rebalance."""

        symbols = set(self._plan_symbols(plan))
        managed = set(self._managed_symbols(plan))
        for symbol in positions:
            if self.config.dedicated_account or symbol in managed:
                symbols.add(symbol)
        return sorted(symbols)

    def _add_flatten_targets(
        self,
        target_quantities: dict[str, float],
        positions: dict[str, PositionSnapshot],
        plan: TargetPlan,
    ) -> None:
        managed = set(self._managed_symbols(plan))
        for symbol, position in positions.items():
            if not (self.config.dedicated_account or symbol in managed):
                continue
            qty = float(position.qty)
            if not math.isfinite(qty):
                raise RuntimeError(
                    f"Broker returned a non-finite position quantity for {symbol}."
                )
            if abs(qty) > 1e-10:
                target_quantities.setdefault(symbol, 0.0)

    def _execution_prices(
        self,
        symbols: Iterable[str],
        positions: dict[str, PositionSnapshot],
        fallback: dict[str, float] | None = None,
    ) -> dict[str, float]:
        """Fetch executable quote midpoints without trusting position valuation marks.

        ``PositionSnapshot.current_price`` can be delayed, derived, or stale and must
        never bypass the live adapter's quote timestamp/spread gates. ``fallback`` is
        reserved for final, non-submitting reconciliation using a quote that this run
        already validated.
        """

        del positions
        chosen = list(dict.fromkeys(str(symbol) for symbol in symbols))
        prices = dict(fallback or {})
        prices.update(self.broker.get_latest_prices(chosen))
        return {
            symbol: float(price)
            for symbol, price in prices.items()
            if math.isfinite(float(price)) and float(price) > 0
        }

    def _relevant_open_orders(self, managed_symbols: list[str]) -> list[OrderReceipt]:
        # Every live order on a strategy symbol can mutate exposure, irrespective of
        # its client-ID spelling.  Ownership controls whether this process may cancel
        # the order; it must never make an unowned order disappear from flat/order-free
        # reconciliation.
        return self.broker.list_open_orders(
            None if self.config.dedicated_account else managed_symbols
        )

    @staticmethod
    def _managed_order_record_mismatch(
        order: OrderReceipt,
        record: Mapping[str, object] | None,
    ) -> str | None:
        """Return why a broker order is not the exact authenticated local order.

        A ``qauto-`` prefix is intentionally absent from this decision.  Client IDs
        are public broker metadata and can be copied by another account actor.  The
        broker-generated order ID plus the full immutable economics must instead
        match a row covered by StateStore's external authenticated commitment.
        """

        if record is None:
            return "missing_authenticated_record"
        required = {
            "broker_order_id",
            "client_order_id",
            "symbol",
            "side",
            "qty",
            "phase",
        }
        if not required.issubset(record):
            return "malformed_authenticated_record"
        if str(record.get("client_order_id", "")) != str(order.client_order_id):
            return "client_order_id_mismatch"
        if str(record.get("broker_order_id", "")) != str(order.broker_order_id):
            return "broker_order_id_mismatch"
        if str(record.get("symbol", "")).upper() != str(order.symbol).upper():
            return "symbol_mismatch"
        if str(record.get("side", "")).lower() != str(order.side).lower():
            return "side_mismatch"
        try:
            persisted_qty = float(record.get("qty"))
            broker_qty = float(order.qty)
        except (TypeError, ValueError):
            return "quantity_malformed"
        if (
            not math.isfinite(persisted_qty)
            or persisted_qty <= 0.0
            or not math.isfinite(broker_qty)
            or broker_qty <= 0.0
            or not math.isclose(
                persisted_qty,
                broker_qty,
                rel_tol=0.0,
                abs_tol=max(1e-8, abs(persisted_qty) * 1e-8),
            )
        ):
            return "quantity_mismatch"
        if str(record.get("phase", "")) not in {
            OrderPhase.REDUCE.value,
            OrderPhase.INCREASE.value,
            OrderPhase.FLATTEN.value,
        }:
            return "phase_malformed"
        return None

    def _partition_authenticated_managed_orders(
        self,
        orders: Iterable[OrderReceipt],
    ) -> tuple[
        list[OrderReceipt],
        list[OrderReceipt],
        dict[str, dict[str, object]],
        dict[str, str],
    ]:
        """Partition broker orders by exact keyed StateStore ownership proof."""

        candidates = list(orders)
        client_ids = [str(order.client_order_id) for order in candidates]
        broker_ids = [str(order.broker_order_id) for order in candidates]
        if len(candidates) > 250:
            failures = {
                f"{client_id or '<empty>'}:{broker_id or '<empty>'}": (
                    "broker_order_scan_exceeds_authenticated_lookup_bound"
                )
                for client_id, broker_id in zip(client_ids, broker_ids)
            }
            return [], candidates, {}, failures
        requested_ids = sorted({value for value in client_ids if value})
        records_raw = self.store.order_records_by_client_order_ids(requested_ids)
        if not isinstance(records_raw, dict):
            raise RuntimeError(
                "Authenticated managed-order lookup returned an invalid result."
            )
        records: dict[str, dict[str, object]] = {}
        for key, value in records_raw.items():
            if not isinstance(key, str) or key not in requested_ids:
                raise RuntimeError(
                    "Authenticated managed-order lookup returned an unexpected identity."
                )
            if not isinstance(value, dict):
                raise RuntimeError(
                    "Authenticated managed-order lookup returned a malformed row."
                )
            records[key] = dict(value)

        client_counts = Counter(value for value in client_ids if value)
        broker_counts = Counter(value for value in broker_ids if value)
        duplicate_clients = {
            value for value, count in client_counts.items() if count > 1
        }
        duplicate_brokers = {
            value for value, count in broker_counts.items() if count > 1
        }
        managed: list[OrderReceipt] = []
        unowned: list[OrderReceipt] = []
        failures: dict[str, str] = {}
        for order in candidates:
            client_id = str(order.client_order_id)
            broker_id = str(order.broker_order_id)
            if not client_id or not broker_id:
                mismatch = "missing_broker_identity"
            elif client_id in duplicate_clients:
                mismatch = "duplicate_broker_client_order_id"
            elif broker_id in duplicate_brokers:
                mismatch = "duplicate_broker_order_id"
            else:
                mismatch = self._managed_order_record_mismatch(
                    order,
                    records.get(client_id),
                )
            if mismatch is None:
                managed.append(order)
            else:
                unowned.append(order)
                failures[f"{client_id or '<empty>'}:{broker_id or '<empty>'}"] = mismatch
        return managed, unowned, records, failures

    def _cancel_authenticated_managed_orders(
        self,
        orders: Iterable[OrderReceipt],
        *,
        timeout_seconds: float,
        best_effort_persistence: bool = False,
    ) -> tuple[list[OrderReceipt], list[OrderReceipt], dict[str, str]]:
        """Cancel only exact authenticated orders, never a public prefix namespace."""

        managed, unowned, records, failures = (
            self._partition_authenticated_managed_orders(orders)
        )
        canceled: list[OrderReceipt] = []
        deadline = time_module.monotonic() + max(float(timeout_seconds), 0.0)
        for order in managed:
            remaining = max(deadline - time_module.monotonic(), 0.0)
            if remaining <= 0.0:
                raise RuntimeError(
                    "Authenticated managed-order cancellation was not confirmed: "
                    "the bounded batch deadline was exhausted."
                )
            current = self.broker.cancel_order_and_wait(
                order.broker_order_id,
                timeout_seconds=remaining,
                poll_seconds=self.config.order_poll_seconds,
            )
            self._mark_progress()
            self._validate_order_receipt(
                current,
                symbol=order.symbol,
                qty=order.qty,
                side=OrderSide(str(order.side).lower()),
                client_order_id=order.client_order_id,
            )
            if current.status.lower() not in TERMINAL_ORDER_STATUSES:
                raise RuntimeError(
                    "Authenticated managed-order cancellation did not reach a terminal "
                    f"state for {order.client_order_id}."
                )
            record = records[order.client_order_id]
            record_args = (
                record.get("plan_id") if isinstance(record.get("plan_id"), str) else None,
                str(record["phase"]),
                current,
            )
            if best_effort_persistence:
                self._best_effort_emergency_store("record_order", *record_args)
            else:
                self.store.record_order(*record_args)
            canceled.append(current)
        return canceled, unowned, failures

    def _foreign_dedicated_orders(
        self,
        orders: Iterable[OrderReceipt],
    ) -> list[OrderReceipt]:
        if not self.config.dedicated_account:
            return []
        _, unowned, _, _ = self._partition_authenticated_managed_orders(orders)
        return unowned

    def _foreign_dedicated_positions(
        self,
        plan: TargetPlan,
        positions: Mapping[str, PositionSnapshot],
    ) -> dict[str, PositionSnapshot]:
        if not self.config.dedicated_account:
            return {}
        authorized = set(self._plan_symbols(plan))
        return {
            str(symbol).upper(): position
            for symbol, position in positions.items()
            if str(symbol).upper() not in authorized
            and (
                not math.isfinite(float(position.qty))
                or abs(float(position.qty)) > 1e-10
            )
        }

    def _persist_foreign_order_halt(
        self,
        reason: str,
        orders: Iterable[OrderReceipt],
        *,
        stage: str,
    ) -> None:
        foreign = list(orders)
        marker_error: Exception | None = None
        try:
            merge_control_marker(
                self.config.kill_switch_path,
                reason,
                flatten=True,
            )
        except Exception as exc:
            marker_error = exc
        self.store.request_halt(reason, flatten=True)
        self.store.record_event(
            "CRITICAL",
            "UNAUTHORIZED_ACCOUNT_ORDER",
            "An order outside the automation client-ID namespace was found during "
            "dedicated-account execution; routine execution was stopped and account-wide "
            "reconciliation was required.",
            {
                "stage": stage,
                "order_count": len(foreign),
                "symbols": sorted({order.symbol for order in foreign}),
                "client_order_ids": sorted(
                    {order.client_order_id for order in foreign}
                ),
            },
        )
        if marker_error is not None:
            raise RuntimeError(
                "Unauthorized account activity was latched in authenticated state, but "
                "the independent flatten marker could not be persisted."
            ) from marker_error

    def _persist_unowned_shared_order_halt(
        self,
        orders: Iterable[OrderReceipt],
        ownership_failures: Mapping[str, str],
        *,
        stage: str,
    ) -> None:
        """Halt without canceling an order the shared-account bot does not own."""

        unowned = list(orders)
        reason = "unowned_shared_account_strategy_order"
        marker_error: Exception | None = None
        try:
            merge_control_marker(
                self.config.kill_switch_path,
                reason,
                flatten=False,
            )
        except Exception as exc:
            marker_error = exc
        self.store.request_halt(reason, flatten=False)
        self.store.record_event(
            "CRITICAL",
            "UNOWNED_STRATEGY_SCOPE_ORDER",
            "An order on a strategy symbol lacked an exact authenticated ownership "
            "record. The shared-account bot did not cancel it and stopped all routine "
            "execution pending human reconciliation.",
            {
                "stage": stage,
                "order_count": len(unowned),
                "symbols": sorted({str(order.symbol).upper() for order in unowned}),
                "client_order_ids": sorted(
                    {str(order.client_order_id) for order in unowned}
                ),
                "ownership_failures": dict(ownership_failures),
            },
        )
        if marker_error is not None:
            raise RuntimeError(
                "Unowned shared-account activity was latched in authenticated state, "
                "but the independent halt marker could not be persisted."
            ) from marker_error

    def _persist_foreign_position_halt(
        self,
        positions: dict[str, PositionSnapshot],
        *,
        stage: str,
    ) -> None:
        reason = "unauthorized_dedicated_account_position"
        marker_error: Exception | None = None
        try:
            merge_control_marker(
                self.config.kill_switch_path,
                reason,
                flatten=True,
            )
        except Exception as exc:
            marker_error = exc
        self.store.request_halt(reason, flatten=True)
        self.store.record_event(
            "CRITICAL",
            "UNAUTHORIZED_ACCOUNT_POSITION",
            "A position outside the authenticated strategy universe appeared during "
            "dedicated-account execution; routine mutation was stopped.",
            {
                "stage": stage,
                "positions": self._position_summary(positions),
            },
        )
        if marker_error is not None:
            raise RuntimeError(
                "Unauthorized account exposure was latched in authenticated state, but "
                "the independent flatten marker could not be persisted."
            ) from marker_error

    @staticmethod
    def _position_quantities_changed(
        before: dict[str, PositionSnapshot],
        after: dict[str, PositionSnapshot],
    ) -> bool:
        symbols = set(before) | set(after)
        return any(
            not math.isclose(
                float(before[symbol].qty) if symbol in before else 0.0,
                float(after[symbol].qty) if symbol in after else 0.0,
                abs_tol=1e-8,
            )
            for symbol in symbols
        )

    @staticmethod
    def _position_summary(positions: dict[str, PositionSnapshot]) -> dict[str, float]:
        return {
            symbol: float(position.qty)
            for symbol, position in sorted(positions.items())
            if abs(float(position.qty)) > 1e-10
        }

    def _scoped_routine_quantities(
        self,
        plan: TargetPlan,
        positions: Mapping[str, PositionSnapshot],
        expected_symbols: Iterable[str] = (),
    ) -> dict[str, float]:
        scope = set(positions) if self.config.dedicated_account else set(
            self._managed_symbols(plan)
        )
        scope.update(str(symbol) for symbol in expected_symbols)
        quantities: dict[str, float] = {}
        for symbol in sorted(scope):
            position = positions.get(symbol)
            quantity = float(position.qty) if position is not None else 0.0
            if not math.isfinite(quantity):
                raise RuntimeError(
                    f"Routine broker reconciliation returned non-finite quantity for {symbol}."
                )
            if abs(quantity) > 1e-10:
                quantities[symbol] = quantity
        return quantities

    @staticmethod
    def _quantity_snapshots_equal(
        left: Mapping[str, float], right: Mapping[str, float]
    ) -> bool:
        symbols = set(left) | set(right)
        return all(
            math.isclose(
                float(left.get(symbol, 0.0)),
                float(right.get(symbol, 0.0)),
                abs_tol=max(
                    1e-8,
                    abs(float(left.get(symbol, 0.0))) * 1e-8,
                    abs(float(right.get(symbol, 0.0))) * 1e-8,
                ),
            )
            for symbol in symbols
        )

    def _await_stable_routine_broker_state(
        self,
        plan: TargetPlan,
        *,
        expected_quantities: Mapping[str, float] | None = None,
        context: str,
        routine_deadline: datetime | None = None,
    ) -> dict[str, PositionSnapshot]:
        """Require two clean broker snapshots before another mutation or completion.

        A terminal order response is not sufficient when the position and open-order
        endpoints are eventually consistent. The next child (and final plan status) is
        authorized only after the reported fill is visible twice with no live order.
        """

        expected = {
            str(symbol): float(quantity)
            for symbol, quantity in (expected_quantities or {}).items()
        }
        if any(not math.isfinite(quantity) for quantity in expected.values()):
            raise RuntimeError("Routine broker reflection expectation is non-finite.")
        if (
            routine_deadline is None
            and self._governed_execution_enabled()
            and self._active_routine_execution_date is not None
        ):
            routine_deadline = self._governed_benchmark_deadline(
                self._active_routine_execution_date
            )
        deadline = time_module.monotonic() + max(
            float(self.config.order_fill_timeout_seconds), 0.0
        )
        prior_quantities: dict[str, float] | None = None
        attempts = 0
        last_reason = "broker state was not sampled"
        while True:
            if routine_deadline is not None and self._routine_deadline_reached(
                routine_deadline
            ):
                raise RuntimeError(
                    f"{context} crossed the hard 09:35 benchmark deadline before "
                    "terminal broker state was stably reflected."
                )
            positions = self.broker.get_positions()
            self._mark_progress()
            open_orders = self.broker.list_open_orders(None)
            self._mark_progress()
            quantities = self._scoped_routine_quantities(
                plan, positions, expected.keys()
            )
            attempts += 1

            mismatches: list[str] = []
            for symbol, required in expected.items():
                actual = float(
                    positions.get(
                        symbol, PositionSnapshot(symbol, 0.0, 0.0, 0.0)
                    ).qty
                )
                tolerance = max(1e-8, abs(required) * 1e-8, abs(actual) * 1e-8)
                if not math.isfinite(actual) or not math.isclose(
                    actual, required, abs_tol=tolerance
                ):
                    mismatches.append(f"{symbol}={actual:.12g}, expected={required:.12g}")

            if open_orders:
                last_reason = "open orders remained: " + ", ".join(
                    order.client_order_id for order in open_orders
                )
                prior_quantities = None
            elif mismatches:
                last_reason = "terminal fill was not reflected: " + "; ".join(mismatches)
                prior_quantities = None
            elif prior_quantities is not None and self._quantity_snapshots_equal(
                prior_quantities, quantities
            ):
                if routine_deadline is not None and self._routine_deadline_reached(
                    routine_deadline
                ):
                    raise RuntimeError(
                        f"{context} crossed the hard 09:35 benchmark deadline while "
                        "confirming terminal broker state."
                    )
                return positions
            else:
                last_reason = "only one clean position/order snapshot was observed"
                prior_quantities = quantities

            timed_out = time_module.monotonic() >= deadline
            if (timed_out and attempts >= 2) or (
                self.config.broker == "simulated" and attempts >= 4
            ):
                raise RuntimeError(
                    f"{context} could not establish stable terminal broker state: "
                    + last_reason
                )
            if self.config.broker != "simulated":
                time_module.sleep(
                    min(max(float(self.config.order_poll_seconds), 0.01), 1.0)
                )

    def _target_quantities(
        self,
        plan: TargetPlan,
        account: AccountSnapshot,
        prices: dict[str, float],
        asset_info: dict[str, AssetInfo],
    ) -> dict[str, float]:
        symbols = self._plan_symbols(plan)
        targets: dict[str, float] = {}
        for symbol in symbols:
            price = float(prices.get(symbol, 0.0))
            if price <= 0:
                raise RuntimeError(f"No valid execution price for {symbol}.")
            info = asset_info.get(symbol)
            weight = float(plan.target_weights.get(symbol, 0.0))
            if abs(weight) > 0 and (info is None or not info.tradable):
                raise RuntimeError(f"{symbol} is not tradable; refusing to distort target neutrality.")
            if weight < 0 and (
                not self.config.allow_shorting
                or info is None
                or not self._short_eligible(info)
            ):
                raise RuntimeError(f"{symbol} is not eligible for the planned short position.")
            raw_qty = weight * account.equity / price
            if self.config.whole_shares_only or (info is not None and not info.fractionable):
                qty = float(math.trunc(raw_qty))
            else:
                qty = round(raw_qty, 6)
            if abs(qty * price) < self.config.min_trade_notional:
                qty = 0.0
            targets[symbol] = qty
        return targets

    def _build_order_intents(
        self,
        plan: TargetPlan,
        positions: dict[str, PositionSnapshot],
        target_quantities: dict[str, float],
        prices: dict[str, float],
        *,
        current_account_equity: float | None = None,
    ) -> tuple[list[OrderIntent], list[OrderIntent]]:
        reductions: list[OrderIntent] = []
        increases: list[OrderIntent] = []
        for symbol in sorted(target_quantities):
            current = float(positions.get(symbol).qty if symbol in positions else 0.0)
            target = float(target_quantities[symbol])
            price = float(prices[symbol])
            if not math.isfinite(current) or not math.isfinite(target):
                raise RuntimeError(f"Non-finite execution quantity for {symbol}.")
            if not math.isfinite(price) or price <= 0.0:
                raise RuntimeError(f"Missing or invalid execution price for {symbol}.")
            if math.isclose(current, target, abs_tol=1e-8):
                continue

            legs: list[tuple[OrderPhase, OrderSide, float]] = []
            if current * target < 0:
                legs.append(
                    (OrderPhase.REDUCE, OrderSide.SELL if current > 0 else OrderSide.BUY, abs(current))
                )
                legs.append(
                    (OrderPhase.INCREASE, OrderSide.BUY if target > 0 else OrderSide.SELL, abs(target))
                )
            else:
                delta = target - current
                phase = OrderPhase.REDUCE if abs(target) < abs(current) else OrderPhase.INCREASE
                side = OrderSide.BUY if delta > 0 else OrderSide.SELL
                legs.append((phase, side, abs(delta)))

            for phase, side, qty in legs:
                notional = qty * price
                # Never suppress a risk-reducing order. Small increases can be ignored.
                if phase == OrderPhase.INCREASE and notional < self.config.min_trade_notional:
                    continue
                planned_equity = float(plan.metadata.get("account_equity", 0.0) or 0.0)
                account_equity = (
                    float(current_account_equity)
                    if current_account_equity is not None
                    else planned_equity
                )
                if not math.isfinite(account_equity) or account_equity <= 0.0:
                    raise RuntimeError(
                        "Current account equity is required for child-order risk sizing."
                    )
                max_child_notional = (
                    self.config.max_single_order_notional_pct * account_equity
                )
                chunk_quantities = [qty]
                if notional > max_child_notional + 1e-8:
                    if self.config.whole_shares_only:
                        max_chunk_qty = float(math.floor(max_child_notional / price))
                        if max_chunk_qty < 1.0:
                            if phase == OrderPhase.INCREASE:
                                raise RuntimeError(
                                    f"One share of {symbol} exceeds the current-account child "
                                    "order notional cap; the increase was blocked."
                                )
                            # A risk reduction is never suppressed solely because one
                            # indivisible share exceeds the increase-order cap.
                            max_chunk_qty = 1.0
                    else:
                        max_chunk_qty = max_child_notional / price
                    chunk_quantities = []
                    remaining_qty = qty
                    while remaining_qty > 1e-10:
                        if len(chunk_quantities) >= self.config.max_orders_per_cycle:
                            raise RuntimeError(
                                f"{symbol} alone requires more than the configured child-order "
                                "budget after current-equity sizing."
                            )
                        child_qty = min(remaining_qty, max_chunk_qty)
                        if self.config.whole_shares_only:
                            child_qty = float(math.floor(child_qty))
                            if child_qty < 1:
                                child_qty = remaining_qty
                        chunk_quantities.append(child_qty)
                        remaining_qty -= child_qty

                for ordinal, chunk_qty in enumerate(chunk_quantities):
                    client_id = self._intent_client_order_id(
                        plan.plan_id,
                        phase,
                        symbol,
                        current_qty=current,
                        target_qty=target,
                        side=side,
                        qty=chunk_qty,
                        ordinal=ordinal,
                    )
                    intent = OrderIntent(
                        symbol=symbol,
                        qty=chunk_qty,
                        side=side,
                        phase=phase,
                        current_qty=current,
                        target_qty=target,
                        estimated_price=price,
                        estimated_notional=chunk_qty * price,
                        client_order_id=client_id,
                    )
                    (reductions if phase == OrderPhase.REDUCE else increases).append(intent)
        return reductions, increases

    def _validate_transient_child_exposure(
        self,
        plan: TargetPlan,
        positions: dict[str, PositionSnapshot],
        prices: Mapping[str, float],
        *,
        account_equity: float,
        symbol: str,
        side: OrderSide,
        qty: float,
        target_qty: float,
        phase: OrderPhase,
        expected_current_qty: float | None = None,
    ) -> dict[str, float]:
        """Validate the exact post-child portfolio against fixed transient limits."""

        equity = float(account_equity)
        if not math.isfinite(equity) or equity <= 0.0:
            raise RuntimeError("Transient child exposure requires positive finite equity.")
        child_symbol = str(symbol).upper()
        authorized_symbols = set(self._plan_symbols(plan))
        if child_symbol not in authorized_symbols:
            raise RuntimeError(
                f"Routine child {child_symbol} is outside the authenticated plan universe."
            )
        if self.config.dedicated_account:
            foreign = sorted(
                str(position_symbol).upper()
                for position_symbol, position in positions.items()
                if str(position_symbol).upper() not in authorized_symbols
                and (
                    not math.isfinite(float(position.qty))
                    or abs(float(position.qty)) > 1e-10
                )
            )
            if foreign:
                raise RuntimeError(
                    "Dedicated-account positions are outside the authenticated plan: "
                    + ", ".join(foreign)
                )

        current_position = positions.get(child_symbol)
        current_qty = float(current_position.qty) if current_position is not None else 0.0
        projected_child_qty = self._validate_child_target_progress(
            current_qty=current_qty,
            target_qty=float(target_qty),
            side=side,
            qty=float(qty),
            phase=phase,
            expected_current_qty=expected_current_qty,
        )

        beta_map = plan.metadata.get("asset_beta")
        gross = 0.0
        net = 0.0
        beta_exposure = 0.0
        maximum_position = 0.0
        symbols = set(authorized_symbols) | {child_symbol}
        for position_symbol, position in positions.items():
            normalized = str(position_symbol).upper()
            if self.config.dedicated_account or normalized in authorized_symbols:
                symbols.add(normalized)
        for position_symbol in sorted(symbols):
            if position_symbol == child_symbol:
                position_qty = projected_child_qty
            else:
                position = positions.get(position_symbol)
                position_qty = float(position.qty) if position is not None else 0.0
            if not math.isfinite(position_qty):
                raise RuntimeError("Transient child exposure contains a non-finite quantity.")
            if abs(position_qty) <= 1e-10:
                continue
            try:
                price = float(prices[position_symbol])
            except (KeyError, TypeError, ValueError) as exc:
                raise RuntimeError(
                    f"Transient child exposure lacks a fresh price for {position_symbol}."
                ) from exc
            if not math.isfinite(price) or price <= 0.0:
                raise RuntimeError(
                    f"Transient child exposure has an invalid price for {position_symbol}."
                )
            weight = position_qty * price / equity
            gross += abs(weight)
            net += weight
            maximum_position = max(maximum_position, abs(weight))
            if self.config.strategy.portfolio.beta_neutral:
                try:
                    beta = float(beta_map[position_symbol]) if isinstance(beta_map, dict) else math.nan
                except (KeyError, TypeError, ValueError):
                    beta = math.nan
                if not math.isfinite(beta):
                    raise RuntimeError(
                        f"Transient beta exposure lacks authenticated beta for {position_symbol}."
                    )
                beta_exposure += weight * beta

        gross_limit = (
            self.config.strategy.portfolio.max_gross_leverage
            + self.config.actual_gross_exposure_tolerance
        )
        position_limit = (
            self.config.strategy.portfolio.max_position_weight
            + self.config.actual_position_weight_tolerance
        )
        if gross > gross_limit + 1e-8:
            raise RuntimeError(
                f"Transient projected gross exposure {gross:.6f} exceeds {gross_limit:.6f}."
            )
        if maximum_position > position_limit + 1e-8:
            raise RuntimeError(
                "Transient projected position concentration exceeds the fixed live limit."
            )
        if (
            self.config.strategy.portfolio.dollar_neutral
            and abs(net) > self.config.actual_net_exposure_limit + 1e-8
        ):
            raise RuntimeError(
                f"Transient projected dollar-net exposure {net:.6f} exceeds "
                f"{self.config.actual_net_exposure_limit:.6f}."
            )
        if (
            self.config.strategy.portfolio.beta_neutral
            and abs(beta_exposure) > self.config.actual_beta_exposure_limit + 1e-8
        ):
            raise RuntimeError(
                f"Transient projected beta exposure {beta_exposure:.6f} exceeds "
                f"{self.config.actual_beta_exposure_limit:.6f}."
            )
        return {
            "gross_exposure": float(gross),
            "net_exposure": float(net),
            "beta_exposure": float(beta_exposure),
            "maximum_position_weight": float(maximum_position),
            "projected_child_qty": float(projected_child_qty),
        }

    def _order_intents_for_transient_limits(
        self,
        plan: TargetPlan,
        intents: Iterable[OrderIntent],
        positions: dict[str, PositionSnapshot],
        prices: Mapping[str, float],
        *,
        account_equity: float,
    ) -> list[OrderIntent]:
        """Choose and prove a feasible low-imbalance child path before mutation."""

        remaining = list(intents)
        if not remaining:
            return []
        # A locally best child can strand the final few unequal chunks even though an
        # alternate earlier ordering is feasible.  The simulated portfolio after a set
        # of children is order-independent, so failed remaining-index sets form a compact
        # memoization key for deterministic bounded backtracking.
        if len(remaining) > 500:
            raise RuntimeError(
                "Transient child path exceeds the bounded exact-ordering proof budget."
            )
        failed_states: set[tuple[int, ...]] = set()
        examined_states = 0
        maximum_states = max(25_000, min(250_000, len(remaining) * len(remaining) * 500))
        root_failures: list[str] = []

        def search(
            remaining_indices: tuple[int, ...],
            simulated: dict[str, PositionSnapshot],
        ) -> list[int] | None:
            nonlocal examined_states, root_failures
            if not remaining_indices:
                return []
            if remaining_indices in failed_states:
                return None
            examined_states += 1
            if examined_states > maximum_states:
                return None
            feasible: list[
                tuple[tuple[float, float, float, float, str], int, dict[str, float]]
            ] = []
            failures: list[str] = []
            for intent_index in remaining_indices:
                intent = remaining[intent_index]
                try:
                    metrics = self._validate_transient_child_exposure(
                        plan,
                        simulated,
                        prices,
                        account_equity=account_equity,
                        symbol=intent.symbol,
                        side=intent.side,
                        qty=float(intent.qty),
                        target_qty=float(intent.target_qty),
                        phase=intent.phase,
                    )
                except RuntimeError as exc:
                    failures.append(f"{intent.client_order_id}:{exc}")
                    continue
                net_scale = max(self.config.actual_net_exposure_limit, 1e-12)
                beta_scale = max(self.config.actual_beta_exposure_limit, 1e-12)
                score = (
                    max(
                        abs(metrics["net_exposure"]) / net_scale,
                        abs(metrics["beta_exposure"]) / beta_scale,
                    ),
                    abs(metrics["net_exposure"]),
                    abs(metrics["beta_exposure"]),
                    metrics["gross_exposure"],
                    intent.client_order_id,
                )
                feasible.append((score, intent_index, metrics))
            if len(remaining_indices) == len(remaining):
                root_failures = failures
            for _, chosen_index, metrics in sorted(feasible, key=lambda item: item[0]):
                chosen = remaining[chosen_index]
                projected_qty = metrics["projected_child_qty"]
                price = float(prices[chosen.symbol])
                next_simulated = dict(simulated)
                next_simulated[chosen.symbol] = PositionSnapshot(
                    symbol=chosen.symbol,
                    qty=projected_qty,
                    market_value=projected_qty * price,
                    current_price=price,
                )
                tail = search(
                    tuple(index for index in remaining_indices if index != chosen_index),
                    next_simulated,
                )
                if tail is not None:
                    return [chosen_index, *tail]
            failed_states.add(remaining_indices)
            return None

        path = search(tuple(range(len(remaining))), dict(positions))
        if path is None:
            detail = "; ".join(root_failures[:3])
            suffix = (
                " exact-ordering search budget exhausted."
                if examined_states > maximum_states
                else ""
            )
            raise RuntimeError(
                "No child ordering satisfies fixed transient gross, dollar-net, and "
                f"beta limits before mutation.{suffix} {detail}"
            )
        return [remaining[index] for index in path]

    def _validate_projected_portfolio(
        self,
        plan: TargetPlan,
        target_quantities: dict[str, float],
        prices: dict[str, float],
        account: AccountSnapshot,
    ) -> None:
        if not math.isfinite(float(account.equity)) or account.equity <= 0:
            raise RuntimeError("Account equity is non-positive or non-finite.")
        weights: dict[str, float] = {}
        for symbol, qty in target_quantities.items():
            quantity = float(qty)
            price = float(prices.get(symbol, 0.0))
            if not math.isfinite(quantity):
                raise RuntimeError(f"Projected quantity for {symbol} is non-finite.")
            if not math.isfinite(price) or price <= 0.0:
                raise RuntimeError(f"Projected price for {symbol} is missing or invalid.")
            weights[symbol] = quantity * price / account.equity
        gross = sum(abs(weight) for weight in weights.values())
        net = sum(weights.values())
        max_position = max((abs(weight) for weight in weights.values()), default=0.0)
        if gross > self.config.strategy.portfolio.max_gross_leverage + 0.02:
            raise RuntimeError(f"Rounded target gross {gross:.4f} exceeds configured limit.")
        if max_position > self.config.strategy.portfolio.max_position_weight + 0.01:
            raise RuntimeError(f"Rounded target position {max_position:.4f} exceeds configured cap.")
        if self.config.strategy.portfolio.dollar_neutral and abs(net) > 0.05:
            raise RuntimeError(f"Rounded target net exposure {net:.4f} exceeds ±5% safety tolerance.")
        planned_gross = float(plan.metadata.get("gross_weight", plan.desired_gross))
        if gross > planned_gross + 0.05:
            raise RuntimeError("Rounded target unexpectedly increases gross risk above the plan.")
        if self.config.strategy.portfolio.beta_neutral:
            beta_map = plan.metadata.get("asset_beta")
            missing_or_invalid: list[str] = []
            beta_exposure = 0.0
            for symbol, weight in weights.items():
                if abs(weight) <= 1e-12:
                    continue
                try:
                    beta = float(beta_map[symbol]) if isinstance(beta_map, dict) else math.nan
                except (KeyError, TypeError, ValueError):
                    beta = math.nan
                if not math.isfinite(beta):
                    missing_or_invalid.append(symbol)
                    continue
                beta_exposure += weight * beta
            if missing_or_invalid:
                raise RuntimeError(
                    "Projected beta exposure cannot be validated; missing/invalid beta for: "
                    + ", ".join(sorted(missing_or_invalid))
                )
            if abs(beta_exposure) > self.config.actual_beta_exposure_limit:
                raise RuntimeError(
                    f"Rounded target beta exposure {beta_exposure:.4f} exceeds "
                    f"the safety limit {self.config.actual_beta_exposure_limit:.4f}."
                )

    def _routine_deadline_reached(self, deadline: datetime) -> bool:
        if deadline.tzinfo is None or deadline.utcoffset() is None:
            raise RuntimeError("Routine execution deadline must be timezone-aware.")
        deadline_utc = deadline.astimezone(timezone.utc)
        if datetime.now(timezone.utc) >= deadline_utc:
            return True
        clock = self.broker.get_market_clock()
        if clock.timestamp.tzinfo is None or clock.timestamp.utcoffset() is None:
            return True
        return clock.timestamp.astimezone(timezone.utc) >= deadline_utc

    def _routine_deadline_remaining_seconds(self, deadline: datetime) -> float:
        """Return the conservative wall/broker time remaining before 09:35."""

        if deadline.tzinfo is None or deadline.utcoffset() is None:
            return 0.0
        deadline_utc = deadline.astimezone(timezone.utc)
        wall_remaining = (
            deadline_utc - datetime.now(timezone.utc)
        ).total_seconds()
        if wall_remaining <= 0.0:
            return 0.0
        try:
            clock = self.broker.get_market_clock()
        except Exception:
            return 0.0
        if clock.timestamp.tzinfo is None or clock.timestamp.utcoffset() is None:
            return 0.0
        broker_remaining = (
            deadline_utc - clock.timestamp.astimezone(timezone.utc)
        ).total_seconds()
        return max(min(wall_remaining, broker_remaining), 0.0)

    def _latch_routine_deadline_failure(
        self,
        reason: str,
        receipts: Iterable[OrderReceipt] = (),
    ) -> None:
        """Persist an incident when order terminality cannot be proven by 09:35."""

        marker_error: Exception | None = None
        try:
            merge_control_marker(
                self.config.kill_switch_path,
                reason,
                flatten=True,
            )
        except Exception as exc:
            marker_error = exc
        self._best_effort_emergency_store("request_halt", reason, flatten=True)
        self._best_effort_emergency_store(
            "record_event",
            "CRITICAL",
            "ROUTINE_DEADLINE_TERMINALITY_UNPROVEN",
            reason,
            {
                "orders": [
                    {
                        "client_order_id": receipt.client_order_id,
                        "broker_order_id": receipt.broker_order_id,
                        "status": receipt.status,
                    }
                    for receipt in receipts
                ],
                "control_marker_error": (
                    type(marker_error).__name__ if marker_error is not None else ""
                ),
            },
        )

    def _submit_and_wait(
        self,
        plan: TargetPlan,
        intents: Iterable[OrderIntent],
    ) -> list[OrderReceipt]:
        receipts: list[OrderReceipt] = []
        intent_batch = list(intents)
        routine_deadline: datetime | None = None
        if self._governed_execution_enabled():
            intended_session = self._active_routine_execution_date
            if intended_session is None:
                raise RuntimeError(
                    "Governed routine submission has no active authenticated session."
                )
            routine_deadline = self._governed_benchmark_deadline(intended_session)
        for original_intent in intent_batch:
            if routine_deadline is not None:
                child_clock = self.broker.get_market_clock()
                self._require_governed_execution_window(
                    child_clock,
                    intended_session=self._active_routine_execution_date,
                    context="Routine child precheck",
                )
                if self._routine_deadline_reached(routine_deadline):
                    raise RuntimeError(
                        "Routine child submission reached the hard 09:35 benchmark deadline."
                    )
            # Every child receives its own broker boundary. This catches manual fills
            # and concurrently opened orders after the phase-level reconciliation but
            # before a stale quantity can cross zero or overshoot the plan target.
            current_positions = self.broker.get_positions()
            account_open_orders = self.broker.list_open_orders(None)
            if self.config.dedicated_account:
                foreign_positions = self._foreign_dedicated_positions(
                    plan,
                    current_positions,
                )
                if foreign_positions:
                    self._persist_foreign_position_halt(
                        foreign_positions,
                        stage="immediate_pre_child",
                    )
                    raise RuntimeError(
                        "Routine child blocked by an unauthorized dedicated-account position."
                    )
            foreign_orders = self._foreign_dedicated_orders(account_open_orders)
            if foreign_orders:
                self._persist_foreign_order_halt(
                    "unauthorized_dedicated_account_order",
                    foreign_orders,
                    stage="immediate_pre_child",
                )
                raise RuntimeError(
                    "Routine child blocked by unauthorized dedicated-account activity."
                )
            conflicting_orders = list(account_open_orders)
            if conflicting_orders:
                raise RuntimeError(
                    "Routine child blocked because an account-wide open order can change "
                    f"{original_intent.symbol} before submission."
                )

            current_qty = float(
                current_positions.get(
                    original_intent.symbol,
                    PositionSnapshot(original_intent.symbol, 0.0, 0.0, 0.0),
                ).qty
            )
            target_qty = float(original_intent.target_qty)
            if not math.isfinite(current_qty) or not math.isfinite(target_qty):
                raise RuntimeError("Routine child position reconciliation is non-finite.")
            tolerance = max(1e-8, abs(current_qty) * 1e-8, abs(target_qty) * 1e-8)
            allowed_qty = 0.0
            if original_intent.phase == OrderPhase.REDUCE:
                if original_intent.side == OrderSide.SELL and current_qty > tolerance:
                    distance = current_qty if target_qty < 0.0 else max(
                        current_qty - target_qty, 0.0
                    )
                    allowed_qty = min(
                        float(original_intent.qty), current_qty, distance
                    )
                elif original_intent.side == OrderSide.BUY and current_qty < -tolerance:
                    distance = -current_qty if target_qty > 0.0 else max(
                        target_qty - current_qty, 0.0
                    )
                    allowed_qty = min(
                        float(original_intent.qty), -current_qty, distance
                    )
            else:
                # An increase may approach, but never pass, its current target. If a
                # reversal's reducing leg is no longer flat, defer rather than crossing
                # zero with an order that was classified under an earlier snapshot.
                if (
                    current_qty > tolerance and target_qty < -tolerance
                ) or (
                    current_qty < -tolerance and target_qty > tolerance
                ):
                    allowed_qty = 0.0
                else:
                    remaining = target_qty - current_qty
                    if (
                        original_intent.side == OrderSide.BUY
                        and remaining > tolerance
                    ) or (
                        original_intent.side == OrderSide.SELL
                        and remaining < -tolerance
                    ):
                        allowed_qty = min(
                            float(original_intent.qty), abs(remaining)
                        )
            if allowed_qty <= tolerance:
                continue

            intent = original_intent
            if not math.isclose(
                current_qty, float(intent.current_qty), abs_tol=tolerance
            ) or not math.isclose(
                allowed_qty, float(intent.qty), abs_tol=tolerance
            ):
                refreshed_client_id = self._intent_client_order_id(
                    plan.plan_id,
                    intent.phase,
                    intent.symbol,
                    current_qty=current_qty,
                    target_qty=target_qty,
                    side=intent.side,
                    qty=allowed_qty,
                    ordinal=0,
                )
                intent = replace(
                    intent,
                    qty=allowed_qty,
                    current_qty=current_qty,
                    estimated_notional=allowed_qty * float(intent.estimated_price),
                    client_order_id=refreshed_client_id,
                )

            if routine_deadline is not None:
                bounded_account_reader = getattr(
                    self.broker,
                    "get_account_for_routine_authorization",
                    None,
                )
                current_account = (
                    bounded_account_reader()
                    if callable(bounded_account_reader)
                    else self.broker.get_account()
                )
            else:
                current_account = self.broker.get_account()
            halt = self.store.halt_state()
            if halt.get("active") or self.config.kill_switch_path.exists():
                raise RuntimeError(
                    "Routine child interrupted by a concurrent halt or kill switch."
                )
            if intent.phase == OrderPhase.INCREASE:
                # A multi-child phase can span multiple fills and material account
                # changes. Refresh the authoritative account and persisted drawdown/loss
                # controls before *each* risk-increasing child, then recheck current
                # buying power and the per-child equity cap. The broker adapter still
                # performs its final approval/account-identity callback after its quote
                # read, immediately before the REST mutation.
                current_decision = self._evaluate_risk(
                    current_account,
                    current_account.timestamp,
                )
                if (
                    not current_decision.allow_new_risk
                    or current_decision.flatten
                    or current_decision.halt
                ):
                    raise RuntimeError(
                        "Increase phase interrupted by refreshed account risk control: "
                        f"{current_decision.reason}"
                    )
                child_notional = float(intent.estimated_notional)
                buffered_buying_power = max(
                    float(current_account.buying_power)
                    * (1.0 - self.config.buying_power_buffer),
                    0.0,
                )
                if child_notional > buffered_buying_power + 1e-6:
                    raise RuntimeError(
                        f"Increase child {intent.client_order_id} notional "
                        f"{child_notional:,.2f} exceeds refreshed buffered buying power "
                        f"{buffered_buying_power:,.2f}."
                    )
                refreshed_child_cap = (
                    self.config.max_single_order_notional_pct
                    * float(current_account.equity)
                )
                if child_notional > refreshed_child_cap + 1e-6:
                    raise RuntimeError(
                        f"Increase child {intent.client_order_id} notional "
                        f"{child_notional:,.2f} exceeds the refreshed current-equity "
                        f"child cap {refreshed_child_cap:,.2f}."
                    )
            if routine_deadline is not None:
                final_child_clock = self.broker.get_market_clock()
                self._require_governed_execution_window(
                    final_child_clock,
                    intended_session=self._active_routine_execution_date,
                    context="Routine child final engine boundary",
                )
                if self._routine_deadline_reached(routine_deadline):
                    raise RuntimeError(
                        "Routine child submission reached the hard 09:35 benchmark deadline."
                    )
            child_authorization: RoutineChildAuthorization | None = None
            if routine_deadline is not None:
                self._validate_child_target_progress(
                    current_qty=float(intent.current_qty),
                    target_qty=float(intent.target_qty),
                    side=intent.side,
                    qty=float(intent.qty),
                    phase=intent.phase,
                    expected_current_qty=float(intent.current_qty),
                )
                child_authorization = self._activate_routine_child_authorization(
                    plan,
                    intent,
                )
            try:
                receipt = self.broker.submit_market_order(
                    symbol=intent.symbol,
                    qty=intent.qty,
                    side=intent.side,
                    client_order_id=intent.client_order_id,
                )
            finally:
                if child_authorization is not None:
                    self._clear_routine_child_authorization(child_authorization)
            self._validate_order_receipt(
                receipt,
                symbol=intent.symbol,
                qty=intent.qty,
                side=intent.side,
                client_order_id=intent.client_order_id,
            )
            self.store.record_order(plan.plan_id, intent.phase.value, receipt)
            self._mark_progress()
            terminal = self._wait_for_receipts(
                plan.plan_id,
                intent.phase,
                [receipt],
                routine_deadline=routine_deadline,
            )[0]
            signed_filled = (
                float(terminal.filled_qty)
                if intent.side == OrderSide.BUY
                else -float(terminal.filled_qty)
            )
            expected_quantity = float(intent.current_qty) + signed_filled
            self._await_stable_routine_broker_state(
                plan,
                expected_quantities={intent.symbol: expected_quantity},
                context=f"Routine child {intent.client_order_id}",
                routine_deadline=routine_deadline,
            )
            receipts.append(terminal)
        return receipts

    def _wait_for_receipts(
        self,
        plan_id: str | None,
        default_phase: OrderPhase | None,
        receipts: list[OrderReceipt],
        *,
        require_filled: bool = True,
        best_effort_store: bool = False,
        routine_deadline: datetime | None = None,
    ) -> list[OrderReceipt]:
        if not receipts:
            return []
        now_monotonic = time_module.monotonic()
        deadline = now_monotonic + self.config.order_fill_timeout_seconds
        cancellation_reserve = max(float(self.config.order_poll_seconds) * 2.0, 1.0)
        initial_remaining = math.inf
        if routine_deadline is not None:
            initial_remaining = self._routine_deadline_remaining_seconds(routine_deadline)
            deadline = min(deadline, now_monotonic + initial_remaining)
        latest = {receipt.broker_order_id: receipt for receipt in receipts}
        if (
            routine_deadline is not None
            and initial_remaining <= 0.0
            and all(
                receipt.status.lower() in TERMINAL_ORDER_STATUSES
                for receipt in latest.values()
            )
        ):
            self._latch_routine_deadline_failure(
                "routine_terminal_receipt_observed_after_deadline",
                latest.values(),
            )
            raise RuntimeError(
                "Routine terminal receipt was observed at or after 09:35; "
                "pre-deadline terminality was not proven."
            )
        benchmark_deadline_reached = False
        while time_module.monotonic() < deadline:
            if routine_deadline is not None:
                remaining_to_benchmark = self._routine_deadline_remaining_seconds(
                    routine_deadline
                )
                if remaining_to_benchmark <= 0.0:
                    benchmark_deadline_reached = True
                    break
                if (
                    remaining_to_benchmark <= cancellation_reserve
                    and any(
                        receipt.status.lower() not in TERMINAL_ORDER_STATUSES
                        for receipt in latest.values()
                    )
                ):
                    break
            if plan_id is not None and self.config.kill_switch_path.exists():
                canceled: list[OrderReceipt] = []
                for order_id, prior in list(latest.items()):
                    current = prior
                    if current.status.lower() not in TERMINAL_ORDER_STATUSES:
                        cancel_timeout = float(self.config.order_fill_timeout_seconds)
                        if routine_deadline is not None:
                            cancel_timeout = min(
                                cancel_timeout,
                                self._routine_deadline_remaining_seconds(routine_deadline),
                            )
                        try:
                            current = self.broker.cancel_order_and_wait(
                                order_id,
                                timeout_seconds=max(cancel_timeout, 0.0),
                                poll_seconds=self.config.order_poll_seconds,
                            )
                        except Exception as exc:
                            if routine_deadline is not None:
                                self._latch_routine_deadline_failure(
                                    "routine_kill_cancellation_terminality_unproven",
                                    latest.values(),
                                )
                            raise RuntimeError(
                                "Kill-switch cancellation terminality could not be proven."
                            ) from exc
                        if (
                            routine_deadline is not None
                            and self._routine_deadline_remaining_seconds(routine_deadline)
                            <= 0.0
                        ):
                            self._latch_routine_deadline_failure(
                                "routine_kill_cancellation_crossed_deadline",
                                [current],
                            )
                            raise RuntimeError(
                                "Kill-switch cancellation returned after 09:35; "
                                "pre-deadline terminality is unproven."
                            )
                        self._mark_progress()
                        self._validate_receipt_transition(prior, current)
                        if best_effort_store:
                            self._best_effort_emergency_store(
                                "record_order",
                                plan_id,
                                default_phase.value if default_phase else "unknown",
                                current,
                            )
                        else:
                            self.store.record_order(
                                plan_id,
                                default_phase.value if default_phase else "unknown",
                                current,
                            )
                    canceled.append(current)
                outcomes = ", ".join(
                    f"{receipt.client_order_id}:{receipt.status}" for receipt in canceled
                )
                raise RuntimeError(
                    "Order wait interrupted by the filesystem kill switch after "
                    f"reconciling active submissions ({outcomes})."
                )
            all_terminal = True
            for order_id, prior in list(latest.items()):
                if prior.status.lower() in TERMINAL_ORDER_STATUSES:
                    continue
                current = self.broker.get_order(order_id)
                self._mark_progress()
                self._validate_receipt_transition(prior, current)
                latest[order_id] = current
                if (
                    routine_deadline is not None
                    and self._routine_deadline_remaining_seconds(routine_deadline)
                    <= 0.0
                ):
                    self._latch_routine_deadline_failure(
                        "routine_order_observation_crossed_deadline",
                        latest.values(),
                    )
                    raise RuntimeError(
                        "Routine order state was observed at or after 09:35; "
                        "pre-deadline terminality was not proven."
                    )
                if best_effort_store:
                    self._best_effort_emergency_store(
                        "record_order",
                        plan_id,
                        default_phase.value if default_phase else "unknown",
                        current,
                    )
                else:
                    self.store.record_order(
                        plan_id,
                        default_phase.value if default_phase else "unknown",
                        current,
                    )
                if current.status.lower() not in TERMINAL_ORDER_STATUSES:
                    all_terminal = False
            if all_terminal:
                break
            sleep_seconds = float(self.config.order_poll_seconds)
            if routine_deadline is not None:
                remaining = self._routine_deadline_remaining_seconds(routine_deadline)
                if remaining <= 0.0:
                    benchmark_deadline_reached = True
                    break
                sleep_seconds = min(
                    sleep_seconds,
                    max(remaining - cancellation_reserve, 0.0),
                )
            time_module.sleep(max(sleep_seconds, 0.0))

        final: list[OrderReceipt] = []
        failures: list[str] = []
        for order_id, prior in latest.items():
            current = prior
            if current.status.lower() not in TERMINAL_ORDER_STATUSES:
                cancel_timeout = float(self.config.order_fill_timeout_seconds)
                if routine_deadline is not None:
                    cancel_timeout = min(
                        cancel_timeout,
                        self._routine_deadline_remaining_seconds(routine_deadline),
                    )
                try:
                    current = self.broker.cancel_order_and_wait(
                        order_id,
                        timeout_seconds=max(cancel_timeout, 0.0),
                        poll_seconds=self.config.order_poll_seconds,
                    )
                except Exception as exc:
                    if routine_deadline is not None:
                        self._latch_routine_deadline_failure(
                            "routine_child_cancellation_terminality_unproven",
                            latest.values(),
                        )
                    raise RuntimeError(
                        "Routine child cancellation terminality could not be proven "
                        "within the remaining 09:35 deadline."
                    ) from exc
                if (
                    routine_deadline is not None
                    and self._routine_deadline_remaining_seconds(routine_deadline)
                    <= 0.0
                ):
                    self._latch_routine_deadline_failure(
                        "routine_child_cancellation_crossed_deadline",
                        [current],
                    )
                    raise RuntimeError(
                        "Routine child cancellation returned at or after 09:35; "
                        "pre-deadline terminality was not proven."
                    )
                self._mark_progress()
                self._validate_receipt_transition(prior, current)
                if best_effort_store:
                    self._best_effort_emergency_store(
                        "record_order",
                        plan_id,
                        default_phase.value if default_phase else "unknown",
                        current,
                    )
                else:
                    self.store.record_order(
                        plan_id,
                        default_phase.value if default_phase else "unknown",
                        current,
                    )
            final.append(current)
            if require_filled and current.status.lower() != "filled":
                failures.append(f"{current.client_order_id}:{current.status}")
        if failures:
            prefix = (
                "Routine 09:35 benchmark deadline reached; one or more children were "
                "canceled or did not fill: "
                if benchmark_deadline_reached
                else "One or more orders did not fill: "
            )
            raise RuntimeError(prefix + ", ".join(failures))
        return final

    @staticmethod
    def _residual_notional(
        targets: dict[str, float],
        positions: dict[str, PositionSnapshot],
        prices: dict[str, float],
    ) -> float:
        residual = 0.0
        for symbol, target in targets.items():
            actual = float(positions.get(symbol).qty if symbol in positions else 0.0)
            if not math.isfinite(actual) or not math.isfinite(float(target)):
                raise RuntimeError(
                    f"Residual exposure for {symbol} contains a non-finite quantity."
                )
            quantity_gap = abs(float(target) - actual)
            if quantity_gap <= 1e-10:
                continue
            price = float(prices.get(symbol, 0.0))
            if not math.isfinite(price) or price <= 0.0:
                raise RuntimeError(
                    f"Residual exposure for {symbol} cannot be valued without a valid price."
                )
            residual += quantity_gap * price
        return residual

    @classmethod
    def _validate_receipt_transition(
        cls,
        previous: OrderReceipt,
        current: OrderReceipt,
    ) -> None:
        """Prove a polled/canceled receipt still describes the submitted order."""

        if current.broker_order_id != previous.broker_order_id:
            raise RuntimeError("Broker order identity changed during reconciliation.")
        cls._validate_order_receipt(
            current,
            symbol=previous.symbol,
            qty=previous.qty,
            side=OrderSide(previous.side.lower()),
            client_order_id=previous.client_order_id,
        )
        filled_qty = float(current.filled_qty)
        previous_filled_qty = float(previous.filled_qty)
        tolerance = max(1e-8, abs(float(current.qty)) * 1e-8)
        if (
            not math.isfinite(filled_qty)
            or filled_qty < -tolerance
            or filled_qty > float(current.qty) + tolerance
            or filled_qty + tolerance < previous_filled_qty
        ):
            raise RuntimeError(
                f"Broker reported an invalid fill progression for {current.client_order_id}."
            )
        if (
            current.status.lower() == "filled"
            and abs(filled_qty - float(current.qty)) > tolerance
        ):
            raise RuntimeError(
                f"Broker marked {current.client_order_id} filled without the full quantity."
            )

    @staticmethod
    def _validate_order_receipt(
        receipt: OrderReceipt,
        *,
        symbol: str,
        qty: float,
        side: OrderSide,
        client_order_id: str,
    ) -> None:
        receipt_qty = float(receipt.qty)
        requested_qty = float(qty)
        tolerance = max(1e-8, abs(requested_qty) * 1e-8)
        same_qty = (
            math.isfinite(receipt_qty)
            and receipt_qty > 0.0
            and abs(receipt_qty - requested_qty) <= tolerance
        )
        if (
            receipt.client_order_id != client_order_id
            or receipt.symbol.upper() != symbol.upper()
            or receipt.side.lower() != side.value
            or not same_qty
        ):
            raise RuntimeError(
                "Broker receipt does not match the submitted economic intent for "
                f"{client_order_id}; execution was stopped."
            )
        filled_qty = float(receipt.filled_qty)
        if (
            not math.isfinite(filled_qty)
            or filled_qty < -tolerance
            or filled_qty > receipt_qty + tolerance
        ):
            raise RuntimeError(
                f"Broker receipt contains an invalid filled quantity for {client_order_id}."
            )
        if (
            receipt.status.lower() == "filled"
            and abs(filled_qty - receipt_qty) > tolerance
        ):
            raise RuntimeError(
                f"Broker marked {client_order_id} filled without the full quantity."
            )

    @staticmethod
    def _intent_client_order_id(
        plan_id: str,
        phase: OrderPhase,
        symbol: str,
        *,
        current_qty: float,
        target_qty: float,
        side: OrderSide,
        qty: float,
        ordinal: int,
    ) -> str:
        """Build a stable ID tied to one exact economic transition.

        Including start/target quantities prevents a partially completed retry from
        accidentally reusing an earlier child order's identity. Repeating an unchanged
        intent after a lost broker response still produces the same idempotency key.
        """

        phase_code = {
            OrderPhase.REDUCE: "r",
            OrderPhase.INCREASE: "i",
            OrderPhase.FLATTEN: "f",
            OrderPhase.DRY_RUN: "d",
        }[phase]
        payload = "|".join(
            [
                str(plan_id),
                phase.value,
                symbol.upper(),
                format(float(current_qty), ".12g"),
                format(float(target_qty), ".12g"),
                side.value,
                format(float(qty), ".12g"),
                str(int(ordinal)),
            ]
        )
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]
        safe_symbol = "".join(ch for ch in symbol if ch.isalnum())[:8]
        return f"qauto-{plan_id[:10]}-{phase_code}-{safe_symbol}-{digest}"[:48]

    @staticmethod
    def _client_order_id(plan_id: str, phase: OrderPhase, symbol: str, index: int) -> str:
        phase_code = {
            OrderPhase.REDUCE: "r",
            OrderPhase.INCREASE: "i",
            OrderPhase.FLATTEN: "f",
            OrderPhase.DRY_RUN: "d",
        }[phase]
        safe_symbol = "".join(ch for ch in symbol if ch.isalnum())[:10]
        return f"qauto-{plan_id[:12]}-{phase_code}-{safe_symbol}-{index}"[:48]
