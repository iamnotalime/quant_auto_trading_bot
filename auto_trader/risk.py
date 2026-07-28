from __future__ import annotations

import math
from datetime import date
from pathlib import Path

from auto_trader.config import BotConfig
from auto_trader.controls import ControlRequest, parse_control_marker
from auto_trader.models import AccountSnapshot, RiskDecision
from auto_trader.store import StateStore


class RiskManager:
    def __init__(self, config: BotConfig, store: StateStore) -> None:
        self.config = config
        self.store = store

    def _kill_switch_request(self) -> ControlRequest | None:
        path = Path(self.config.kill_switch_path)
        if not path.exists():
            return None
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            text = ""
        return parse_control_marker(text)

    def _invalid_state_decision(
        self,
        reason: str,
        message: str,
        details: dict[str, object],
    ) -> RiskDecision:
        # Authentication-anchor damage must produce a liquidation decision even when
        # the compromised authoritative store correctly refuses every further write.
        # The engine's independent emergency journal is the persistence boundary for
        # broker reconciliation in that case.
        try:
            self.store.request_halt(reason, flatten=True)
        except Exception:
            pass
        try:
            self.store.record_event(
                "CRITICAL",
                "INVALID_RISK_STATE",
                message,
                details,
            )
        except Exception:
            pass
        return RiskDecision(False, True, True, reason, 0.0, 0.0, 0.0)

    def _cash_activity_guard(
        self,
        account: AccountSnapshot,
    ) -> RiskDecision | None:
        """Block Alpaca risk accounting when external cash evidence is unsafe.

        The Trading API exposes creation/settlement-date account activities rather than
        a transaction-time cash-flow ledger suitable for rewriting historical returns.
        Therefore the safe automated policy is detection, durable persistence, halt,
        and flattening. A reviewed baseline may be established only while execution is
        disabled; any later difference is deliberately non-resumable in-place.
        """

        if self.config.broker != "alpaca":
            return None
        activities = account.external_cash_activities
        if activities is None:
            return self._invalid_state_decision(
                "cash_activity_evidence_unavailable",
                "Alpaca cash-activity evidence was unavailable; risk baselines were not updated.",
                {"broker_error_type": account.cash_activity_error or "unknown"},
            )
        allowed_types = {"CSD", "CSW", "ACATC", "JNLC"}
        for activity in activities:
            try:
                invalid_activity = (
                    not isinstance(activity.activity_id, str)
                    or not activity.activity_id
                    or activity.activity_type not in allowed_types
                    or not isinstance(activity.activity_date, date)
                    or not math.isfinite(float(activity.net_amount))
                    or (
                        activity.status is not None
                        and not isinstance(activity.status, str)
                    )
                    or (
                        activity.currency is not None
                        and not isinstance(activity.currency, str)
                    )
                )
            except (AttributeError, TypeError, ValueError, OverflowError):
                invalid_activity = True
            if invalid_activity:
                return self._invalid_state_decision(
                    "cash_activity_evidence_invalid",
                    "Alpaca cash-activity evidence contained invalid fields.",
                    {},
                )
        try:
            current = {
                activity.activity_id: activity.to_dict() for activity in activities
            }
        except (AttributeError, TypeError, ValueError, OverflowError) as exc:
            return self._invalid_state_decision(
                "cash_activity_evidence_invalid",
                "Alpaca cash-activity evidence was malformed; risk baselines were not updated.",
                {"error": type(exc).__name__},
            )
        if len(current) != len(activities):
            return self._invalid_state_decision(
                "cash_activity_evidence_invalid",
                "Alpaca cash-activity evidence contained duplicate IDs.",
                {"record_count": len(activities)},
            )
        try:
            monitor = self.store.cash_activity_monitor_state()
        except (TypeError, ValueError, OverflowError) as exc:
            return self._invalid_state_decision(
                "invalid_persisted_cash_activity_state",
                "Persisted cash-activity monitoring state was invalid.",
                {"error": type(exc).__name__},
            )

        if monitor is None:
            if self.config.execution_enabled:
                ids = sorted(current)
                self.store.record_cash_activity_incident(
                    activities,
                    ids,
                    reason="cash_activity_monitor_uninitialized",
                )
                return self._invalid_state_decision(
                    "cash_activity_monitor_uninitialized",
                    "Alpaca execution cannot initialize cash-flow history. Disable "
                    "execution, independently reconcile the account, and establish a "
                    "reviewed baseline before enabling orders.",
                    {"baseline_candidate_count": len(ids)},
                )
            self.store.initialize_cash_activity_monitor(activities)
            self.store.record_event(
                "WARNING",
                "CASH_ACTIVITY_BASELINE_INITIALIZED",
                "Cash-activity monitoring was initialized while execution was disabled.",
                {"baseline_activity_count": len(current)},
            )
            return None

        if (
            not monitor.get("initialized")
            and monitor.get("incident_reason") == "cash_activity_monitor_uninitialized"
            and not self.config.execution_enabled
        ):
            self.store.initialize_cash_activity_monitor(activities)
            self.store.record_event(
                "WARNING",
                "CASH_ACTIVITY_BASELINE_INITIALIZED",
                "Cash-activity monitoring was initialized after execution was disabled "
                "for independent account review.",
                {"baseline_activity_count": len(current)},
            )
            return None

        if not monitor.get("initialized") or monitor.get("incident_active"):
            return self._invalid_state_decision(
                "external_cash_activity_reconciliation_required",
                "Cash-activity monitoring has an unresolved incident. Automatic resume "
                "is blocked because rewriting historical P&L from settlement-date "
                "activities is not defensible.",
                {
                    "incident_activity_count": len(
                        monitor.get("incident_activity_ids", [])
                    )
                },
            )

        previous = monitor["activities"]
        new_ids = sorted(set(current) - set(previous))
        missing_ids = sorted(set(previous) - set(current))
        changed_ids = sorted(
            activity_id
            for activity_id in set(current).intersection(previous)
            if current[activity_id] != previous[activity_id]
        )
        if new_ids or missing_ids or changed_ids:
            incident_ids = sorted(set(new_ids + missing_ids + changed_ids))
            self.store.record_cash_activity_incident(
                activities,
                incident_ids,
                reason="external_cash_activity_changed",
            )
            net_new_cash = sum(
                float(current[activity_id]["net_amount"])
                for activity_id in new_ids
            )
            return self._invalid_state_decision(
                "external_cash_activity_detected",
                "An external Alpaca cash activity was added, removed, or corrected. "
                "Trading P&L baselines were left untouched and the account requires "
                "independent reconciliation.",
                {
                    "new_activity_ids": new_ids,
                    "missing_activity_ids": missing_ids,
                    "changed_activity_ids": changed_ids,
                    "new_net_cash": net_new_cash,
                },
            )
        return None

    def evaluate_and_record(
        self,
        account: AccountSnapshot,
        session_date: date,
        *,
        ignore_operator_controls: bool = False,
    ) -> RiskDecision:
        invalid_fields: list[str] = []
        if not math.isfinite(float(account.equity)) or float(account.equity) <= 0.0:
            invalid_fields.append("equity")
        if not math.isfinite(float(account.cash)):
            # Negative cash can be legitimate in a margin account; non-finite cash cannot.
            invalid_fields.append("cash")
        if (
            not math.isfinite(float(account.buying_power))
            or float(account.buying_power) < 0.0
        ):
            invalid_fields.append("buying_power")
        if (
            not math.isfinite(float(account.last_equity))
            or float(account.last_equity) <= 0.0
        ):
            invalid_fields.append("last_equity")
        if not math.isfinite(float(account.multiplier)) or float(account.multiplier) <= 0.0:
            invalid_fields.append("multiplier")
        if invalid_fields:
            return self._invalid_state_decision(
                "invalid_broker_account_snapshot",
                "Broker account fields failed finite/range validation; risk was halted.",
                {"invalid_fields": invalid_fields},
            )

        cash_activity_decision = self._cash_activity_guard(account)
        if cash_activity_decision is not None:
            return cash_activity_decision

        if self.config.broker == "alpaca":
            try:
                persisted_halt = self.store.halt_state()
            except (TypeError, ValueError, OverflowError) as exc:
                return self._invalid_state_decision(
                    "invalid_persisted_halt_state",
                    "The persisted halt latch failed keyed or semantic validation.",
                    {"error": str(exc)},
                )
            if not persisted_halt:
                if self.config.execution_enabled:
                    return self._invalid_state_decision(
                        "halt_latch_uninitialized",
                        "Alpaca execution cannot bootstrap a missing authenticated halt "
                        "latch. Disable execution and establish reviewed state first.",
                        {"field": "halt"},
                    )
                self.store.clear_halt()
                self.store.record_event(
                    "WARNING",
                    "HALT_LATCH_INITIALIZED",
                    "The authenticated inactive halt latch was initialized while "
                    "Alpaca execution was disabled.",
                )

        if self.config.broker == "alpaca":
            approved_aum = float(self.config.strategy.costs.starting_capital)
            if not math.isfinite(approved_aum) or approved_aum <= 0.0:
                return self._invalid_state_decision(
                    "invalid_approved_research_aum",
                    "The approved research AUM limit is non-finite or non-positive.",
                    {"approved_aum": approved_aum},
                )
            if float(account.equity) > approved_aum + max(0.01, approved_aum * 1e-12):
                return self._invalid_state_decision(
                    "account_equity_exceeds_approved_research_aum",
                    "Broker equity exceeds the AUM modeled by the approved research "
                    "capacity assumptions. New risk is blocked until capital is reduced "
                    "or a larger capacity study is independently approved.",
                    {
                        "account_equity": float(account.equity),
                        "approved_research_aum": approved_aum,
                    },
                )

        try:
            cooldown = self.store.cooldown_remaining()
        except (TypeError, ValueError, OverflowError) as exc:
            return self._invalid_state_decision(
                "invalid_persisted_risk_baseline",
                "The persisted cooldown state could not be interpreted safely.",
                {"field": "cooldown_remaining", "error": str(exc)},
            )

        try:
            existing_high_watermark = self.store.high_watermark_state()
            if (
                self.config.broker == "alpaca"
                and self.config.execution_enabled
                and existing_high_watermark is None
            ):
                return self._invalid_state_decision(
                    "high_watermark_uninitialized",
                    "Alpaca execution cannot initialize a missing high-water mark. "
                    "Disable execution, independently review the account, and establish "
                    "the baseline before enabling orders.",
                    {"field": "high_watermark"},
                )
            high_watermark = float(self.store.update_high_watermark(account.equity))
        except (TypeError, ValueError, OverflowError) as exc:
            return self._invalid_state_decision(
                "invalid_persisted_risk_baseline",
                "The persisted high-water mark could not be interpreted safely.",
                {"field": "high_watermark", "error": str(exc)},
            )
        if not math.isfinite(high_watermark) or high_watermark <= 0.0:
            return self._invalid_state_decision(
                "invalid_persisted_risk_baseline",
                "The persisted high-water mark is non-finite or non-positive.",
                {"field": "high_watermark", "value": high_watermark},
            )
        drawdown = account.equity / high_watermark - 1.0 if high_watermark > 0 else 0.0

        session_key = f"session_open_equity:{session_date.isoformat()}"
        session_open = self.store.get_state(session_key, None)
        if session_open is None:
            # Recover a deleted state key from the immutable intraday snapshot history
            # before consulting a broker field that may already include today's P&L.
            try:
                session_open = self.store.get_session_open_equity(session_date)
            except (TypeError, ValueError, OverflowError) as exc:
                return self._invalid_state_decision(
                    "invalid_persisted_risk_baseline",
                    "The earliest session snapshot could not reconstruct a safe open.",
                    {"field": session_key, "error": str(exc)},
                )
            if session_open is None:
                session_open = account.last_equity if account.last_equity > 0 else account.equity
            self.store.set_state(session_key, float(session_open))
        elif isinstance(session_open, bool) or not isinstance(session_open, (int, float)):
            return self._invalid_state_decision(
                "invalid_persisted_risk_baseline",
                "The persisted session-open equity must be a numeric value.",
                {"field": session_key, "value_type": type(session_open).__name__},
            )
        try:
            session_open = float(session_open)
        except (TypeError, ValueError, OverflowError) as exc:
            return self._invalid_state_decision(
                "invalid_persisted_risk_baseline",
                "The persisted session-open equity could not be interpreted safely.",
                {"field": session_key, "error": str(exc)},
            )
        if not math.isfinite(session_open) or session_open <= 0.0:
            return self._invalid_state_decision(
                "invalid_persisted_risk_baseline",
                "The persisted session-open equity is non-finite or non-positive.",
                {"field": session_key, "value": session_open},
            )
        daily_return = account.equity / session_open - 1.0 if session_open > 0 else 0.0

        closes = self.store.get_daily_closing_equities_before(session_date, limit=5)
        invalid_closes = [
            value
            for value in closes
            if not math.isfinite(float(value)) or float(value) <= 0.0
        ]
        if invalid_closes:
            return self._invalid_state_decision(
                "invalid_persisted_risk_baseline",
                "Persisted historical closing equity contains invalid values.",
                {"field": "equity_snapshots", "invalid_count": len(invalid_closes)},
            )
        # Current equity versus the close five completed sessions earlier. Excluding the
        # current session keeps the anchor stable across repeated intraday monitor cycles.
        five_day_anchor = closes[0] if closes else account.last_equity
        five_day_return = (
            account.equity / five_day_anchor - 1.0 if five_day_anchor and five_day_anchor > 0 else 0.0
        )
        if not all(math.isfinite(value) for value in (drawdown, daily_return, five_day_return)):
            return self._invalid_state_decision(
                "invalid_computed_risk_metrics",
                "Computed drawdown or loss metrics were non-finite.",
                {},
            )

        self.store.record_equity(
            account=account,
            session_date=session_date,
            drawdown=drawdown,
            daily_return=daily_return,
            five_day_return=five_day_return,
        )

        if not ignore_operator_controls:
            kill_request = self._kill_switch_request()
            if kill_request is not None:
                self.store.request_halt(
                    kill_request.reason,
                    flatten=kill_request.flatten,
                )
                if kill_request.flatten:
                    return RiskDecision(
                        False,
                        True,
                        True,
                        kill_request.reason,
                        drawdown,
                        daily_return,
                        five_day_return,
                    )

        if account.account_blocked or account.trading_blocked:
            reason = "broker_account_blocked"
            self.store.request_halt(reason)
            return RiskDecision(False, True, True, reason, drawdown, daily_return, five_day_return)

        if self.config.allow_shorting and not account.shorting_enabled:
            reason = "broker_shorting_disabled"
            self.store.request_halt(reason)
            return RiskDecision(False, True, True, reason, drawdown, daily_return, five_day_return)

        risk = self.config.strategy.risk
        if drawdown <= -risk.hard_drawdown_limit:
            reason = "hard_drawdown_breach"
            # A hard-limit breach always requires a human review and explicit resume.
            effective_halt = self._activate_shutdown(reason, persistent=True)
            return RiskDecision(
                False,
                True,
                effective_halt,
                reason,
                drawdown,
                daily_return,
                five_day_return,
            )

        persistent = not self.config.auto_resume_after_cooldown

        if drawdown <= -risk.flatten_drawdown:
            reason = "prelimit_drawdown_flatten"
            effective_halt = self._activate_shutdown(reason, persistent=persistent)
            return RiskDecision(
                False,
                True,
                effective_halt,
                reason,
                drawdown,
                daily_return,
                five_day_return,
            )

        if self.config.flatten_on_daily_loss and daily_return <= -risk.daily_loss_trigger:
            reason = "daily_loss_shutdown"
            effective_halt = self._activate_shutdown(reason, persistent=persistent)
            return RiskDecision(
                False,
                True,
                effective_halt,
                reason,
                drawdown,
                daily_return,
                five_day_return,
            )

        if self.config.flatten_on_five_day_loss and five_day_return <= -risk.five_day_loss_trigger:
            reason = "five_day_loss_shutdown"
            effective_halt = self._activate_shutdown(reason, persistent=persistent)
            return RiskDecision(
                False,
                True,
                effective_halt,
                reason,
                drawdown,
                daily_return,
                five_day_return,
            )

        # A halt-only request blocks new risk, but account and loss controls above are
        # still allowed to escalate it into a mandatory flatten.
        if not ignore_operator_controls:
            halt = self.store.halt_state()
            if halt.get("active"):
                return RiskDecision(
                    False,
                    bool(halt.get("flatten", True)),
                    True,
                    str(halt.get("reason", "persistent_halt")),
                    drawdown,
                    daily_return,
                    five_day_return,
                )

            if cooldown > 0:
                return RiskDecision(
                    False,
                    True,
                    False,
                    f"cooldown_{cooldown}_sessions_remaining",
                    drawdown,
                    daily_return,
                    five_day_return,
                )

        return RiskDecision(True, False, False, "risk_checks_passed", drawdown, daily_return, five_day_return)

    def _activate_shutdown(self, reason: str, persistent: bool) -> bool:
        """Activate a loss shutdown without weakening an existing incident latch.

        Automatic cooldowns are represented by the authenticated cooldown counter,
        not by writing an inactive value over the halt latch.  If another control has
        already opened an incident, the loss breach escalates that incident to a
        mandatory flatten and the returned decision remains persistently halted.
        """

        self.store.set_state("cooldown_remaining", self.config.strategy.risk.cooldown_days)
        current_halt = self.store.halt_state()
        if persistent or current_halt.get("active"):
            # request_halt performs the serialized monotonic merge.  Passing flatten
            # explicitly documents that every shutdown reaching this helper already
            # requires liquidation, including escalation from an operator halt-only.
            self.store.request_halt(reason, flatten=True)
            return True
        return False

    def advance_cooldown(self, as_of: date) -> int:
        remaining = self.store.cooldown_remaining()
        last = self.store.get_state("cooldown_last_as_of", None)
        if remaining <= 0 or last == as_of.isoformat():
            return max(remaining, 0)
        remaining = max(remaining - 1, 0)
        self.store.set_state("cooldown_remaining", remaining)
        self.store.set_state("cooldown_last_as_of", as_of.isoformat())
        # Automatic cooldown expiry must never clear an independently created halt.
        # Auto-resumable loss shutdowns do not create a halt latch; only an explicit,
        # independently risk-checked manual resume may clear an active incident.
        return remaining
