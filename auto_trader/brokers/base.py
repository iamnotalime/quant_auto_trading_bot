from __future__ import annotations

import math
import time as time_module
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import TYPE_CHECKING, Callable, Mapping

import pandas as pd

from auto_trader.models import (
    AccountSnapshot,
    AssetInfo,
    MarketClock,
    OrderReceipt,
    OrderSide,
    PositionSnapshot,
    TERMINAL_ORDER_STATUSES,
)

if TYPE_CHECKING:
    from auto_trader.borrow_evidence import VerifiedBorrowEvidence


@dataclass(frozen=True)
class GovernedCovarianceEvidence:
    """Authenticated inputs for research-identical execution-return covariance.

    The execution-price panel is intentionally inseparable from complete split and
    cash-distribution panels.  A production adapter verifies the external signature
    before constructing this object; the planner then validates the axes/economics and
    binds exact panel and provenance hashes into the authenticated target plan.
    """

    execution_prices: pd.DataFrame
    split_ratios: pd.DataFrame
    cash_distributions: pd.DataFrame
    intended_execution_date: date
    provenance: Mapping[str, str] = field(default_factory=dict)


class Broker(ABC):
    def set_progress_callback(self, callback: Callable[[], None] | None) -> None:
        """Register a daemon-liveness callback for completed broker round trips."""
        self._progress_callback = callback

    def _mark_progress(self) -> None:
        callback = getattr(self, "_progress_callback", None)
        if callback is not None:
            callback()

    @abstractmethod
    def get_account(self) -> AccountSnapshot: ...

    def get_account_for_routine_authorization(self) -> AccountSnapshot:
        """Return an account snapshot suitable for the final routine-order boundary.

        Most adapters can reuse :meth:`get_account`.  A remote adapter whose ordinary
        snapshot performs a complete historical reconciliation may override this with
        a bounded incremental refresh, provided that refresh fails closed unless it is
        rooted in a recent complete snapshot.
        """

        return self.get_account()

    @abstractmethod
    def get_positions(self) -> dict[str, PositionSnapshot]: ...

    @abstractmethod
    def get_asset_info(self, symbols: list[str]) -> dict[str, AssetInfo]: ...

    @abstractmethod
    def get_market_clock(self) -> MarketClock: ...

    @abstractmethod
    def get_daily_prices(
        self,
        symbols: list[str],
        history_bars: int,
        latest_allowed_date: date,
    ) -> pd.DataFrame: ...

    def get_governed_covariance_evidence(
        self,
        symbols: list[str],
        history_bars: int,
        latest_allowed_date: date,
    ) -> GovernedCovarianceEvidence | None:
        """Return authenticated VWAP/corporate-action covariance evidence, if available.

        Production adapters must verify their governed snapshot/signature before
        returning evidence. ``None`` is deliberately fail-closed for routine Alpaca
        planning; ordinary daily closes or raw split-discontinuous VWAP returns are not
        silently relabeled as the sealed economic-return risk model.
        """

        return None

    def get_governed_borrow_evidence(
        self,
        symbols: list[str],
        intended_session: date,
        *,
        now: datetime | None = None,
    ) -> VerifiedBorrowEvidence | None:
        """Return authenticated exact-session locate/rate/recall evidence, if available.

        Routine production execution treats ``None`` as unavailable evidence. The
        emergency-order API deliberately does not call this method, so missing locate
        data can block all routine mutation without trapping liquidation.
        """

        return None

    @abstractmethod
    def get_latest_prices(self, symbols: list[str]) -> dict[str, float]: ...

    @abstractmethod
    def list_open_orders(self, symbols: list[str] | None = None) -> list[OrderReceipt]: ...

    @abstractmethod
    def cancel_order(self, broker_order_id: str) -> None: ...

    @abstractmethod
    def submit_market_order(
        self,
        symbol: str,
        qty: float,
        side: OrderSide,
        client_order_id: str,
    ) -> OrderReceipt: ...

    def submit_emergency_market_order(
        self,
        symbol: str,
        qty: float,
        side: OrderSide,
        client_order_id: str,
    ) -> OrderReceipt:
        """Submit an uncapped liquidation order for an active risk emergency.

        Simple/offline adapters retain their existing behavior through this default.
        Production adapters can keep routine orders price-collared while overriding
        this method with a true market order so a stale collar cannot trap exposure.
        """

        return self.submit_market_order(symbol, qty, side, client_order_id)

    @abstractmethod
    def get_order(self, broker_order_id: str) -> OrderReceipt: ...

    def get_order_by_client_id(self, client_order_id: str) -> OrderReceipt | None:
        """Return an exact client-ID match, or ``None`` only for authoritative absence.

        Emergency stale-economics reconciliation depends on terminal order history,
        not merely the open-order list. Production adapters must override this method;
        failing closed is safer than treating an unsupported lookup as a 404.
        """

        raise RuntimeError("Broker does not support authoritative client-ID lookup.")

    def cancel_managed_orders(self, symbols: list[str], client_prefix: str = "qauto-") -> int:
        canceled = 0
        for order in self.list_open_orders(symbols):
            if order.client_order_id.startswith(client_prefix):
                self.cancel_order(order.broker_order_id)
                canceled += 1
        return canceled

    @staticmethod
    def _validate_receipt_transition(
        previous: OrderReceipt,
        current: OrderReceipt,
    ) -> None:
        """Reject broker polling data that changes an order's economic identity."""

        previous_qty = float(previous.qty)
        current_qty = float(current.qty)
        tolerance = max(1e-8, abs(previous_qty) * 1e-8)
        if (
            current.broker_order_id != previous.broker_order_id
            or current.client_order_id != previous.client_order_id
            or current.symbol.upper() != previous.symbol.upper()
            or current.side.lower() != previous.side.lower()
            or not math.isfinite(current_qty)
            or abs(current_qty - previous_qty) > tolerance
        ):
            raise RuntimeError(
                f"Broker order identity changed during cancellation for "
                f"{previous.client_order_id}."
            )
        previous_filled = float(previous.filled_qty)
        current_filled = float(current.filled_qty)
        if (
            not math.isfinite(previous_filled)
            or not math.isfinite(current_filled)
            or current_filled < -tolerance
            or current_filled > current_qty + tolerance
            or current_filled + tolerance < previous_filled
        ):
            raise RuntimeError(
                f"Broker fill progression is invalid during cancellation for "
                f"{previous.client_order_id}."
            )

    def cancel_orders_and_wait(
        self,
        symbols: list[str] | None,
        *,
        client_prefix: str | None = "qauto-",
        timeout_seconds: float = 30.0,
        poll_seconds: float = 0.25,
    ) -> list[OrderReceipt]:
        """Cancel matching open orders and prove they reached a terminal state.

        A cancellation request is only an acknowledgement that the broker received the
        request. The order may fill while cancellation is in flight, so callers must not
        take a replacement position snapshot until every matching order is terminal.
        ``client_prefix=None`` intentionally selects every order (for dedicated accounts).
        """

        deadline = time_module.monotonic() + max(float(timeout_seconds), 0.0)
        latest: dict[str, OrderReceipt] = {}
        cancellation_requested: set[str] = set()

        while True:
            open_orders = [
                order
                for order in self.list_open_orders(symbols)
                if client_prefix is None or order.client_order_id.startswith(client_prefix)
            ]
            self._mark_progress()
            for order in open_orders:
                prior = latest.get(order.broker_order_id)
                if prior is not None:
                    self._validate_receipt_transition(prior, order)
                latest[order.broker_order_id] = order
                if order.broker_order_id not in cancellation_requested:
                    try:
                        self.cancel_order(order.broker_order_id)
                        self._mark_progress()
                    except Exception:
                        # The order can fill between list_open_orders and cancel_order.
                        # A terminal get_order result proves the race resolved safely;
                        # otherwise retain the order in the bounded confirmation loop.
                        try:
                            raced = self.get_order(order.broker_order_id)
                            self._mark_progress()
                        except Exception as lookup_exc:
                            raise RuntimeError(
                                "Cancellation outcome could not be reconciled for "
                                f"{order.client_order_id}."
                            ) from lookup_exc
                        self._validate_receipt_transition(order, raced)
                        latest[order.broker_order_id] = raced
                        if raced.status.lower() not in TERMINAL_ORDER_STATUSES:
                            # The request may have reached the broker despite the client
                            # error. Do not resubmit blindly; wait for a terminal result.
                            latest[order.broker_order_id] = raced
                    cancellation_requested.add(order.broker_order_id)

            nonterminal: list[str] = []
            for order_id in list(latest):
                previous = latest[order_id]
                current = self.get_order(order_id)
                self._mark_progress()
                self._validate_receipt_transition(previous, current)
                latest[order_id] = current
                if current.status.lower() not in TERMINAL_ORDER_STATUSES:
                    nonterminal.append(order_id)

            # Query the open-order endpoint again on the next pass. This catches an order
            # that appeared concurrently while the first cancellation batch was processed.
            if not open_orders and not nonterminal:
                return list(latest.values())
            if time_module.monotonic() >= deadline:
                remaining = [
                    receipt.client_order_id
                    for receipt in latest.values()
                    if receipt.status.lower() not in TERMINAL_ORDER_STATUSES
                ]
                # Even if get_order looked terminal, an open-order result at the deadline
                # is contradictory broker state and must fail closed.
                if open_orders:
                    remaining.extend(order.client_order_id for order in open_orders)
                names = ", ".join(sorted(set(remaining))) or "unknown matching order"
                raise RuntimeError(
                    "Broker cancellation was not confirmed before the deadline: " + names
                )
            time_module.sleep(max(float(poll_seconds), 0.0))

    def cancel_order_and_wait(
        self,
        broker_order_id: str,
        *,
        timeout_seconds: float = 30.0,
        poll_seconds: float = 0.25,
    ) -> OrderReceipt:
        """Cancel one order and return only after its final state is known."""

        cancel_error: Exception | None = None
        try:
            self.cancel_order(broker_order_id)
            self._mark_progress()
        except Exception as exc:
            # A fill/cancel race commonly surfaces as a cancel rejection. Querying the
            # order below distinguishes a harmless terminal fill from unknown live risk.
            cancel_error = exc
        deadline = time_module.monotonic() + max(float(timeout_seconds), 0.0)
        previous: OrderReceipt | None = None
        while True:
            try:
                current = self.get_order(broker_order_id)
                self._mark_progress()
            except Exception as lookup_exc:
                if cancel_error is not None:
                    raise RuntimeError(
                        f"Cancellation outcome could not be reconciled for {broker_order_id}."
                    ) from lookup_exc
                raise
            if str(current.broker_order_id) != str(broker_order_id):
                raise RuntimeError(
                    f"Broker order identity changed during cancellation for {broker_order_id}."
                )
            if previous is not None:
                self._validate_receipt_transition(previous, current)
            previous = current
            if current.status.lower() in TERMINAL_ORDER_STATUSES:
                return current
            if time_module.monotonic() >= deadline:
                raise RuntimeError(
                    "Broker cancellation was not confirmed before the deadline for "
                    f"{current.client_order_id}."
                ) from cancel_error
            time_module.sleep(max(float(poll_seconds), 0.0))

    def now(self) -> datetime:
        return self.get_market_clock().timestamp
