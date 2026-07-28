from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import date, datetime
from enum import Enum
from typing import Any


class OrderSide(str, Enum):
    BUY = "buy"
    SELL = "sell"


class OrderPhase(str, Enum):
    REDUCE = "reduce"
    INCREASE = "increase"
    FLATTEN = "flatten"
    DRY_RUN = "dry_run"


TERMINAL_ORDER_STATUSES = {
    "filled",
    "canceled",
    "cancelled",
    "expired",
    "rejected",
    "failed",
    "done_for_day",
}


@dataclass(frozen=True)
class CashActivity:
    """Broker-reported external cash movement used only for risk governance.

    Cash activities are deliberately not folded into returns automatically. Broker
    activity dates can represent creation or settlement dates and corrections can
    arrive later, so a newly observed activity is an incident requiring independent
    reconciliation rather than an invitation to rewrite P&L history.
    """

    activity_id: str
    activity_type: str
    activity_date: date
    net_amount: float
    status: str | None = None
    currency: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "activity_id": self.activity_id,
            "activity_type": self.activity_type,
            "activity_date": self.activity_date.isoformat(),
            "net_amount": self.net_amount,
            "status": self.status,
            "currency": self.currency,
        }


@dataclass(frozen=True)
class AccountSnapshot:
    timestamp: datetime
    equity: float
    cash: float
    buying_power: float
    last_equity: float
    trading_blocked: bool = False
    account_blocked: bool = False
    shorting_enabled: bool = True
    multiplier: float = 1.0
    # ``None`` means the broker could not produce complete cash-activity evidence.
    # Alpaca risk evaluation fails closed in that state. Other brokers must explicitly
    # provide an empty tuple when they can prove no external cash activity exists.
    external_cash_activities: tuple[CashActivity, ...] | None = None
    cash_activity_error: str = ""


@dataclass(frozen=True)
class PositionSnapshot:
    symbol: str
    qty: float
    market_value: float
    current_price: float
    avg_entry_price: float = 0.0
    unrealized_pl: float = 0.0


@dataclass(frozen=True)
class AssetInfo:
    symbol: str
    tradable: bool
    shortable: bool
    easy_to_borrow: bool
    fractionable: bool
    marginable: bool


@dataclass(frozen=True)
class MarketClock:
    timestamp: datetime
    is_open: bool
    next_open: datetime
    next_close: datetime


@dataclass(frozen=True)
class OrderIntent:
    symbol: str
    qty: float
    side: OrderSide
    phase: OrderPhase
    current_qty: float
    target_qty: float
    estimated_price: float
    estimated_notional: float
    client_order_id: str
    reason: str = "rebalance"

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["side"] = self.side.value
        result["phase"] = self.phase.value
        return result


@dataclass(frozen=True)
class RoutineChildAuthorization:
    """One-time authenticated capability for exactly one routine child order.

    The engine derives these fields from an already authenticated target plan and
    HMACs the complete payload before handing control to the broker adapter.  The
    final broker callback must match every field and the refreshed broker position
    before the capability can authorize a state-mutating REST request.
    """

    plan_id: str
    plan_authentication_hmac_sha256: str
    intended_session: date
    phase: OrderPhase
    client_order_id: str
    symbol: str
    side: OrderSide
    qty: float
    current_qty: float
    target_qty: float
    not_after: datetime
    authorization_hmac_sha256: str


@dataclass(frozen=True)
class RoutineSubmissionContext:
    """Quote and request identity passed through the final Alpaca commit gate."""

    client_order_id: str
    quote_timestamp: datetime
    bid: float
    ask: float
    midpoint: float
    final_commit: bool = False


@dataclass(frozen=True)
class OrderReceipt:
    broker_order_id: str
    client_order_id: str
    symbol: str
    qty: float
    side: str
    status: str
    submitted_at: datetime
    filled_qty: float = 0.0
    filled_avg_price: float | None = None
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class TargetPlan:
    plan_id: str
    as_of: date
    created_at: datetime
    regime: str
    regime_multiplier: float
    desired_gross: float
    forecast_volatility: float
    target_weights: dict[str, float]
    metadata: dict[str, Any] = field(default_factory=dict)
    status: str = "approved"

    def to_dict(self) -> dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "as_of": self.as_of.isoformat(),
            "created_at": self.created_at.isoformat(),
            "regime": self.regime,
            "regime_multiplier": self.regime_multiplier,
            "desired_gross": self.desired_gross,
            "forecast_volatility": self.forecast_volatility,
            "target_weights": self.target_weights,
            "metadata": self.metadata,
            "status": self.status,
        }


@dataclass(frozen=True)
class RiskDecision:
    allow_new_risk: bool
    flatten: bool
    halt: bool
    reason: str
    drawdown: float
    daily_return: float
    five_day_return: float


@dataclass(frozen=True)
class ExecutionSummary:
    plan_id: str
    status: str
    submitted_orders: int
    filled_orders: int
    residual_notional: float
    message: str
    intents: list[OrderIntent] = field(default_factory=list)
