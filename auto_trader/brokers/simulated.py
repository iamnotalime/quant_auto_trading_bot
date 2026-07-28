from __future__ import annotations

import json
import math
import uuid
from datetime import date, datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

import pandas as pd

from auto_trader.models import (
    AccountSnapshot,
    AssetInfo,
    MarketClock,
    OrderReceipt,
    OrderSide,
    PositionSnapshot,
)
from .base import Broker


class SimulatedBroker(Broker):
    """Persistent, immediate-fill broker for offline end-to-end testing.

    It deliberately uses simple fills and must not be interpreted as a realistic execution
    simulator. Its purpose is to test scheduling, persistence, order sequencing, and risk
    controls without touching a brokerage account.
    """

    def __init__(
        self,
        prices_path: str | Path,
        state_path: str | Path,
        starting_cash: float = 100_000.0,
        slippage_bps: float = 2.0,
        timezone: str = "America/New_York",
        market_always_open: bool = True,
        prices: pd.DataFrame | None = None,
    ) -> None:
        self.prices_path = Path(prices_path)
        self.state_path = Path(state_path)
        self.starting_cash = float(starting_cash)
        self.slippage_bps = float(slippage_bps)
        self.tz = ZoneInfo(timezone)
        self.market_always_open = market_always_open
        self._prices = self._load_prices(prices)
        self._state = self._load_state()

    def _load_prices(self, supplied: pd.DataFrame | None) -> pd.DataFrame:
        if supplied is not None:
            frame = supplied.copy()
        else:
            frame = pd.read_csv(self.prices_path)
            date_col = next((c for c in frame.columns if c.lower() in {"date", "datetime", "timestamp"}), frame.columns[0])
            frame[date_col] = pd.to_datetime(frame[date_col], errors="coerce")
            frame = frame.set_index(date_col)
        frame.index = pd.to_datetime(frame.index).tz_localize(None)
        frame = frame.sort_index().apply(pd.to_numeric, errors="coerce")
        frame = frame.where(frame > 0).ffill(limit=5).dropna(how="all")
        if frame.empty:
            raise ValueError("The simulated price file contains no usable prices.")
        return frame

    @property
    def available_symbols(self) -> list[str]:
        return list(self._prices.columns)

    def _load_state(self) -> dict:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        if self.state_path.exists():
            try:
                state = json.loads(self.state_path.read_text(encoding="utf-8"))
                self._validate_state(state)
            except (json.JSONDecodeError, OSError, TypeError, ValueError) as exc:
                raise RuntimeError(
                    "Existing simulated broker state is corrupt or incomplete; refusing "
                    "to recreate it as a flat account."
                ) from exc
            return state
        state = {
            "cash": self.starting_cash,
            "last_equity": self.starting_cash,
            "positions": {},
            "orders": {},
        }
        self._persist(state)
        return state

    @staticmethod
    def _validate_state(state: object) -> None:
        if not isinstance(state, dict):
            raise ValueError("state root must be an object")
        required = {"cash", "last_equity", "positions", "orders"}
        missing = sorted(required.difference(state))
        if missing:
            raise ValueError(f"state is missing required fields: {missing}")
        cash = float(state["cash"])
        last_equity = float(state["last_equity"])
        if not math.isfinite(cash):
            raise ValueError("cash must be finite")
        if not math.isfinite(last_equity) or last_equity <= 0.0:
            raise ValueError("last_equity must be positive and finite")
        positions = state["positions"]
        orders = state["orders"]
        if not isinstance(positions, dict) or not isinstance(orders, dict):
            raise ValueError("positions and orders must be objects")
        for symbol, raw_qty in positions.items():
            if not isinstance(symbol, str) or not symbol:
                raise ValueError("position symbols must be non-empty strings")
            if not math.isfinite(float(raw_qty)):
                raise ValueError(f"position quantity for {symbol} must be finite")
        client_ids: set[str] = set()
        for order_id, raw in orders.items():
            if not isinstance(raw, dict):
                raise ValueError(f"order {order_id} must be an object")
            order_required = {
                "broker_order_id",
                "client_order_id",
                "symbol",
                "qty",
                "side",
                "status",
                "submitted_at",
            }
            if order_required.difference(raw):
                raise ValueError(f"order {order_id} is incomplete")
            qty = float(raw["qty"])
            filled_qty = float(raw.get("filled_qty", 0.0))
            if not math.isfinite(qty) or qty <= 0.0:
                raise ValueError(f"order {order_id} quantity is invalid")
            if not math.isfinite(filled_qty) or filled_qty < 0.0 or filled_qty > qty + 1e-8:
                raise ValueError(f"order {order_id} filled quantity is invalid")
            client_order_id = str(raw["client_order_id"])
            if not client_order_id or client_order_id in client_ids:
                raise ValueError("client order IDs must be non-empty and unique")
            client_ids.add(client_order_id)
            if str(raw["side"]).lower() not in {"buy", "sell"}:
                raise ValueError(f"order {order_id} side is invalid")
            if str(raw["status"]).lower() not in {
                "new",
                "accepted",
                "partially_filled",
                "filled",
                "canceled",
                "cancelled",
                "expired",
                "rejected",
                "failed",
                "done_for_day",
            }:
                raise ValueError(f"order {order_id} status is invalid")
            datetime.fromisoformat(str(raw["submitted_at"]))

    def _persist(self, state: dict | None = None) -> None:
        payload = state if state is not None else self._state
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.state_path.with_suffix(self.state_path.suffix + ".tmp")
        temporary.write_text(
            json.dumps(payload, indent=2, sort_keys=True, allow_nan=False),
            encoding="utf-8",
        )
        temporary.replace(self.state_path)

    def _last_prices(self) -> dict[str, float]:
        row = self._prices.iloc[-1]
        return {str(symbol): float(value) for symbol, value in row.items() if pd.notna(value) and value > 0}

    def _equity_and_gross(self) -> tuple[float, float]:
        prices = self._last_prices()
        market_value = 0.0
        gross = 0.0
        for symbol, qty in self._state["positions"].items():
            quantity = float(qty)
            if not math.isfinite(quantity):
                raise RuntimeError(f"Simulated position quantity for {symbol} is non-finite.")
            if abs(quantity) <= 1e-12:
                continue
            price = prices.get(symbol)
            if price is None or not math.isfinite(float(price)) or float(price) <= 0.0:
                raise RuntimeError(
                    f"Held simulated position {symbol} has no valid latest valuation mark."
                )
            value = quantity * price
            market_value += value
            gross += abs(value)
        cash = float(self._state["cash"])
        if not math.isfinite(cash):
            raise RuntimeError("Simulated cash balance is non-finite.")
        return cash + market_value, gross

    def get_account(self) -> AccountSnapshot:
        now = datetime.now(self.tz)
        equity, gross = self._equity_and_gross()
        buying_power = max(2.0 * equity - gross, 0.0)
        return AccountSnapshot(
            timestamp=now,
            equity=equity,
            cash=float(self._state["cash"]),
            buying_power=buying_power,
            last_equity=float(self._state.get("last_equity", equity)),
            trading_blocked=False,
            account_blocked=False,
            shorting_enabled=True,
            multiplier=2.0,
            external_cash_activities=(),
        )

    def get_positions(self) -> dict[str, PositionSnapshot]:
        prices = self._last_prices()
        result: dict[str, PositionSnapshot] = {}
        for symbol, raw_qty in self._state["positions"].items():
            qty = float(raw_qty)
            if not math.isfinite(qty):
                raise RuntimeError(f"Simulated position quantity for {symbol} is non-finite.")
            if abs(qty) < 1e-12:
                continue
            if symbol not in prices:
                raise RuntimeError(
                    f"Held simulated position {symbol} has no valid latest valuation mark."
                )
            price = prices[symbol]
            result[symbol] = PositionSnapshot(
                symbol=symbol,
                qty=qty,
                market_value=qty * price,
                current_price=price,
            )
        return result

    def get_asset_info(self, symbols: list[str]) -> dict[str, AssetInfo]:
        available = set(self.available_symbols)
        return {
            symbol: AssetInfo(
                symbol=symbol,
                tradable=symbol in available,
                shortable=symbol in available,
                easy_to_borrow=symbol in available,
                fractionable=True,
                marginable=True,
            )
            for symbol in symbols
        }

    def get_market_clock(self) -> MarketClock:
        now = datetime.now(self.tz)
        open_today = now.replace(hour=9, minute=30, second=0, microsecond=0)
        close_today = now.replace(hour=16, minute=0, second=0, microsecond=0)
        if self.market_always_open:
            is_open = True
        else:
            is_open = now.weekday() < 5 and open_today <= now <= close_today

        cursor = now
        while True:
            cursor = cursor + timedelta(days=1)
            if cursor.weekday() < 5:
                break
        next_open = cursor.replace(hour=9, minute=30, second=0, microsecond=0)
        next_close = cursor.replace(hour=16, minute=0, second=0, microsecond=0)
        if now.weekday() < 5 and now < open_today:
            next_open = open_today
            next_close = close_today
        elif now.weekday() < 5 and is_open:
            next_close = close_today
        return MarketClock(now, is_open, next_open, next_close)

    def get_daily_prices(
        self,
        symbols: list[str],
        history_bars: int,
        latest_allowed_date: date,
    ) -> pd.DataFrame:
        chosen = [s for s in symbols if s in self._prices.columns]
        if len(chosen) < 4:
            chosen = self.available_symbols
        frame = self._prices.loc[self._prices.index.date <= latest_allowed_date, chosen]
        return frame.tail(history_bars).copy()

    def get_latest_prices(self, symbols: list[str]) -> dict[str, float]:
        prices = self._last_prices()
        return {s: prices[s] for s in symbols if s in prices}

    def list_open_orders(self, symbols: list[str] | None = None) -> list[OrderReceipt]:
        allowed = set(symbols) if symbols else None
        result: list[OrderReceipt] = []
        for raw in self._state["orders"].values():
            if raw.get("status") not in {"new", "accepted", "partially_filled"}:
                continue
            if allowed is not None and raw["symbol"] not in allowed:
                continue
            result.append(self._receipt(raw))
        return result

    def get_order_by_client_id(self, client_order_id: str) -> OrderReceipt | None:
        matches = [
            self._receipt(raw)
            for raw in self._state["orders"].values()
            if raw.get("client_order_id") == str(client_order_id)
        ]
        if len(matches) > 1:
            raise RuntimeError("Simulated broker contains a duplicate client order ID.")
        return matches[0] if matches else None

    def cancel_order(self, broker_order_id: str) -> None:
        raw = self._state["orders"].get(str(broker_order_id))
        if raw and raw.get("status") not in {"filled", "canceled", "rejected"}:
            raw["status"] = "canceled"
            self._persist()

    def submit_market_order(
        self,
        symbol: str,
        qty: float,
        side: OrderSide,
        client_order_id: str,
    ) -> OrderReceipt:
        qty = float(qty)
        if not math.isfinite(qty) or qty <= 0:
            raise ValueError("Order quantity must be positive and finite.")
        prices = self._last_prices()
        if symbol not in prices:
            raise ValueError(f"No simulated price is available for {symbol}.")

        # Idempotent client order IDs prevent accidental duplicate fills on retry.
        for raw in self._state["orders"].values():
            if raw.get("client_order_id") == client_order_id:
                existing_qty = float(raw.get("qty", 0.0))
                same_qty = abs(existing_qty - qty) <= max(1e-8, abs(qty) * 1e-8)
                if (
                    str(raw.get("symbol", "")).upper() != symbol.upper()
                    or str(raw.get("side", "")).lower() != side.value
                    or not same_qty
                ):
                    raise RuntimeError(
                        "Existing simulated client order ID does not match the requested "
                        "economic intent."
                    )
                return self._receipt(raw)

        mid = prices[symbol]
        slip = self.slippage_bps / 10_000.0
        fill_price = mid * (1.0 + slip if side == OrderSide.BUY else 1.0 - slip)
        signed_qty = qty if side == OrderSide.BUY else -qty
        old_qty = float(self._state["positions"].get(symbol, 0.0))
        new_qty = old_qty + signed_qty
        self._state["cash"] = float(self._state["cash"]) - signed_qty * fill_price
        if abs(new_qty) < 1e-10:
            self._state["positions"].pop(symbol, None)
        else:
            self._state["positions"][symbol] = new_qty

        order_id = str(uuid.uuid4())
        submitted_at = datetime.now(self.tz)
        raw = {
            "broker_order_id": order_id,
            "client_order_id": client_order_id,
            "symbol": symbol,
            "qty": qty,
            "side": side.value,
            "status": "filled",
            "submitted_at": submitted_at.isoformat(),
            "filled_qty": qty,
            "filled_avg_price": fill_price,
        }
        self._state["orders"][order_id] = raw
        equity, _ = self._equity_and_gross()
        self._state["last_equity"] = equity
        self._persist()
        return self._receipt(raw)

    def get_order(self, broker_order_id: str) -> OrderReceipt:
        raw = self._state["orders"].get(str(broker_order_id))
        if raw is None:
            raise KeyError(f"Unknown simulated order {broker_order_id}.")
        return self._receipt(raw)

    @staticmethod
    def _receipt(raw: dict) -> OrderReceipt:
        return OrderReceipt(
            broker_order_id=str(raw["broker_order_id"]),
            client_order_id=str(raw["client_order_id"]),
            symbol=str(raw["symbol"]),
            qty=float(raw["qty"]),
            side=str(raw["side"]),
            status=str(raw["status"]),
            submitted_at=datetime.fromisoformat(raw["submitted_at"]),
            filled_qty=float(raw.get("filled_qty", 0.0)),
            filled_avg_price=(
                float(raw["filled_avg_price"])
                if raw.get("filled_avg_price") is not None
                else None
            ),
            raw=dict(raw),
        )
