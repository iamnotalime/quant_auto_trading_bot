from __future__ import annotations

import math
import inspect
from decimal import Decimal, ROUND_CEILING, ROUND_FLOOR
from datetime import date, datetime, timedelta, timezone
from typing import Any, Callable, NamedTuple

import pandas as pd

from auto_trader.covariance_evidence import SignedCovarianceEvidenceProvider
from auto_trader.borrow_evidence import (
    SignedBorrowEvidenceProvider,
    VerifiedBorrowEvidence,
)
from auto_trader.models import (
    AccountSnapshot,
    AssetInfo,
    CashActivity,
    MarketClock,
    OrderReceipt,
    OrderSide,
    PositionSnapshot,
    RoutineSubmissionContext,
)
from .base import Broker, GovernedCovarianceEvidence


class VerifiedExecutionQuote(NamedTuple):
    bid: float
    ask: float
    midpoint: float
    timestamp: datetime


class AlpacaBroker(Broker):
    """Alpaca Trading API and Market Data API adapter using the official alpaca-py SDK."""

    # These account activities move capital into or out of the strategy account and
    # therefore cannot be interpreted as trading P&L. Security transfers (ACATS/FOPT)
    # remain an external reconciliation blocker documented in SECURITY.md because the
    # legacy activity object does not provide a reliable equity value for them.
    _EXTERNAL_CASH_ACTIVITY_TYPES = ("CSD", "CSW", "ACATC", "JNLC")
    _MAX_CASH_ACTIVITY_RECORDS = 10_000
    _CASH_ACTIVITY_PAGE_SIZE = 100
    _MAX_ROUTINE_CASH_ACTIVITY_PAGES = 3
    _ROUTINE_CASH_ACTIVITY_BOUNDARY_SIZE = 10
    _MAX_COMPLETE_CASH_ACTIVITY_SNAPSHOT_AGE_SECONDS = 300.0
    _REST_CONNECT_TIMEOUT_SECONDS = 2.0
    _REST_READ_TIMEOUT_SECONDS = 5.0
    _MIN_ROUTINE_REST_MARGIN_SECONDS = 8.0

    def __init__(
        self,
        api_key: str,
        secret_key: str,
        paper: bool = True,
        data_feed: str = "iex",
        max_execution_price_age_seconds: int = 60,
        max_execution_spread_bps: float = 50.0,
        marketable_limit_collar_bps: float = 35.0,
        routine_execution_authorized_until: datetime | None = None,
        routine_authorization_check: Callable[..., datetime | None] | None = None,
        covariance_evidence_provider: SignedCovarianceEvidenceProvider | None = None,
        borrow_evidence_provider: SignedBorrowEvidenceProvider | None = None,
    ) -> None:
        try:
            from alpaca.data.enums import DataFeed
            from alpaca.data.historical import StockHistoricalDataClient
            from alpaca.trading.client import TradingClient
        except ImportError as exc:  # pragma: no cover - exercised only without optional SDK
            raise RuntimeError(
                "alpaca-py is required for BROKER=alpaca. Install requirements.txt."
            ) from exc

        self._imports()
        self.trading = TradingClient(api_key, secret_key, paper=paper)
        self.data = StockHistoricalDataClient(api_key, secret_key)
        self._install_bounded_rest_timeout(self.trading)
        self._install_bounded_rest_timeout(self.data)
        self.max_execution_price_age_seconds = int(max_execution_price_age_seconds)
        self.max_execution_spread_bps = float(max_execution_spread_bps)
        self.marketable_limit_collar_bps = float(marketable_limit_collar_bps)
        self._routine_execution_authorized_until = routine_execution_authorized_until
        self._routine_authorization_check = routine_authorization_check
        self._covariance_evidence_provider = covariance_evidence_provider
        self._borrow_evidence_provider = borrow_evidence_provider
        try:
            self.feed = DataFeed(data_feed)
        except ValueError as exc:
            raise ValueError(f"Unsupported ALPACA_DATA_FEED {data_feed!r}.") from exc

    @staticmethod
    def _imports() -> None:
        # Import validation is kept in one place so the rest of the adapter remains readable.
        from alpaca.data.enums import Adjustment, DataFeed  # noqa: F401
        from alpaca.data.requests import StockBarsRequest, StockLatestQuoteRequest  # noqa: F401
        from alpaca.data.timeframe import TimeFrame  # noqa: F401
        from alpaca.trading.enums import OrderSide as AlpacaOrderSide, QueryOrderStatus, TimeInForce  # noqa: F401
        from alpaca.trading.requests import GetOrdersRequest, LimitOrderRequest, MarketOrderRequest  # noqa: F401

    @classmethod
    def _install_bounded_rest_timeout(cls, client: object) -> None:
        """Install explicit connect/read deadlines on alpaca-py's requests session.

        Alpaca-py 0.43 does not pass a timeout to ``requests.Session.request``.  A
        blocked socket would otherwise make the 09:35 checks and daemon watchdog the
        only bounds.  The SDK has no public timeout hook, so validate its session shape
        and wrap only this client instance; caller-supplied stricter timeouts survive.
        """

        session = getattr(client, "_session", None)
        request = getattr(session, "request", None)
        retry_count = getattr(client, "_retry", None)
        if (
            session is None
            or not callable(request)
            or isinstance(retry_count, bool)
            or not isinstance(retry_count, int)
        ):
            raise RuntimeError(
                "The installed alpaca-py client does not expose the expected bounded "
                "HTTP session; refusing an unbounded broker connection."
            )
        # The SDK otherwise retries 429/504 responses with blocking sleeps. At a hard
        # execution boundary a deterministic failure is safer than a hidden multi-call
        # delay; the engine can reconcile/retry under its own client-ID/deadline policy.
        client._retry = 0
        if bool(getattr(session, "_qauto_timeout_installed", False)):
            return

        def bounded_request(method: str, url: str, **kwargs: object):
            kwargs.setdefault(
                "timeout",
                (
                    cls._REST_CONNECT_TIMEOUT_SECONDS,
                    cls._REST_READ_TIMEOUT_SECONDS,
                ),
            )
            return request(method, url, **kwargs)

        session.request = bounded_request
        session._qauto_timeout_installed = True

    @classmethod
    def _parse_external_cash_activity(cls, raw: object) -> CashActivity:
        if not isinstance(raw, dict):
            raise RuntimeError("Alpaca cash-activity entry was not an object.")
        activity_id = str(raw.get("id", "")).strip()
        activity_type = str(raw.get("activity_type", "")).strip().upper()
        if not activity_id or len(activity_id) > 512:
            raise RuntimeError("Alpaca cash activity had a missing or invalid ID.")
        if activity_type not in cls._EXTERNAL_CASH_ACTIVITY_TYPES:
            raise RuntimeError(
                "Alpaca returned an unexpected type in the cash-activity feed."
            )
        date_value = raw.get("date")
        if not isinstance(date_value, str) or not date_value.strip():
            raise RuntimeError("Alpaca cash activity had an invalid date.")
        try:
            parsed_date = pd.Timestamp(date_value)
            if pd.isna(parsed_date):
                raise ValueError("missing date")
            activity_date = parsed_date.date()
            net_amount = float(raw.get("net_amount"))
        except (TypeError, ValueError, OverflowError) as exc:
            raise RuntimeError(
                "Alpaca cash activity had an invalid date or net amount."
            ) from exc
        if not math.isfinite(net_amount):
            raise RuntimeError("Alpaca cash activity had a non-finite net amount.")
        status_value = raw.get("status")
        if status_value is not None and not isinstance(status_value, str):
            raise RuntimeError("Alpaca cash activity had an invalid status.")
        currency_value = raw.get("currency")
        if currency_value is not None and not isinstance(currency_value, str):
            raise RuntimeError("Alpaca cash activity had an invalid currency.")
        return CashActivity(
            activity_id=activity_id,
            activity_type=activity_type,
            activity_date=activity_date,
            net_amount=net_amount,
            status=(status_value.strip().lower() if status_value else None),
            currency=(currency_value.strip().upper() if currency_value else None),
        )

    @staticmethod
    def _sorted_cash_activities(
        records: dict[str, CashActivity],
    ) -> tuple[CashActivity, ...]:
        return tuple(
            sorted(
                records.values(),
                key=lambda item: (item.activity_date, item.activity_id),
            )
        )

    def _get_external_cash_activities(self) -> tuple[CashActivity, ...]:
        """Return the complete paginated Trading-API cash activity history.

        Alpaca-py 0.43.x models account activities but does not expose the personal
        Trading API method on ``TradingClient``. Its inherited authenticated ``get``
        method is public and the official endpoint is ``/v2/account/activities``.
        Pagination is explicit so the risk layer never mistakes a truncated first page
        for complete evidence.
        """

        page_size = self._CASH_ACTIVITY_PAGE_SIZE
        page_token: str | None = None
        seen_tokens: set[str] = set()
        records: dict[str, CashActivity] = {}
        while True:
            params: dict[str, object] = {
                "activity_types": ",".join(self._EXTERNAL_CASH_ACTIVITY_TYPES),
                "direction": "asc",
                "page_size": page_size,
            }
            if page_token is not None:
                params["page_token"] = page_token
            response = self.trading.get("/account/activities", params)
            if not isinstance(response, list):
                raise RuntimeError("Alpaca cash-activity response was not a list.")
            if len(response) > page_size:
                raise RuntimeError(
                    "Alpaca cash-activity response exceeded the requested page size."
                )
            for raw in response:
                activity = self._parse_external_cash_activity(raw)
                activity_id = activity.activity_id
                if activity_id in records:
                    raise RuntimeError("Alpaca cash-activity pagination returned a duplicate ID.")
                records[activity_id] = activity
                if len(records) > self._MAX_CASH_ACTIVITY_RECORDS:
                    raise RuntimeError(
                        "Alpaca cash-activity history exceeds the bounded safety limit."
                    )

            if len(response) < page_size:
                break
            next_token = str(response[-1].get("id", "")).strip()
            if not next_token or next_token == page_token or next_token in seen_tokens:
                raise RuntimeError("Alpaca cash-activity pagination did not advance.")
            seen_tokens.add(next_token)
            page_token = next_token

        result = self._sorted_cash_activities(records)
        self._cash_activity_cache = result
        self._complete_cash_activity_snapshot_at = datetime.now(timezone.utc)
        return result

    def _get_bounded_routine_cash_activities(self) -> tuple[CashActivity, ...]:
        """Refresh cash evidence with bounded latency at the final order boundary.

        A complete ascending history is loaded before routine execution begins.  This
        method walks at most three newest-first pages and must either reach the complete
        history or overlap every one of the recent authenticated boundary IDs.  It can
        therefore detect new records and recent rewrites/deletions without placing a
        10,000-record historical scan in every child-order commit path.  Historical
        corrections remain covered by the complete pre-execution/monitor snapshot.
        """

        cached = getattr(self, "_cash_activity_cache", None)
        completed_at = getattr(self, "_complete_cash_activity_snapshot_at", None)
        now = datetime.now(timezone.utc)
        if cached is None or not isinstance(completed_at, datetime):
            raise RuntimeError(
                "Routine cash-activity refresh has no complete reconciled snapshot."
            )
        if completed_at.tzinfo is None or completed_at.utcoffset() is None:
            raise RuntimeError("Complete cash-activity snapshot time is not absolute.")
        snapshot_age = (now - completed_at.astimezone(timezone.utc)).total_seconds()
        if (
            not math.isfinite(snapshot_age)
            or snapshot_age < -5.0
            or snapshot_age > self._MAX_COMPLETE_CASH_ACTIVITY_SNAPSHOT_AGE_SECONDS
        ):
            raise RuntimeError(
                "Routine cash-activity refresh is not rooted in a recent complete snapshot."
            )

        cached_records = {item.activity_id: item for item in cached}
        if len(cached_records) != len(cached):
            raise RuntimeError("Cached cash-activity evidence contains duplicate IDs.")
        boundary_ids = {
            item.activity_id
            for item in cached[-self._ROUTINE_CASH_ACTIVITY_BOUNDARY_SIZE :]
        }
        fetched: dict[str, CashActivity] = {}
        seen_tokens: set[str] = set()
        page_token: str | None = None
        complete_history = False
        boundary_reached = False

        for _ in range(self._MAX_ROUTINE_CASH_ACTIVITY_PAGES):
            params: dict[str, object] = {
                "activity_types": ",".join(self._EXTERNAL_CASH_ACTIVITY_TYPES),
                "direction": "desc",
                "page_size": self._CASH_ACTIVITY_PAGE_SIZE,
            }
            if page_token is not None:
                params["page_token"] = page_token
            response = self.trading.get("/account/activities", params)
            if not isinstance(response, list):
                raise RuntimeError("Alpaca cash-activity response was not a list.")
            if len(response) > self._CASH_ACTIVITY_PAGE_SIZE:
                raise RuntimeError(
                    "Alpaca cash-activity response exceeded the requested page size."
                )
            for raw in response:
                activity = self._parse_external_cash_activity(raw)
                if activity.activity_id in fetched:
                    raise RuntimeError(
                        "Alpaca cash-activity pagination returned a duplicate ID."
                    )
                fetched[activity.activity_id] = activity
            if len(fetched) > (
                self._CASH_ACTIVITY_PAGE_SIZE
                * self._MAX_ROUTINE_CASH_ACTIVITY_PAGES
            ):
                raise RuntimeError("Routine cash-activity refresh exceeded its bound.")
            if len(response) < self._CASH_ACTIVITY_PAGE_SIZE:
                complete_history = True
                break
            if boundary_ids and boundary_ids.issubset(fetched):
                boundary_reached = True
                break
            if not response:
                complete_history = True
                break
            last = response[-1]
            if not isinstance(last, dict):
                raise RuntimeError("Alpaca cash-activity entry was not an object.")
            next_token = str(last.get("id", "")).strip()
            if not next_token or next_token == page_token or next_token in seen_tokens:
                raise RuntimeError("Alpaca cash-activity pagination did not advance.")
            seen_tokens.add(next_token)
            page_token = next_token

        if not complete_history and not boundary_reached:
            raise RuntimeError(
                "Routine cash-activity refresh could not prove a recent-history boundary "
                "within its fixed page limit."
            )
        if complete_history:
            current = fetched
        else:
            current = dict(cached_records)
            current.update(fetched)
        if len(current) > self._MAX_CASH_ACTIVITY_RECORDS:
            raise RuntimeError(
                "Alpaca cash-activity history exceeds the bounded safety limit."
            )
        result = self._sorted_cash_activities(current)
        self._cash_activity_cache = result
        return result

    def _get_account_with_cash_activity_loader(
        self,
        loader: Callable[[], tuple[CashActivity, ...]],
    ) -> AccountSnapshot:
        account = self.trading.get_account()
        timestamp = datetime.now(timezone.utc)
        cash_activities: tuple[CashActivity, ...] | None
        cash_activity_error = ""
        try:
            cash_activities = loader()
        except Exception as exc:
            # Preserve the valid account snapshot so RiskManager can durably halt and
            # request reconciliation. Raising here would leave a one-shot execution
            # caller without a persisted risk incident.
            cash_activities = None
            cash_activity_error = type(exc).__name__
        return AccountSnapshot(
            timestamp=timestamp,
            equity=float(account.equity),
            cash=float(account.cash),
            buying_power=float(account.buying_power),
            last_equity=float(account.last_equity),
            trading_blocked=bool(account.trading_blocked),
            account_blocked=bool(account.account_blocked),
            shorting_enabled=bool(account.shorting_enabled),
            multiplier=float(account.multiplier),
            external_cash_activities=cash_activities,
            cash_activity_error=cash_activity_error,
        )

    def get_account(self) -> AccountSnapshot:
        """Return an account snapshot with complete cash-history reconciliation."""

        return self._get_account_with_cash_activity_loader(
            self._get_external_cash_activities
        )

    def get_account_for_routine_authorization(self) -> AccountSnapshot:
        """Return a final-boundary account with a strictly bounded cash refresh."""

        return self._get_account_with_cash_activity_loader(
            self._get_bounded_routine_cash_activities
        )

    def get_account_identity(self) -> str:
        """Return the broker's authoritative account identifier without logging it."""

        account = self.trading.get_account()
        account_id = str(getattr(account, "id", "")).strip()
        if not account_id or len(account_id) > 128:
            raise RuntimeError("Alpaca returned a missing or invalid account identity.")
        return account_id

    def get_positions(self) -> dict[str, PositionSnapshot]:
        result: dict[str, PositionSnapshot] = {}
        for position in self.trading.get_all_positions():
            qty = float(position.qty)
            if str(position.side).lower().endswith("short") and qty > 0:
                qty = -qty
            result[position.symbol] = PositionSnapshot(
                symbol=position.symbol,
                qty=qty,
                market_value=float(position.market_value),
                current_price=float(position.current_price),
                avg_entry_price=float(position.avg_entry_price),
                unrealized_pl=float(position.unrealized_pl),
            )
        return result

    def get_asset_info(self, symbols: list[str]) -> dict[str, AssetInfo]:
        result: dict[str, AssetInfo] = {}
        for symbol in symbols:
            try:
                asset = self.trading.get_asset(symbol)
                result[symbol] = AssetInfo(
                    symbol=symbol,
                    tradable=bool(asset.tradable),
                    shortable=bool(asset.shortable),
                    easy_to_borrow=bool(asset.easy_to_borrow),
                    fractionable=bool(asset.fractionable),
                    marginable=bool(asset.marginable),
                )
            except Exception:
                result[symbol] = AssetInfo(symbol, False, False, False, False, False)
        return result

    def get_market_clock(self) -> MarketClock:
        clock = self.trading.get_clock()
        return MarketClock(
            timestamp=clock.timestamp,
            is_open=bool(clock.is_open),
            next_open=clock.next_open,
            next_close=clock.next_close,
        )

    def get_daily_prices(
        self,
        symbols: list[str],
        history_bars: int,
        latest_allowed_date: date,
    ) -> pd.DataFrame:
        from alpaca.data.enums import Adjustment
        from alpaca.data.requests import StockBarsRequest
        from alpaca.data.timeframe import TimeFrame

        end = datetime.combine(latest_allowed_date + timedelta(days=1), datetime.min.time(), tzinfo=timezone.utc)
        start = end - timedelta(days=max(int(history_bars * 2.2), history_bars + 60))
        request = StockBarsRequest(
            symbol_or_symbols=symbols,
            timeframe=TimeFrame.Day,
            start=start,
            end=end,
            adjustment=Adjustment.ALL,
            feed=self.feed,
        )
        bars = self.data.get_stock_bars(request)
        frame = bars.df.copy()
        if frame.empty:
            return pd.DataFrame(columns=symbols, dtype=float)

        reset = frame.reset_index()
        symbol_col = next(c for c in reset.columns if str(c).lower() == "symbol")
        timestamp_col = next(c for c in reset.columns if str(c).lower() in {"timestamp", "time"})
        close_col = next(c for c in reset.columns if str(c).lower() == "close")
        reset[timestamp_col] = pd.to_datetime(reset[timestamp_col], utc=True)
        reset["session_date"] = reset[timestamp_col].dt.tz_convert("America/New_York").dt.date
        reset = reset.loc[reset["session_date"] <= latest_allowed_date]
        pivot = reset.pivot_table(
            index="session_date",
            columns=symbol_col,
            values=close_col,
            aggfunc="last",
        )
        pivot.index = pd.to_datetime(pivot.index)
        pivot = pivot.reindex(columns=[s for s in symbols if s in pivot.columns])
        return pivot.sort_index().tail(history_bars).astype(float)

    def get_governed_covariance_evidence(
        self,
        symbols: list[str],
        history_bars: int,
        latest_allowed_date: date,
    ) -> GovernedCovarianceEvidence:
        """Load only authenticated PIT VWAP/action evidence for governed planning."""

        provider = self._covariance_evidence_provider
        if provider is None:
            raise RuntimeError(
                "Signed point-in-time covariance evidence provider is not configured; "
                "daily closes cannot be substituted."
            )
        verified = provider.load(symbols, history_bars, latest_allowed_date)
        return GovernedCovarianceEvidence(
            execution_prices=verified.execution_prices,
            split_ratios=verified.split_ratios,
            cash_distributions=verified.cash_distributions,
            intended_execution_date=verified.intended_execution_date,
            provenance=verified.provenance,
        )

    def get_governed_borrow_evidence(
        self,
        symbols: list[str],
        intended_session: date,
        *,
        now: datetime | None = None,
    ) -> VerifiedBorrowEvidence:
        """Load only signed, account-bound, exact-session live borrow terms."""

        provider = self._borrow_evidence_provider
        if provider is None:
            raise RuntimeError(
                "Signed point-in-time live borrow evidence provider is not configured; "
                "broker asset flags cannot substitute for account-bound locate terms."
            )
        return provider.load(symbols, intended_session, now=now)

    def get_latest_prices(self, symbols: list[str]) -> dict[str, float]:
        return {
            symbol: quote.midpoint
            for symbol, quote in self._fresh_quotes(symbols).items()
        }

    def _quote_is_fresh(
        self,
        quote: VerifiedExecutionQuote,
        *,
        now: datetime | None = None,
    ) -> bool:
        observed = now or datetime.now(timezone.utc)
        if observed.tzinfo is None or observed.utcoffset() is None:
            return False
        timestamp = quote.timestamp
        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            return False
        age_seconds = (
            observed.astimezone(timezone.utc) - timestamp.astimezone(timezone.utc)
        ).total_seconds()
        midpoint = float(quote.midpoint)
        spread_bps = (
            (float(quote.ask) - float(quote.bid)) / midpoint * 10_000.0
            if midpoint > 0.0
            else math.inf
        )
        return bool(
            all(
                math.isfinite(value)
                for value in (
                    float(quote.bid),
                    float(quote.ask),
                    midpoint,
                    age_seconds,
                    spread_bps,
                )
            )
            and quote.bid > 0.0
            and quote.ask >= quote.bid
            and -5.0 <= age_seconds <= self.max_execution_price_age_seconds
            and spread_bps <= self.max_execution_spread_bps
        )

    def _fresh_quotes(
        self, symbols: list[str]
    ) -> dict[str, VerifiedExecutionQuote]:
        """Return executable quotes while retaining their broker timestamps."""

        from alpaca.data.requests import StockLatestQuoteRequest

        if not symbols:
            return {}
        quotes = self.data.get_stock_latest_quote(
            StockLatestQuoteRequest(symbol_or_symbols=symbols, feed=self.feed)
        )
        result: dict[str, VerifiedExecutionQuote] = {}
        now = pd.Timestamp.now(tz="UTC")
        for symbol, quote in quotes.items():
            bid = float(getattr(quote, "bid_price", 0.0) or 0.0)
            ask = float(getattr(quote, "ask_price", 0.0) or 0.0)
            timestamp = getattr(quote, "timestamp", None)
            if (
                not math.isfinite(bid)
                or not math.isfinite(ask)
                or bid <= 0.0
                or ask <= 0.0
                or ask < bid
                or timestamp is None
            ):
                continue
            quote_time = pd.Timestamp(timestamp)
            # Broker execution timestamps must be absolute instants. Treating a naive
            # timestamp as UTC can make an ambiguous/local quote appear fresh.
            if quote_time.tzinfo is None:
                continue
            quote_time = quote_time.tz_convert("UTC")
            midpoint = (bid + ask) / 2.0
            verified = VerifiedExecutionQuote(
                bid=bid,
                ask=ask,
                midpoint=midpoint,
                timestamp=quote_time.to_pydatetime(),
            )
            if not self._quote_is_fresh(verified, now=now.to_pydatetime()):
                continue
            result[str(symbol)] = verified
        return result

    def list_open_orders(self, symbols: list[str] | None = None) -> list[OrderReceipt]:
        from alpaca.trading.enums import QueryOrderStatus
        from alpaca.trading.requests import GetOrdersRequest

        orders = self.trading.get_orders(
            GetOrdersRequest(status=QueryOrderStatus.OPEN, symbols=symbols or None)
        )
        return [self._receipt(order) for order in orders]

    def cancel_order(self, broker_order_id: str) -> None:
        self.trading.cancel_order_by_id(broker_order_id)

    def submit_market_order(
        self,
        symbol: str,
        qty: float,
        side: OrderSide,
        client_order_id: str,
    ) -> OrderReceipt:
        """Submit a routine rebalance as a fresh-quote, price-collared limit order.

        The legacy method name is retained for Broker/simulator compatibility. Only
        the explicit emergency method below transmits a true, uncollared market order.
        """

        return self._submit_order(
            symbol=symbol,
            qty=qty,
            side=side,
            client_order_id=client_order_id,
            emergency=False,
        )

    def _authorize_routine_submission(
        self,
        symbol: str,
        qty: float,
        side: OrderSide,
        limit_price: float,
        context: RoutineSubmissionContext | None = None,
    ) -> datetime | None:
        """Authorize only at the last pre-REST boundary after quote/ID reads."""

        authorized_until = getattr(self, "_routine_execution_authorized_until", None)
        authorization_check = getattr(self, "_routine_authorization_check", None)
        if (
            authorized_until is None
            or authorized_until.tzinfo is None
            or authorized_until.utcoffset() is None
            or datetime.now(timezone.utc) >= authorized_until.astimezone(timezone.utc)
        ):
            raise RuntimeError(
                "Routine Alpaca order submission is blocked because the signed "
                "deployment approval is missing or expired. Emergency liquidation "
                "remains available."
            )
        if authorization_check is None:
            raise RuntimeError(
                "Routine Alpaca order submission is blocked because no live deployment "
                "authorization verifier is installed. Emergency liquidation remains available."
            )
        supports_context = self._authorization_accepts_context(authorization_check)
        if context is not None and supports_context:
            result = authorization_check(symbol, qty, side, limit_price, context)
        else:
            result = authorization_check(symbol, qty, side, limit_price)
        if result is None:
            return None
        if not isinstance(result, datetime) or result.tzinfo is None or result.utcoffset() is None:
            raise RuntimeError("Routine authorization returned an invalid commit deadline.")
        return result.astimezone(timezone.utc)

    @staticmethod
    def _authorization_accepts_context(authorization_check: Callable[..., object]) -> bool:
        try:
            parameters = tuple(inspect.signature(authorization_check).parameters.values())
        except (TypeError, ValueError):
            return False
        return any(parameter.kind == inspect.Parameter.VAR_POSITIONAL for parameter in parameters) or len(
            [
                parameter
                for parameter in parameters
                if parameter.kind
                in {
                    inspect.Parameter.POSITIONAL_ONLY,
                    inspect.Parameter.POSITIONAL_OR_KEYWORD,
                }
            ]
        ) >= 5

    def get_order_by_client_id(self, client_order_id: str) -> OrderReceipt | None:
        try:
            order = self.trading.get_order_by_client_id(str(client_order_id))
        except Exception as lookup_exc:
            if getattr(lookup_exc, "status_code", None) == 404:
                return None
            raise RuntimeError(
                "Could not authoritatively look up the broker client order ID."
            ) from lookup_exc
        return self._receipt(order)

    def submit_emergency_market_order(
        self,
        symbol: str,
        qty: float,
        side: OrderSide,
        client_order_id: str,
    ) -> OrderReceipt:
        """Submit a true market order when immediate risk removal is paramount."""

        return self._submit_order(
            symbol=symbol,
            qty=qty,
            side=side,
            client_order_id=client_order_id,
            emergency=True,
        )

    def _submit_order(
        self,
        *,
        symbol: str,
        qty: float,
        side: OrderSide,
        client_order_id: str,
        emergency: bool,
    ) -> OrderReceipt:
        qty = float(qty)
        if not math.isfinite(qty) or qty <= 0.0:
            raise ValueError("Order quantity must be positive and finite.")

        # Resolve an existing deterministic client ID before submitting. This makes a
        # daemon retry idempotent when a previous response was lost after broker acceptance.
        try:
            existing = self.trading.get_order_by_client_id(client_order_id)
        except Exception as lookup_exc:
            # A genuine 404 means the deterministic ID is unused. Connectivity, auth,
            # and server failures must block submission because duplicate status is unknown.
            if getattr(lookup_exc, "status_code", None) != 404:
                raise RuntimeError(
                    "Could not verify whether the client order ID already exists; "
                    "submission was blocked to prevent a duplicate order."
                ) from lookup_exc
            existing = None
        if existing is not None:
            return self._matching_receipt(
                existing,
                symbol=symbol,
                qty=qty,
                side=side,
                client_order_id=client_order_id,
            )

        from alpaca.trading.enums import OrderSide as AlpacaOrderSide, TimeInForce
        from alpaca.trading.requests import LimitOrderRequest, MarketOrderRequest

        request_side = (
            AlpacaOrderSide.BUY if side == OrderSide.BUY else AlpacaOrderSide.SELL
        )
        common = {
            "symbol": symbol,
            "qty": qty,
            "side": request_side,
            # Routine benchmark children must never rest beyond 09:35. Emergency
            # liquidation remains a DAY market order; routine marketable limits are
            # IOC and are also polled/canceled against the engine's wall-clock deadline.
            "time_in_force": TimeInForce.DAY if emergency else TimeInForce.IOC,
            "client_order_id": client_order_id,
        }
        if emergency:
            request = MarketOrderRequest(**common)
        else:
            authorization_check = getattr(self, "_routine_authorization_check", None)
            supports_commit_context = bool(
                authorization_check is not None
                and self._authorization_accepts_context(authorization_check)
            )
            request = None
            for _quote_attempt in range(3):
                quote = self._fresh_quotes([symbol]).get(symbol)
                if quote is None:
                    raise RuntimeError(
                        f"No fresh, spread-compliant quote is available for {symbol}; "
                        "the routine order was blocked rather than sent without a price collar."
                    )
                limit_price = self._marketable_limit_price(quote.midpoint, side)
                if (
                    (side == OrderSide.BUY and limit_price + 1e-12 < quote.ask)
                    or (side == OrderSide.SELL and limit_price - 1e-12 > quote.bid)
                ):
                    raise RuntimeError(
                        f"No broker-valid marketable limit for {symbol} fits inside the "
                        "configured price collar; submission was blocked."
                    )
                candidate_request = LimitOrderRequest(
                    **common,
                    limit_price=limit_price,
                )
                context = RoutineSubmissionContext(
                    client_order_id=client_order_id,
                    quote_timestamp=quote.timestamp,
                    bid=quote.bid,
                    ask=quote.ask,
                    midpoint=quote.midpoint,
                    final_commit=False,
                )
                commit_deadline = self._authorize_routine_submission(
                    symbol,
                    qty,
                    side,
                    limit_price,
                    context,
                )
                # RSA/evidence/account verification can consume most of a quote's
                # freshness budget. Never reuse a quote that aged out during that work.
                if not self._quote_is_fresh(quote):
                    continue
                if supports_commit_context:
                    commit_deadline = self._authorize_routine_submission(
                        symbol,
                        qty,
                        side,
                        limit_price,
                        RoutineSubmissionContext(
                            client_order_id=client_order_id,
                            quote_timestamp=quote.timestamp,
                            bid=quote.bid,
                            ask=quote.ask,
                            midpoint=quote.midpoint,
                            final_commit=True,
                        ),
                    )
                if not self._quote_is_fresh(quote):
                    continue
                if commit_deadline is not None:
                    remaining = (
                        commit_deadline - datetime.now(timezone.utc)
                    ).total_seconds()
                    if remaining < self._MIN_ROUTINE_REST_MARGIN_SECONDS:
                        raise RuntimeError(
                            "Routine order lacks the fixed REST latency margin before "
                            "its hard commit deadline."
                        )
                request = candidate_request
                break
            if request is None:
                raise RuntimeError(
                    "Routine authorization repeatedly outlived its quote; submission was blocked."
                )
        try:
            order = self.trading.submit_order(order_data=request)
        except Exception as submit_exc:
            # The request may have reached the broker even if the client timed out. Query by
            # client ID once before propagating the error and triggering the safety path.
            try:
                order = self.trading.get_order_by_client_id(client_order_id)
            except Exception as lookup_exc:
                if getattr(lookup_exc, "status_code", None) == 404:
                    raise submit_exc
                raise RuntimeError(
                    "Order submission outcome is unknown and broker reconciliation failed. "
                    "The bot will halt rather than retry blindly."
                ) from lookup_exc
        return self._matching_receipt(
            order,
            symbol=symbol,
            qty=qty,
            side=side,
            client_order_id=client_order_id,
        )

    def _marketable_limit_price(self, midpoint: float, side: OrderSide) -> float:
        """Return a broker-valid price no worse than the configured quote collar.

        Equity limit prices use Alpaca's supported precision (two decimals at $1+
        and four below $1). Rounding is deliberately inward: a buy is rounded down
        and a sell up, so tick rounding can make an order less marketable but can
        never enlarge the configured worst-price boundary.
        """

        midpoint = float(midpoint)
        collar_bps = float(self.marketable_limit_collar_bps)
        if (
            not math.isfinite(midpoint)
            or midpoint <= 0.0
            or not math.isfinite(collar_bps)
            or collar_bps <= 0.0
        ):
            raise ValueError("A positive finite midpoint and order-price collar are required.")
        direction = Decimal("1") if side == OrderSide.BUY else Decimal("-1")
        raw_limit = Decimal(str(midpoint)) * (
            Decimal("1") + direction * Decimal(str(collar_bps)) / Decimal("10000")
        )
        tick = Decimal("0.01") if raw_limit >= Decimal("1") else Decimal("0.0001")
        rounding = ROUND_FLOOR if side == OrderSide.BUY else ROUND_CEILING
        limit_price = raw_limit.quantize(tick, rounding=rounding)
        if limit_price <= 0:
            raise ValueError("The configured order-price collar produced a non-positive limit.")
        return float(limit_price)

    def get_order(self, broker_order_id: str) -> OrderReceipt:
        return self._receipt(self.trading.get_order_by_id(broker_order_id))

    @staticmethod
    def _enum_value(value: Any) -> str:
        return str(getattr(value, "value", value))

    @classmethod
    def _matching_receipt(
        cls,
        order: Any,
        *,
        symbol: str,
        qty: float,
        side: OrderSide,
        client_order_id: str,
    ) -> OrderReceipt:
        """Reject a deterministic-ID collision with a different economic intent."""

        receipt = cls._receipt(order)
        same_qty = abs(receipt.qty - float(qty)) <= max(1e-8, abs(float(qty)) * 1e-8)
        if (
            receipt.client_order_id != client_order_id
            or receipt.symbol.upper() != symbol.upper()
            or receipt.side.lower() != side.value
            or not same_qty
        ):
            raise RuntimeError(
                "Existing client order ID does not match the requested symbol, side, and "
                f"quantity; refusing an unsafe retry for {client_order_id}."
            )
        return receipt

    @classmethod
    def _receipt(cls, order: Any) -> OrderReceipt:
        raw = order.model_dump(mode="json") if hasattr(order, "model_dump") else {}
        submitted = order.submitted_at or order.created_at or datetime.now(timezone.utc)
        return OrderReceipt(
            broker_order_id=str(order.id),
            client_order_id=str(order.client_order_id),
            symbol=str(order.symbol),
            qty=float(order.qty or 0.0),
            side=cls._enum_value(order.side),
            status=cls._enum_value(order.status),
            submitted_at=submitted,
            filled_qty=float(order.filled_qty or 0.0),
            filled_avg_price=(float(order.filled_avg_price) if order.filled_avg_price else None),
            raw=raw,
        )
