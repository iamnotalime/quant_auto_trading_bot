from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from auto_trader.brokers.alpaca import AlpacaBroker, VerifiedExecutionQuote
from auto_trader.models import CashActivity, OrderSide


def _activity(index: int, *, amount: float = 100.0) -> CashActivity:
    return CashActivity(
        activity_id=f"20260701000000000::cash-{index:04d}",
        activity_type="CSD",
        activity_date=date(2026, 7, 1),
        net_amount=amount,
        status="executed",
        currency="USD",
    )


def _raw(activity: CashActivity) -> dict[str, str]:
    return {
        "id": activity.activity_id,
        "activity_type": activity.activity_type,
        "date": activity.activity_date.isoformat(),
        "net_amount": str(activity.net_amount),
        "status": activity.status or "",
        "currency": activity.currency or "",
    }


def _account() -> SimpleNamespace:
    return SimpleNamespace(
        equity="100000",
        cash="100000",
        buying_power="200000",
        last_equity="100000",
        trading_blocked=False,
        account_blocked=False,
        shorting_enabled=True,
        multiplier="2",
    )


def test_routine_cash_refresh_merges_new_activity_in_one_bounded_page() -> None:
    cached = tuple(_activity(index) for index in range(150))
    newest_page = [_activity(150), *reversed(cached[-99:])]

    class TradingStub:
        calls: list[dict[str, object]] = []

        def get(self, path, params):
            assert path == "/account/activities"
            self.calls.append(dict(params))
            return [_raw(item) for item in newest_page]

    broker = AlpacaBroker.__new__(AlpacaBroker)
    broker.trading = TradingStub()
    broker._cash_activity_cache = cached
    broker._complete_cash_activity_snapshot_at = datetime.now(timezone.utc)

    result = broker._get_bounded_routine_cash_activities()

    assert len(result) == 151
    assert result[-1].activity_id == _activity(150).activity_id
    assert len(broker.trading.calls) == 1
    assert broker.trading.calls[0]["direction"] == "desc"
    assert broker.trading.calls[0]["page_size"] == 100


def test_routine_cash_refresh_fails_after_fixed_pages_without_overlap() -> None:
    cached = tuple(_activity(index) for index in range(20))

    class TradingStub:
        calls: list[dict[str, object]] = []

        def get(self, _path, params):
            page = len(self.calls)
            self.calls.append(dict(params))
            return [
                _raw(_activity(1_000 + page * 100 + index))
                for index in range(100)
            ]

    broker = AlpacaBroker.__new__(AlpacaBroker)
    broker.trading = TradingStub()
    broker._cash_activity_cache = cached
    broker._complete_cash_activity_snapshot_at = datetime.now(timezone.utc)

    with pytest.raises(RuntimeError, match="fixed page limit"):
        broker._get_bounded_routine_cash_activities()

    assert len(broker.trading.calls) == broker._MAX_ROUTINE_CASH_ACTIVITY_PAGES
    assert "page_token" not in broker.trading.calls[0]
    assert all("page_token" in call for call in broker.trading.calls[1:])


def test_complete_short_routine_refresh_exposes_deletion_and_correction() -> None:
    cached = (_activity(1), _activity(2))
    corrected = _activity(2, amount=125.0)

    class TradingStub:
        @staticmethod
        def get(_path, params):
            assert params["direction"] == "desc"
            return [_raw(corrected)]

    broker = AlpacaBroker.__new__(AlpacaBroker)
    broker.trading = TradingStub()
    broker._cash_activity_cache = cached
    broker._complete_cash_activity_snapshot_at = datetime.now(timezone.utc)

    result = broker._get_bounded_routine_cash_activities()

    assert result == (corrected,)
    assert _activity(1).activity_id not in {item.activity_id for item in result}
    assert result[0].net_amount == pytest.approx(125.0)


def test_stale_complete_snapshot_fails_before_activity_network_read() -> None:
    class TradingStub:
        activity_calls = 0

        @classmethod
        def get(cls, *_args, **_kwargs):
            cls.activity_calls += 1
            raise AssertionError("stale cache must fail before an activity request")

    broker = AlpacaBroker.__new__(AlpacaBroker)
    broker.trading = TradingStub()
    broker._cash_activity_cache = (_activity(1),)
    broker._complete_cash_activity_snapshot_at = datetime.now(timezone.utc) - timedelta(
        seconds=301
    )

    with pytest.raises(RuntimeError, match="recent complete snapshot"):
        broker._get_bounded_routine_cash_activities()

    assert broker.trading.activity_calls == 0


def test_routine_account_surfaces_missing_prime_as_unavailable_evidence() -> None:
    class TradingStub:
        activity_calls = 0

        @staticmethod
        def get_account():
            return _account()

        @classmethod
        def get(cls, *_args, **_kwargs):
            cls.activity_calls += 1
            raise AssertionError("unprimed routine read must not paginate history")

    broker = AlpacaBroker.__new__(AlpacaBroker)
    broker.trading = TradingStub()

    account = broker.get_account_for_routine_authorization()

    assert account.external_cash_activities is None
    assert account.cash_activity_error == "RuntimeError"
    assert broker.trading.activity_calls == 0


def test_alpaca_rest_session_installs_explicit_deadlines_without_weakening_caller() -> None:
    class SessionStub:
        calls: list[dict[str, object]] = []

        def request(self, _method, _url, **kwargs):
            self.calls.append(dict(kwargs))
            return "ok"

    session = SessionStub()
    client = SimpleNamespace(_session=session, _retry=3)

    AlpacaBroker._install_bounded_rest_timeout(client)
    assert client._retry == 0
    assert session.request("GET", "https://example.invalid") == "ok"
    assert session.calls[-1]["timeout"] == (
        AlpacaBroker._REST_CONNECT_TIMEOUT_SECONDS,
        AlpacaBroker._REST_READ_TIMEOUT_SECONDS,
    )

    AlpacaBroker._install_bounded_rest_timeout(client)
    assert session.request("GET", "https://example.invalid", timeout=(1.0, 1.5)) == "ok"
    assert session.calls[-1]["timeout"] == (1.0, 1.5)


def test_alpaca_rest_session_shape_change_fails_closed() -> None:
    with pytest.raises(RuntimeError, match="refusing an unbounded broker connection"):
        AlpacaBroker._install_bounded_rest_timeout(SimpleNamespace())


def test_routine_submission_requires_fixed_rest_latency_margin() -> None:
    class MissingOrder(Exception):
        status_code = 404

    class TradingStub:
        submitted = False

        @staticmethod
        def get_order_by_client_id(_client_order_id):
            raise MissingOrder("unused")

        def submit_order(self, **_kwargs):
            self.submitted = True
            raise AssertionError("insufficient-margin order must not reach REST")

    broker = AlpacaBroker.__new__(AlpacaBroker)
    broker.trading = TradingStub()
    broker.max_execution_price_age_seconds = 60
    broker.max_execution_spread_bps = 50.0
    broker.marketable_limit_collar_bps = 35.0
    broker._routine_execution_authorized_until = datetime.now(timezone.utc) + timedelta(
        hours=1
    )

    def authorize(_symbol, _qty, _side, _limit_price, _context):
        return datetime.now(timezone.utc) + timedelta(
            seconds=broker._MIN_ROUTINE_REST_MARGIN_SECONDS - 0.5
        )

    broker._routine_authorization_check = authorize
    broker._fresh_quotes = lambda _symbols: {
        "SPY": VerifiedExecutionQuote(
            bid=99.99,
            ask=100.01,
            midpoint=100.0,
            timestamp=datetime.now(timezone.utc),
        )
    }

    with pytest.raises(RuntimeError, match="fixed REST latency margin"):
        broker.submit_market_order("SPY", 1.0, OrderSide.BUY, "qauto-margin-test")

    assert broker.trading.submitted is False
