from __future__ import annotations

import os
import math
import re
import hashlib
from dataclasses import dataclass, replace
from datetime import time
from pathlib import Path
from typing import Mapping
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from auto_trader.plan_auth import (
    SIMULATED_PLAN_AUTHENTICATION_KEY,
    decode_plan_authentication_key,
    is_strong_plan_authentication_key,
    plan_authentication_key_fingerprint,
)
from auto_trader.emergency_auth import (
    SIMULATED_EMERGENCY_AUTHENTICATION_KEY,
    decode_emergency_authentication_key,
    emergency_authentication_key_fingerprint,
    is_strong_emergency_authentication_key,
)
from auto_trader.governed import (
    GOVERNED_EXECUTION_START,
    GOVERNED_EXECUTION_WINDOW_MINUTES,
    GOVERNED_MINIMUM_ASSETS,
)
from quant_app.config import AppConfig, CostConfig, PortfolioConfig, RiskConfig


DEFAULT_SYMBOLS = (
    "SPY", "QQQ", "IWM", "DIA", "XLK", "XLF", "XLE", "XLV", "XLI", "XLY",
    "XLP", "XLU", "XLB", "XLRE", "TLT", "IEF", "GLD", "SLV", "DBC", "USO",
)
LIVE_ACK_TEXT = "I_UNDERSTAND_LIVE_TRADING_CAN_LOSE_MONEY"
RESUME_ACK_TEXT = "RESUME_AUTOMATED_TRADING"
PROJECT_ROOT = Path(__file__).resolve().parents[1]
_SYMBOL_PATTERN = re.compile(r"^[A-Z][A-Z0-9./-]{0,14}$")
_ACCOUNT_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{7,127}$")
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def _load_env_file(path: Path) -> None:
    if not path.exists():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


def _bool(env: Mapping[str, str], key: str, default: bool) -> bool:
    raw = env.get(key)
    if raw is None:
        return default
    value = raw.strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{key} must be true or false, got {raw!r}.")


def _int(env: Mapping[str, str], key: str, default: int) -> int:
    raw = env.get(key, str(default))
    try:
        return int(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{key} must be an integer, got {raw!r}.") from exc


def _float(env: Mapping[str, str], key: str, default: float) -> float:
    raw = env.get(key, str(default))
    try:
        value = float(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{key} must be a number, got {raw!r}.") from exc
    if not math.isfinite(value):
        raise ValueError(f"{key} must be finite, got {raw!r}.")
    return value


def _clock_time(env: Mapping[str, str], key: str, default: str) -> time:
    raw = env.get(key, default).strip()
    parts = raw.split(":")
    if len(parts) != 2:
        raise ValueError(f"{key} must use HH:MM 24-hour format.")
    try:
        return time(hour=int(parts[0]), minute=int(parts[1]))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{key} must use a valid HH:MM 24-hour time, got {raw!r}.") from exc


def _rooted_path(raw: str | Path, root: Path) -> Path:
    path = Path(raw).expanduser()
    if not path.is_absolute():
        path = root / path
    return path.resolve(strict=False)


def _env_path(env_file: str | Path) -> Path:
    """Resolve config paths independently of the caller's working directory."""
    return _rooted_path(env_file, PROJECT_ROOT)


def emergency_control_paths(
    env_file: str | Path | None = ".env",
) -> tuple[Path, Path]:
    """Resolve kill/ack paths without parsing any strategy or routine-order setting."""

    config_root = PROJECT_ROOT
    if env_file:
        resolved_env_file = _env_path(env_file)
        _load_env_file(resolved_env_file)
        config_root = resolved_env_file.parent
    env = os.environ
    return (
        _rooted_path(env.get("KILL_SWITCH_PATH", "runtime/KILL_SWITCH"), config_root),
        _rooted_path(
            env.get("KILL_SWITCH_ACK_PATH", "runtime/KILL_SWITCH.ack.json"),
            config_root,
        ),
    )


def _require_finite(name: str, value: float) -> float:
    try:
        numeric = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be numeric, got {value!r}.") from exc
    if not math.isfinite(numeric):
        raise ValueError(f"{name} must be finite, got {value!r}.")
    return numeric


def _require_range(
    name: str,
    value: float,
    minimum: float,
    maximum: float,
    *,
    include_minimum: bool = True,
    include_maximum: bool = True,
) -> None:
    numeric = _require_finite(name, value)
    lower_ok = numeric >= minimum if include_minimum else numeric > minimum
    upper_ok = numeric <= maximum if include_maximum else numeric < maximum
    if not lower_ok or not upper_ok:
        left = "[" if include_minimum else "("
        right = "]" if include_maximum else ")"
        raise ValueError(f"{name} must be in {left}{minimum}, {maximum}{right}, got {value!r}.")


def _require_int_range(name: str, value: int, minimum: int, maximum: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer, got {value!r}.")
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}, got {value!r}.")


@dataclass(frozen=True)
class BotConfig:
    broker: str = "simulated"
    execution_enabled: bool = False
    alpaca_paper: bool = True
    alpaca_api_key: str = ""
    alpaca_secret_key: str = ""
    alpaca_account_id: str = ""
    alpaca_data_feed: str = "iex"
    live_ack: str = ""
    deployment_approval_path: Path | None = None
    deployment_public_keys_path: Path | None = None
    deployment_public_keys_sha256: str = ""
    covariance_evidence_path: Path | None = None
    covariance_execution_prices_path: Path | None = None
    covariance_corporate_actions_path: Path | None = None
    covariance_public_keys_path: Path | None = None
    covariance_public_keys_sha256: str = ""
    covariance_provider_id: str = ""
    covariance_venue_id: str = ""
    borrow_evidence_path: Path | None = None
    borrow_terms_path: Path | None = None
    borrow_public_keys_path: Path | None = None
    borrow_public_keys_sha256: str = ""
    borrow_provider_id: str = ""
    borrow_venue_id: str = ""
    borrow_max_term_age_seconds: int = 300
    max_live_annual_borrow_rate: float = 0.02
    plan_authentication_key: str = SIMULATED_PLAN_AUTHENTICATION_KEY
    emergency_authentication_key: str = SIMULATED_EMERGENCY_AUTHENTICATION_KEY

    symbols: tuple[str, ...] = DEFAULT_SYMBOLS
    timezone: str = "America/New_York"
    plan_time: time = time(16, 15)
    execution_time: time = GOVERNED_EXECUTION_START
    execution_window_minutes: int = GOVERNED_EXECUTION_WINDOW_MINUTES
    poll_seconds: int = 60
    scheduler_retry_minutes: int = 5
    history_bars: int = 420
    minimum_assets: int = GOVERNED_MINIMUM_ASSETS
    max_data_age_days: int = 5
    max_plan_age_days: int = 5

    database_path: Path = Path("runtime/auto_trader.sqlite3")
    log_path: Path = Path("runtime/auto_trader.log")
    kill_switch_path: Path = Path("runtime/KILL_SWITCH")
    process_lock_path: Path = Path("runtime/auto_trader.lock")
    operation_lock_path: Path = Path("runtime/auto_trader.operation.lock")
    kill_switch_ack_path: Path = Path("runtime/KILL_SWITCH.ack.json")
    daemon_health_path: Path = Path("runtime/daemon_health.json")
    emergency_journal_path: Path | None = None
    simulated_prices_path: Path = Path("sample_prices.csv")
    simulated_state_path: Path = Path("runtime/simulated_broker.json")
    simulated_starting_cash: float = 100_000.0
    simulated_market_always_open: bool = True
    simulated_slippage_bps: float = 2.0

    allow_shorting: bool = True
    require_easy_to_borrow: bool = True
    whole_shares_only: bool = True
    dedicated_account: bool = False
    min_trade_notional: float = 100.0
    max_single_order_notional_pct: float = 0.08
    buying_power_buffer: float = 0.10
    order_fill_timeout_seconds: int = 90
    order_poll_seconds: int = 2
    max_execution_price_age_seconds: int = 60
    max_execution_spread_bps: float = 50.0
    marketable_limit_collar_bps: float = 35.0
    max_orders_per_cycle: int = 50
    residual_notional_tolerance: float = 250.0
    flatten_on_execution_error: bool = True
    flatten_on_daily_loss: bool = True
    flatten_on_five_day_loss: bool = True
    auto_resume_after_cooldown: bool = False
    operation_lock_timeout_seconds: int = 30
    health_failure_threshold: int = 3
    daemon_watchdog_timeout_seconds: int = 900
    actual_gross_exposure_tolerance: float = 0.05
    actual_net_exposure_limit: float = 0.07
    actual_beta_exposure_limit: float = 0.10
    actual_position_weight_tolerance: float = 0.02

    strategy: AppConfig = AppConfig(
        portfolio=PortfolioConfig(
            target_volatility=0.08,
            max_gross_leverage=1.50,
            max_position_weight=0.08,
            covariance_halflife=42,
            rebalance_every=1,
            beta_neutral=True,
            dollar_neutral=True,
        ),
        risk=RiskConfig(
            throttle_drawdown=0.04,
            defensive_drawdown=0.07,
            severe_drawdown=0.09,
            flatten_drawdown=0.12,
            hard_drawdown_limit=0.15,
            throttle_multiplier=0.75,
            defensive_multiplier=0.50,
            severe_multiplier=0.20,
            cooldown_days=20,
            daily_loss_trigger=0.02,
            five_day_loss_trigger=0.04,
            loss_shock_multiplier=0.50,
        ),
        costs=CostConfig(
            transaction_cost_bps=3.0,
            annual_short_borrow_rate=0.02,
            annual_financing_rate=0.04,
        ),
    )

    @property
    def plan_authentication_key_bytes(self) -> bytes:
        """Return decoded key material for authenticated plan and state persistence."""

        return decode_plan_authentication_key(self.plan_authentication_key)

    @property
    def plan_authentication_key_sha256(self) -> str:
        """Return the non-secret fingerprint bound into deployment governance."""

        return plan_authentication_key_fingerprint(self.plan_authentication_key)

    @property
    def emergency_authentication_key_bytes(self) -> bytes:
        return decode_emergency_authentication_key(self.emergency_authentication_key)

    @property
    def emergency_authentication_key_sha256(self) -> str:
        return emergency_authentication_key_fingerprint(
            self.emergency_authentication_key
        )

    @property
    def effective_emergency_journal_path(self) -> Path:
        configured = self.emergency_journal_path
        if configured is not None:
            return Path(configured).expanduser().resolve(strict=False)
        kill_path = Path(self.kill_switch_path).expanduser().resolve(strict=False)
        return kill_path.with_name("EMERGENCY_JOURNAL.json")

    @property
    def emergency_journal_scope(self) -> str:
        scope = {
            "broker": self.broker,
            "environment": (
                "paper" if self.broker == "alpaca" and self.alpaca_paper else "live"
            ),
            "account_id": self.alpaca_account_id if self.broker == "alpaca" else "simulation",
            "dedicated_account": bool(self.dedicated_account),
            "symbols": [] if self.dedicated_account else sorted(set(self.symbols)),
        }
        encoded = repr(sorted(scope.items())).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    @classmethod
    def from_env(cls, env_file: str | Path | None = ".env") -> "BotConfig":
        config_root = PROJECT_ROOT
        if env_file:
            resolved_env_file = _env_path(env_file)
            _load_env_file(resolved_env_file)
            config_root = resolved_env_file.parent
        env = os.environ
        symbols_raw = env.get("SYMBOLS", ",".join(DEFAULT_SYMBOLS))
        symbols = tuple(dict.fromkeys(s.strip().upper() for s in symbols_raw.split(",") if s.strip()))

        base = cls(
            broker=env.get("BROKER", "simulated").strip().lower(),
            execution_enabled=_bool(env, "EXECUTION_ENABLED", False),
            alpaca_paper=_bool(env, "ALPACA_PAPER", True),
            alpaca_api_key=env.get("ALPACA_API_KEY", "").strip(),
            alpaca_secret_key=env.get("ALPACA_SECRET_KEY", "").strip(),
            alpaca_account_id=env.get("ALPACA_ACCOUNT_ID", "").strip(),
            alpaca_data_feed=env.get("ALPACA_DATA_FEED", "iex").strip().lower(),
            live_ack=env.get("LIVE_TRADING_ACK", "").strip(),
            deployment_approval_path=(
                _rooted_path(env["DEPLOYMENT_APPROVAL_PATH"].strip(), config_root)
                if env.get("DEPLOYMENT_APPROVAL_PATH", "").strip()
                else None
            ),
            deployment_public_keys_path=(
                _rooted_path(
                    env["DEPLOYMENT_GOVERNANCE_PUBLIC_KEYS_PATH"].strip(), config_root
                )
                if env.get("DEPLOYMENT_GOVERNANCE_PUBLIC_KEYS_PATH", "").strip()
                else None
            ),
            deployment_public_keys_sha256=env.get(
                "DEPLOYMENT_GOVERNANCE_PUBLIC_KEYS_SHA256", ""
            ).strip().lower(),
            covariance_evidence_path=(
                _rooted_path(env["COVARIANCE_EVIDENCE_PATH"].strip(), config_root)
                if env.get("COVARIANCE_EVIDENCE_PATH", "").strip()
                else None
            ),
            covariance_execution_prices_path=(
                _rooted_path(
                    env["COVARIANCE_EXECUTION_PRICES_PATH"].strip(), config_root
                )
                if env.get("COVARIANCE_EXECUTION_PRICES_PATH", "").strip()
                else None
            ),
            covariance_corporate_actions_path=(
                _rooted_path(
                    env["COVARIANCE_CORPORATE_ACTIONS_PATH"].strip(), config_root
                )
                if env.get("COVARIANCE_CORPORATE_ACTIONS_PATH", "").strip()
                else None
            ),
            covariance_public_keys_path=(
                _rooted_path(
                    env["COVARIANCE_GOVERNANCE_PUBLIC_KEYS_PATH"].strip(),
                    config_root,
                )
                if env.get("COVARIANCE_GOVERNANCE_PUBLIC_KEYS_PATH", "").strip()
                else None
            ),
            covariance_public_keys_sha256=env.get(
                "COVARIANCE_GOVERNANCE_PUBLIC_KEYS_SHA256", ""
            ).strip().lower(),
            covariance_provider_id=env.get("COVARIANCE_PROVIDER_ID", "").strip(),
            covariance_venue_id=env.get("COVARIANCE_VENUE_ID", "").strip(),
            borrow_evidence_path=(
                _rooted_path(env["BORROW_EVIDENCE_PATH"].strip(), config_root)
                if env.get("BORROW_EVIDENCE_PATH", "").strip()
                else None
            ),
            borrow_terms_path=(
                _rooted_path(env["BORROW_TERMS_PATH"].strip(), config_root)
                if env.get("BORROW_TERMS_PATH", "").strip()
                else None
            ),
            borrow_public_keys_path=(
                _rooted_path(
                    env["BORROW_GOVERNANCE_PUBLIC_KEYS_PATH"].strip(),
                    config_root,
                )
                if env.get("BORROW_GOVERNANCE_PUBLIC_KEYS_PATH", "").strip()
                else None
            ),
            borrow_public_keys_sha256=env.get(
                "BORROW_GOVERNANCE_PUBLIC_KEYS_SHA256", ""
            ).strip().lower(),
            borrow_provider_id=env.get("BORROW_PROVIDER_ID", "").strip(),
            borrow_venue_id=env.get("BORROW_VENUE_ID", "").strip(),
            borrow_max_term_age_seconds=_int(
                env, "BORROW_MAX_TERM_AGE_SECONDS", 300
            ),
            max_live_annual_borrow_rate=_float(
                env,
                "MAX_LIVE_ANNUAL_BORROW_RATE",
                _float(env, "ANNUAL_SHORT_BORROW_RATE", 0.02),
            ),
            plan_authentication_key=env.get(
                "PLAN_AUTHENTICATION_KEY",
                SIMULATED_PLAN_AUTHENTICATION_KEY,
            ).strip(),
            emergency_authentication_key=env.get(
                "EMERGENCY_AUTHENTICATION_KEY",
                SIMULATED_EMERGENCY_AUTHENTICATION_KEY,
            ).strip(),
            symbols=symbols,
            timezone=env.get("STRATEGY_TIMEZONE", "America/New_York").strip(),
            plan_time=_clock_time(env, "PLAN_TIME", "16:15"),
            execution_time=_clock_time(env, "EXECUTION_TIME", "09:30"),
            execution_window_minutes=_int(
                env,
                "EXECUTION_WINDOW_MINUTES",
                GOVERNED_EXECUTION_WINDOW_MINUTES,
            ),
            poll_seconds=_int(env, "POLL_SECONDS", 60),
            scheduler_retry_minutes=_int(env, "SCHEDULER_RETRY_MINUTES", 5),
            history_bars=_int(env, "HISTORY_BARS", 420),
            minimum_assets=_int(env, "MINIMUM_ASSETS", GOVERNED_MINIMUM_ASSETS),
            max_data_age_days=_int(env, "MAX_DATA_AGE_DAYS", 5),
            max_plan_age_days=_int(env, "MAX_PLAN_AGE_DAYS", 5),
            database_path=_rooted_path(env.get("DATABASE_PATH", "runtime/auto_trader.sqlite3"), config_root),
            log_path=_rooted_path(env.get("LOG_PATH", "runtime/auto_trader.log"), config_root),
            kill_switch_path=_rooted_path(env.get("KILL_SWITCH_PATH", "runtime/KILL_SWITCH"), config_root),
            process_lock_path=_rooted_path(env.get("PROCESS_LOCK_PATH", "runtime/auto_trader.lock"), config_root),
            operation_lock_path=_rooted_path(
                env.get("OPERATION_LOCK_PATH", "runtime/auto_trader.operation.lock"), config_root
            ),
            kill_switch_ack_path=_rooted_path(
                env.get("KILL_SWITCH_ACK_PATH", "runtime/KILL_SWITCH.ack.json"), config_root
            ),
            daemon_health_path=_rooted_path(
                env.get("DAEMON_HEALTH_PATH", "runtime/daemon_health.json"), config_root
            ),
            emergency_journal_path=_rooted_path(
                env.get("EMERGENCY_JOURNAL_PATH", "runtime/EMERGENCY_JOURNAL.json"),
                config_root,
            ),
            simulated_prices_path=_rooted_path(
                env.get("SIMULATED_PRICES_PATH", "sample_prices.csv"), config_root
            ),
            simulated_state_path=_rooted_path(
                env.get("SIMULATED_STATE_PATH", "runtime/simulated_broker.json"), config_root
            ),
            simulated_starting_cash=_float(env, "SIMULATED_STARTING_CASH", 100_000.0),
            simulated_market_always_open=_bool(env, "SIMULATED_MARKET_ALWAYS_OPEN", True),
            simulated_slippage_bps=_float(env, "SIMULATED_SLIPPAGE_BPS", 2.0),
            allow_shorting=_bool(env, "ALLOW_SHORTING", True),
            require_easy_to_borrow=_bool(env, "REQUIRE_EASY_TO_BORROW", True),
            whole_shares_only=_bool(env, "WHOLE_SHARES_ONLY", True),
            dedicated_account=_bool(env, "DEDICATED_ACCOUNT", False),
            min_trade_notional=_float(env, "MIN_TRADE_NOTIONAL", 100.0),
            max_single_order_notional_pct=_float(env, "MAX_SINGLE_ORDER_NOTIONAL_PCT", 0.08),
            buying_power_buffer=_float(env, "BUYING_POWER_BUFFER", 0.10),
            order_fill_timeout_seconds=_int(env, "ORDER_FILL_TIMEOUT_SECONDS", 90),
            order_poll_seconds=_int(env, "ORDER_POLL_SECONDS", 2),
            max_execution_price_age_seconds=_int(
                env, "MAX_EXECUTION_PRICE_AGE_SECONDS", 60
            ),
            max_execution_spread_bps=_float(env, "MAX_EXECUTION_SPREAD_BPS", 50.0),
            marketable_limit_collar_bps=_float(
                env, "MARKETABLE_LIMIT_COLLAR_BPS", 35.0
            ),
            max_orders_per_cycle=_int(env, "MAX_ORDERS_PER_CYCLE", 50),
            residual_notional_tolerance=_float(env, "RESIDUAL_NOTIONAL_TOLERANCE", 250.0),
            flatten_on_execution_error=_bool(env, "FLATTEN_ON_EXECUTION_ERROR", True),
            flatten_on_daily_loss=_bool(env, "FLATTEN_ON_DAILY_LOSS", True),
            flatten_on_five_day_loss=_bool(env, "FLATTEN_ON_FIVE_DAY_LOSS", True),
            auto_resume_after_cooldown=_bool(env, "AUTO_RESUME_AFTER_COOLDOWN", False),
            operation_lock_timeout_seconds=_int(env, "OPERATION_LOCK_TIMEOUT_SECONDS", 30),
            health_failure_threshold=_int(env, "HEALTH_FAILURE_THRESHOLD", 3),
            daemon_watchdog_timeout_seconds=_int(
                env, "DAEMON_WATCHDOG_TIMEOUT_SECONDS", 900
            ),
            actual_gross_exposure_tolerance=_float(
                env, "ACTUAL_GROSS_EXPOSURE_TOLERANCE", 0.05
            ),
            actual_net_exposure_limit=_float(env, "ACTUAL_NET_EXPOSURE_LIMIT", 0.07),
            actual_beta_exposure_limit=_float(env, "ACTUAL_BETA_EXPOSURE_LIMIT", 0.10),
            actual_position_weight_tolerance=_float(
                env, "ACTUAL_POSITION_WEIGHT_TOLERANCE", 0.02
            ),
        )

        portfolio = replace(
            base.strategy.portfolio,
            target_volatility=_float(env, "TARGET_VOLATILITY", base.strategy.portfolio.target_volatility),
            max_gross_leverage=_float(env, "MAX_GROSS_LEVERAGE", base.strategy.portfolio.max_gross_leverage),
            max_position_weight=_float(env, "MAX_POSITION_WEIGHT", base.strategy.portfolio.max_position_weight),
        )
        risk = replace(
            base.strategy.risk,
            flatten_drawdown=_float(env, "FLATTEN_DRAWDOWN", base.strategy.risk.flatten_drawdown),
            hard_drawdown_limit=_float(env, "HARD_DRAWDOWN_LIMIT", base.strategy.risk.hard_drawdown_limit),
            daily_loss_trigger=_float(env, "DAILY_LOSS_TRIGGER", base.strategy.risk.daily_loss_trigger),
            five_day_loss_trigger=_float(env, "FIVE_DAY_LOSS_TRIGGER", base.strategy.risk.five_day_loss_trigger),
            cooldown_days=_int(env, "COOLDOWN_SESSIONS", base.strategy.risk.cooldown_days),
        )
        costs = replace(
            base.strategy.costs,
            transaction_cost_bps=_float(env, "TRANSACTION_COST_BPS", base.strategy.costs.transaction_cost_bps),
            annual_short_borrow_rate=_float(env, "ANNUAL_SHORT_BORROW_RATE", base.strategy.costs.annual_short_borrow_rate),
            annual_financing_rate=_float(env, "ANNUAL_FINANCING_RATE", base.strategy.costs.annual_financing_rate),
        )
        strategy = replace(base.strategy, portfolio=portfolio, risk=risk, costs=costs)
        if base.deployment_approval_path is not None:
            # For governed deployment the signed artifact, not a partial set of
            # environment overrides, is the single source of truth for every AppConfig
            # field. build_engine authenticates this untrusted parse before connecting.
            # A missing/corrupt approval must not prevent BotConfig construction because
            # the kill CLI needs the configured filesystem marker path *before* engine
            # governance, state, or broker initialization. In that case keep the safe
            # local strategy only long enough for build_engine to fail closed (or for an
            # out-of-band kill marker to be written).
            from auto_trader.deployment import load_approved_strategy

            try:
                strategy = load_approved_strategy(base.deployment_approval_path)
            except (OSError, TypeError, ValueError):
                strategy = base.strategy
        result = replace(base, strategy=strategy)
        result.validate()
        return result

    @classmethod
    def emergency_from_env(
        cls,
        env_file: str | Path | None = ".env",
    ) -> "BotConfig":
        """Build a minimal, risk-reduction-only Alpaca configuration.

        Explicit ``kill`` authorization enables liquidation, but never installs the
        routine-order approval callback. Routine strategy, schedule, quote-collar,
        live-ack, and watchdog settings are deliberately ignored so malformed knobs
        cannot trap existing exposure.
        """

        config_root = PROJECT_ROOT
        if env_file:
            resolved_env_file = _env_path(env_file)
            _load_env_file(resolved_env_file)
            config_root = resolved_env_file.parent
        env = os.environ
        broker = env.get("BROKER", "simulated").strip().lower()
        if broker != "alpaca":
            raise ValueError("Minimal emergency recovery requires BROKER=alpaca.")
        paper = _bool(env, "ALPACA_PAPER", True)
        # The normal Alpaca deployment is a dedicated account and emergency recovery
        # is account-wide. Ignore a malformed routine universe entirely.
        symbols = DEFAULT_SYMBOLS

        def bounded_int(key: str, default: int, minimum: int, maximum: int) -> int:
            try:
                value = _int(env, key, default)
            except ValueError:
                return default
            return value if minimum <= value <= maximum else default

        result = cls(
            broker="alpaca",
            execution_enabled=True,
            alpaca_paper=paper,
            alpaca_api_key=env.get("ALPACA_API_KEY", "").strip(),
            alpaca_secret_key=env.get("ALPACA_SECRET_KEY", "").strip(),
            alpaca_account_id=env.get("ALPACA_ACCOUNT_ID", "").strip(),
            alpaca_data_feed="iex",
            plan_authentication_key=env.get(
                "PLAN_AUTHENTICATION_KEY",
                "",
            ).strip(),
            emergency_authentication_key=env.get(
                "EMERGENCY_AUTHENTICATION_KEY",
                "",
            ).strip(),
            live_ack="",
            symbols=symbols,
            timezone="America/New_York",
            database_path=_rooted_path(
                env.get("DATABASE_PATH", "runtime/auto_trader.sqlite3"), config_root
            ),
            log_path=_rooted_path(
                env.get("LOG_PATH", "runtime/auto_trader.log"), config_root
            ),
            kill_switch_path=_rooted_path(
                env.get("KILL_SWITCH_PATH", "runtime/KILL_SWITCH"), config_root
            ),
            process_lock_path=_rooted_path(
                env.get("PROCESS_LOCK_PATH", "runtime/auto_trader.lock"), config_root
            ),
            operation_lock_path=_rooted_path(
                env.get("OPERATION_LOCK_PATH", "runtime/auto_trader.operation.lock"),
                config_root,
            ),
            kill_switch_ack_path=_rooted_path(
                env.get("KILL_SWITCH_ACK_PATH", "runtime/KILL_SWITCH.ack.json"),
                config_root,
            ),
            daemon_health_path=_rooted_path(
                env.get("DAEMON_HEALTH_PATH", "runtime/daemon_health.json"),
                config_root,
            ),
            emergency_journal_path=_rooted_path(
                env.get("EMERGENCY_JOURNAL_PATH", "runtime/EMERGENCY_JOURNAL.json"),
                config_root,
            ),
            simulated_state_path=_rooted_path(
                env.get("SIMULATED_STATE_PATH", "runtime/simulated_broker.json"),
                config_root,
            ),
            dedicated_account=True,
            order_fill_timeout_seconds=bounded_int(
                "ORDER_FILL_TIMEOUT_SECONDS", 90, 1, 7_200
            ),
            order_poll_seconds=bounded_int("ORDER_POLL_SECONDS", 2, 1, 300),
            operation_lock_timeout_seconds=bounded_int(
                "OPERATION_LOCK_TIMEOUT_SECONDS", 30, 0, 600
            ),
        )
        if result.order_poll_seconds > result.order_fill_timeout_seconds:
            result = replace(result, order_poll_seconds=1)
        result.validate_emergency()
        return result

    def validate_emergency(self) -> None:
        """Validate only fields required to cancel orders and reduce Alpaca exposure."""

        if self.broker != "alpaca":
            raise ValueError("Emergency broker recovery is only specialized for BROKER=alpaca.")
        if not self.execution_enabled:
            raise ValueError("Emergency flattening requires explicit execution authorization.")
        if not self.alpaca_api_key or not self.alpaca_secret_key:
            raise ValueError("ALPACA_API_KEY and ALPACA_SECRET_KEY are required for emergency recovery.")
        if not _ACCOUNT_ID_PATTERN.fullmatch(self.alpaca_account_id):
            raise ValueError(
                "ALPACA_ACCOUNT_ID is required for emergency recovery and must be an "
                "8-128 character broker account identifier."
            )
        if not self.symbols:
            raise ValueError("At least one configured symbol is required for emergency recovery.")
        invalid_symbols = [
            symbol for symbol in self.symbols if not _SYMBOL_PATTERN.fullmatch(symbol)
        ]
        if invalid_symbols:
            raise ValueError(f"Emergency symbols contain invalid broker identifiers: {invalid_symbols!r}.")
        if not is_strong_emergency_authentication_key(
            self.emergency_authentication_key
        ):
            raise ValueError(
                "Minimal Alpaca emergency recovery requires an independent CSPRNG-generated "
                "64-hex EMERGENCY_AUTHENTICATION_KEY."
            )
        if (
            self.plan_authentication_key
            and self.emergency_authentication_key == self.plan_authentication_key
        ):
            raise ValueError(
                "EMERGENCY_AUTHENTICATION_KEY must be independent from "
                "PLAN_AUTHENTICATION_KEY."
            )
        try:
            ZoneInfo(self.timezone)
        except (ZoneInfoNotFoundError, ValueError) as exc:
            raise ValueError(f"Emergency timezone is not recognized: {self.timezone!r}.") from exc
        _require_int_range("ORDER_FILL_TIMEOUT_SECONDS", self.order_fill_timeout_seconds, 1, 7_200)
        _require_int_range("ORDER_POLL_SECONDS", self.order_poll_seconds, 1, 300)
        if self.order_poll_seconds > self.order_fill_timeout_seconds:
            raise ValueError("ORDER_POLL_SECONDS cannot exceed ORDER_FILL_TIMEOUT_SECONDS.")
        _require_int_range("OPERATION_LOCK_TIMEOUT_SECONDS", self.operation_lock_timeout_seconds, 0, 600)
        emergency_paths = {
            "DATABASE_PATH": self.database_path,
            "LOG_PATH": self.log_path,
            "KILL_SWITCH_PATH": self.kill_switch_path,
            "OPERATION_LOCK_PATH": self.operation_lock_path,
            "KILL_SWITCH_ACK_PATH": self.kill_switch_ack_path,
            "EMERGENCY_JOURNAL_PATH": self.effective_emergency_journal_path,
        }
        normalized = {
            name: Path(path).expanduser().resolve(strict=False)
            for name, path in emergency_paths.items()
        }
        if len(set(normalized.values())) != len(normalized):
            raise ValueError("Emergency database, log, lock, kill, and acknowledgement paths must be distinct.")

    def validate(self) -> None:
        self.strategy.validate()
        # Validate even the optional simulation override so plan authentication never
        # silently accepts malformed key material.
        decode_plan_authentication_key(self.plan_authentication_key)
        decode_emergency_authentication_key(self.emergency_authentication_key)
        if self.broker not in {"simulated", "alpaca"}:
            raise ValueError("BROKER must be 'simulated' or 'alpaca'.")
        if len(self.symbols) < 4 and self.broker != "simulated":
            raise ValueError("At least four symbols are required.")
        if not self.symbols:
            raise ValueError("SYMBOLS must contain at least one symbol.")
        invalid_symbols = [symbol for symbol in self.symbols if not _SYMBOL_PATTERN.fullmatch(symbol)]
        if invalid_symbols:
            raise ValueError(f"SYMBOLS contains invalid broker symbols: {invalid_symbols!r}.")
        if len(set(self.symbols)) != len(self.symbols):
            raise ValueError("SYMBOLS must not contain duplicates.")
        try:
            ZoneInfo(self.timezone)
        except (ZoneInfoNotFoundError, ValueError) as exc:
            raise ValueError(f"STRATEGY_TIMEZONE is not recognized: {self.timezone!r}.") from exc

        portfolio = self.strategy.portfolio
        if portfolio.dollar_neutral and not self.allow_shorting:
            raise ValueError(
                "ALLOW_SHORTING=false is incompatible with the configured dollar-neutral "
                "strategy; a separately validated long-only optimizer is required."
            )
        _require_range("TARGET_VOLATILITY", portfolio.target_volatility, 0.0, 0.50, include_minimum=False)
        _require_range("MAX_GROSS_LEVERAGE", portfolio.max_gross_leverage, 0.0, 4.0, include_minimum=False)
        _require_range("MAX_POSITION_WEIGHT", portfolio.max_position_weight, 0.0, 0.25, include_minimum=False)
        _require_int_range("COVARIANCE_HALFLIFE", portfolio.covariance_halflife, 2, 2_000)
        _require_int_range("REBALANCE_EVERY", portfolio.rebalance_every, 1, 252)
        if (
            self.broker == "alpaca"
            and self.execution_enabled
            and portfolio.rebalance_every != 1
        ):
            raise ValueError(
                "Governed Alpaca execution currently requires REBALANCE_EVERY=1; "
                "non-daily research cadence has no persistent live session anchor."
            )

        signals = self.strategy.signals
        signal_weights = {
            "REVERSAL_3_WEIGHT": signals.reversal_3_weight,
            "REVERSAL_10_WEIGHT": signals.reversal_10_weight,
            "RESIDUAL_REVERSAL_WEIGHT": signals.residual_reversal_weight,
            "MOMENTUM_63_WEIGHT": signals.momentum_63_weight,
            "MOMENTUM_126_WEIGHT": signals.momentum_126_weight,
        }
        for name, value in signal_weights.items():
            _require_range(name, value, 0.0, 10.0)
        if sum(float(value) for value in signal_weights.values()) <= 0:
            raise ValueError("At least one signal weight must be positive.")
        _require_int_range("BETA_LOOKBACK", signals.beta_lookback, 20, 2_000)
        _require_int_range("VOL_LOOKBACK", signals.vol_lookback, 2, 1_000)
        _require_range("SIGNAL_CLIP", signals.signal_clip, 0.0, 20.0, include_minimum=False)

        regime = self.strategy.regime
        _require_int_range("IC_WINDOW", regime.ic_window, 10, 2_000)
        for name, value in {
            "FAVORABLE_IC_TSTAT": regime.favorable_ic_tstat,
            "NEUTRAL_IC_TSTAT": regime.neutral_ic_tstat,
            "INVALID_IC_TSTAT": regime.invalid_ic_tstat,
        }.items():
            _require_range(name, value, -20.0, 20.0)
        if not regime.favorable_ic_tstat >= regime.neutral_ic_tstat > regime.invalid_ic_tstat:
            raise ValueError("IC t-stat thresholds must satisfy favorable >= neutral > invalid.")
        regime_multipliers = (
            regime.favorable_multiplier,
            regime.neutral_multiplier,
            regime.degraded_multiplier,
            regime.invalid_multiplier,
        )
        for name, value in zip(
            ("FAVORABLE_MULTIPLIER", "NEUTRAL_MULTIPLIER", "DEGRADED_MULTIPLIER", "INVALID_MULTIPLIER"),
            regime_multipliers,
        ):
            _require_range(name, value, 0.0, 1.0)
        if list(regime_multipliers) != sorted(regime_multipliers, reverse=True):
            raise ValueError("Regime multipliers must be non-increasing from favorable to invalid.")
        _require_range("VOLATILITY_STRESS_PERCENTILE", regime.volatility_stress_percentile, 0.50, 1.0, include_maximum=False)
        _require_range("MINIMUM_CROSS_SECTIONAL_DISPERSION", regime.minimum_cross_sectional_dispersion, 0.0, 20.0, include_minimum=False)

        risk = self.strategy.risk
        drawdown_limits = (
            risk.throttle_drawdown,
            risk.defensive_drawdown,
            risk.severe_drawdown,
            risk.flatten_drawdown,
            risk.hard_drawdown_limit,
        )
        for name, value in zip(
            ("THROTTLE_DRAWDOWN", "DEFENSIVE_DRAWDOWN", "SEVERE_DRAWDOWN", "FLATTEN_DRAWDOWN", "HARD_DRAWDOWN_LIMIT"),
            drawdown_limits,
        ):
            _require_range(name, value, 0.0, 0.75, include_minimum=False)
        if list(drawdown_limits) != sorted(drawdown_limits) or len(set(drawdown_limits)) != len(drawdown_limits):
            raise ValueError("Drawdown controls must be strictly increasing through HARD_DRAWDOWN_LIMIT.")
        risk_multipliers = (risk.throttle_multiplier, risk.defensive_multiplier, risk.severe_multiplier)
        for name, value in zip(
            ("THROTTLE_MULTIPLIER", "DEFENSIVE_MULTIPLIER", "SEVERE_MULTIPLIER"),
            risk_multipliers,
        ):
            _require_range(name, value, 0.0, 1.0)
        if list(risk_multipliers) != sorted(risk_multipliers, reverse=True):
            raise ValueError("Risk multipliers must be non-increasing as drawdown worsens.")
        _require_int_range("COOLDOWN_SESSIONS", risk.cooldown_days, 1, 2_000)
        _require_range("DAILY_LOSS_TRIGGER", risk.daily_loss_trigger, 0.0, 0.50, include_minimum=False)
        _require_range("FIVE_DAY_LOSS_TRIGGER", risk.five_day_loss_trigger, 0.0, 0.75, include_minimum=False)
        _require_range("LOSS_SHOCK_MULTIPLIER", risk.loss_shock_multiplier, 0.0, 1.0)

        costs = self.strategy.costs
        _require_range("TRANSACTION_COST_BPS", costs.transaction_cost_bps, 0.0, 1_000.0)
        _require_range("ANNUAL_SHORT_BORROW_RATE", costs.annual_short_borrow_rate, 0.0, 2.0)
        _require_range("ANNUAL_FINANCING_RATE", costs.annual_financing_rate, 0.0, 2.0)
        if self.broker == "alpaca" and (not self.alpaca_api_key or not self.alpaca_secret_key):
            raise ValueError("ALPACA_API_KEY and ALPACA_SECRET_KEY are required for BROKER=alpaca.")
        if (
            self.broker == "alpaca"
            and self.execution_enabled
            and not _ACCOUNT_ID_PATTERN.fullmatch(self.alpaca_account_id)
        ):
            raise ValueError(
                "ALPACA_ACCOUNT_ID is required for Alpaca execution and must be an "
                "8-128 character broker account identifier."
            )
        if self.broker == "alpaca" and not is_strong_plan_authentication_key(
            self.plan_authentication_key
        ):
            raise ValueError(
                "BROKER=alpaca requires a CSPRNG-generated 64-hex "
                "PLAN_AUTHENTICATION_KEY, including plan-only mode; the fixed "
                "simulation key and weak placeholders are forbidden."
            )
        if self.broker == "alpaca" and not is_strong_emergency_authentication_key(
            self.emergency_authentication_key
        ):
            raise ValueError(
                "BROKER=alpaca requires an independent CSPRNG-generated 64-hex "
                "EMERGENCY_AUTHENTICATION_KEY in every mode."
            )
        if (
            self.broker == "alpaca"
            and self.emergency_authentication_key == self.plan_authentication_key
        ):
            raise ValueError(
                "EMERGENCY_AUTHENTICATION_KEY must be independent from "
                "PLAN_AUTHENTICATION_KEY."
            )
        if self.broker == "alpaca" and not self.alpaca_paper and self.execution_enabled:
            if self.live_ack != LIVE_ACK_TEXT:
                raise ValueError(
                    "Live order submission is locked. Set LIVE_TRADING_ACK exactly to "
                    f"{LIVE_ACK_TEXT!r} only after paper validation."
                )
        if self.broker == "alpaca" and self.execution_enabled and not self.dedicated_account:
            raise ValueError(
                "Alpaca order submission requires DEDICATED_ACCOUNT=true, including paper "
                "trading, because account-level equity, buying power, drawdown, and kill "
                "controls cannot isolate unrelated positions."
            )
        _require_int_range("EXECUTION_WINDOW_MINUTES", self.execution_window_minutes, 1, 180)
        if self.broker == "alpaca":
            if self.timezone != "America/New_York":
                raise ValueError(
                    "BROKER=alpaca requires STRATEGY_TIMEZONE=America/New_York so session "
                    "and completed-bar boundaries are unambiguous."
                )
            if self.plan_time < time(16, 5):
                raise ValueError(
                    "BROKER=alpaca requires PLAN_TIME at or after 16:05 America/New_York "
                    "to avoid a still-forming regular-session daily bar."
                )
            execution_start = self.execution_time.hour * 60 + self.execution_time.minute
            execution_end = execution_start + self.execution_window_minutes
            if execution_start < 9 * 60 + 30:
                raise ValueError(
                    "BROKER=alpaca requires EXECUTION_TIME at or after the 09:30 regular open."
                )
            if execution_end > 15 * 60 + 55:
                raise ValueError(
                    "BROKER=alpaca requires the execution window to end by 15:55 "
                    "America/New_York, preserving a close buffer."
                )
        _require_int_range("POLL_SECONDS", self.poll_seconds, 1, 3_600)
        _require_int_range("SCHEDULER_RETRY_MINUTES", self.scheduler_retry_minutes, 1, 120)
        _require_int_range("HISTORY_BARS", self.history_bars, 253, 20_000)
        _require_int_range("MINIMUM_ASSETS", self.minimum_assets, 1, 10_000)
        if self.minimum_assets > len(self.symbols) and self.broker != "simulated":
            raise ValueError("MINIMUM_ASSETS cannot exceed the configured SYMBOLS count.")
        if self.broker == "alpaca" and self.execution_enabled:
            if self.execution_time != GOVERNED_EXECUTION_START:
                raise ValueError(
                    "Governed Alpaca execution requires EXECUTION_TIME=09:30 "
                    "America/New_York to match the sealed VWAP benchmark."
                )
            if self.execution_window_minutes != GOVERNED_EXECUTION_WINDOW_MINUTES:
                raise ValueError(
                    "Governed Alpaca execution requires EXECUTION_WINDOW_MINUTES=5; "
                    "09:35 is an exclusive hard deadline."
                )
            if self.minimum_assets < GOVERNED_MINIMUM_ASSETS:
                raise ValueError(
                    "Governed Alpaca execution requires MINIMUM_ASSETS>=20 to match "
                    "the sealed effective OOS breadth gate."
                )
        _require_int_range("MAX_DATA_AGE_DAYS", self.max_data_age_days, 0, 30)
        _require_int_range("MAX_PLAN_AGE_DAYS", self.max_plan_age_days, 0, 30)
        covariance_trust = {
            "COVARIANCE_EVIDENCE_PATH": self.covariance_evidence_path,
            "COVARIANCE_EXECUTION_PRICES_PATH": self.covariance_execution_prices_path,
            "COVARIANCE_CORPORATE_ACTIONS_PATH": self.covariance_corporate_actions_path,
            "COVARIANCE_GOVERNANCE_PUBLIC_KEYS_PATH": self.covariance_public_keys_path,
            "COVARIANCE_GOVERNANCE_PUBLIC_KEYS_SHA256": (
                self.covariance_public_keys_sha256 or None
            ),
            "COVARIANCE_PROVIDER_ID": self.covariance_provider_id or None,
            "COVARIANCE_VENUE_ID": self.covariance_venue_id or None,
        }
        configured_covariance_trust = {
            name: value for name, value in covariance_trust.items() if value is not None
        }
        if configured_covariance_trust and len(configured_covariance_trust) != len(
            covariance_trust
        ):
            missing = sorted(set(covariance_trust).difference(configured_covariance_trust))
            raise ValueError(
                "Signed covariance evidence configuration is incomplete; missing "
                + ", ".join(missing)
                + "."
            )
        if (
            self.broker == "alpaca"
            and self.execution_enabled
            and len(configured_covariance_trust) != len(covariance_trust)
        ):
            raise ValueError(
                "Governed Alpaca execution requires all seven signed covariance "
                "evidence paths, registry pin, and provider/venue identity settings."
            )
        if self.covariance_public_keys_sha256 and not _SHA256_PATTERN.fullmatch(
            self.covariance_public_keys_sha256
        ):
            raise ValueError(
                "COVARIANCE_GOVERNANCE_PUBLIC_KEYS_SHA256 must be a pinned lowercase "
                "SHA-256 digest."
            )
        for name, value in (
            ("COVARIANCE_PROVIDER_ID", self.covariance_provider_id),
            ("COVARIANCE_VENUE_ID", self.covariance_venue_id),
        ):
            if value and not _ACCOUNT_ID_PATTERN.fullmatch(value):
                raise ValueError(
                    f"{name} must be an 8-128 character governed identifier."
                )
        borrow_trust = {
            "BORROW_EVIDENCE_PATH": self.borrow_evidence_path,
            "BORROW_TERMS_PATH": self.borrow_terms_path,
            "BORROW_GOVERNANCE_PUBLIC_KEYS_PATH": self.borrow_public_keys_path,
            "BORROW_GOVERNANCE_PUBLIC_KEYS_SHA256": (
                self.borrow_public_keys_sha256 or None
            ),
            "BORROW_PROVIDER_ID": self.borrow_provider_id or None,
            "BORROW_VENUE_ID": self.borrow_venue_id or None,
        }
        configured_borrow_trust = {
            name: value for name, value in borrow_trust.items() if value is not None
        }
        if configured_borrow_trust and len(configured_borrow_trust) != len(borrow_trust):
            missing = sorted(set(borrow_trust).difference(configured_borrow_trust))
            raise ValueError(
                "Signed live-borrow evidence configuration is incomplete; missing "
                + ", ".join(missing)
                + "."
            )
        if (
            self.broker == "alpaca"
            and self.execution_enabled
            and len(configured_borrow_trust) != len(borrow_trust)
        ):
            raise ValueError(
                "Governed Alpaca execution requires every signed live-borrow evidence "
                "path, registry pin, and provider/venue identity setting."
            )
        if self.borrow_public_keys_sha256 and not _SHA256_PATTERN.fullmatch(
            self.borrow_public_keys_sha256
        ):
            raise ValueError(
                "BORROW_GOVERNANCE_PUBLIC_KEYS_SHA256 must be a pinned lowercase "
                "SHA-256 digest."
            )
        for name, value in (
            ("BORROW_PROVIDER_ID", self.borrow_provider_id),
            ("BORROW_VENUE_ID", self.borrow_venue_id),
        ):
            if value and not _ACCOUNT_ID_PATTERN.fullmatch(value):
                raise ValueError(
                    f"{name} must be an 8-128 character governed identifier."
                )
        _require_int_range(
            "BORROW_MAX_TERM_AGE_SECONDS",
            self.borrow_max_term_age_seconds,
            1,
            300,
        )
        _require_range(
            "MAX_LIVE_ANNUAL_BORROW_RATE",
            self.max_live_annual_borrow_rate,
            0.0,
            2.0,
        )
        if (
            self.max_live_annual_borrow_rate
            > self.strategy.costs.annual_short_borrow_rate + 1e-12
        ):
            raise ValueError(
                "MAX_LIVE_ANNUAL_BORROW_RATE cannot exceed the annual short-borrow "
                "rate in the sealed deployment strategy. Approve a more conservative "
                "research/deployment assumption before admitting higher-rate shorts."
            )
        _require_range("SIMULATED_STARTING_CASH", self.simulated_starting_cash, 0.0, 1e15, include_minimum=False)
        _require_range("SIMULATED_SLIPPAGE_BPS", self.simulated_slippage_bps, 0.0, 1_000.0)
        _require_range("MIN_TRADE_NOTIONAL", self.min_trade_notional, 0.0, 1e12)
        _require_range("MAX_SINGLE_ORDER_NOTIONAL_PCT", self.max_single_order_notional_pct, 0.0, 1.0, include_minimum=False)
        _require_range("BUYING_POWER_BUFFER", self.buying_power_buffer, 0.0, 1.0, include_maximum=False)
        _require_int_range("ORDER_FILL_TIMEOUT_SECONDS", self.order_fill_timeout_seconds, 1, 7_200)
        _require_int_range("ORDER_POLL_SECONDS", self.order_poll_seconds, 1, 300)
        if self.order_poll_seconds > self.order_fill_timeout_seconds:
            raise ValueError("ORDER_POLL_SECONDS cannot exceed ORDER_FILL_TIMEOUT_SECONDS.")
        _require_int_range(
            "MAX_EXECUTION_PRICE_AGE_SECONDS",
            self.max_execution_price_age_seconds,
            1,
            3_600,
        )
        _require_range(
            "MAX_EXECUTION_SPREAD_BPS",
            self.max_execution_spread_bps,
            0.0,
            1_000.0,
            include_minimum=False,
        )
        _require_range(
            "MARKETABLE_LIMIT_COLLAR_BPS",
            self.marketable_limit_collar_bps,
            0.0,
            1_000.0,
            include_minimum=False,
        )
        if self.marketable_limit_collar_bps < self.max_execution_spread_bps / 2.0:
            raise ValueError(
                "MARKETABLE_LIMIT_COLLAR_BPS must be at least half of "
                "MAX_EXECUTION_SPREAD_BPS so every accepted quote can produce a "
                "marketable order before conservative tick rounding."
            )
        _require_int_range("MAX_ORDERS_PER_CYCLE", self.max_orders_per_cycle, 1, 10_000)
        _require_range("RESIDUAL_NOTIONAL_TOLERANCE", self.residual_notional_tolerance, 0.0, 1e12)
        _require_int_range("OPERATION_LOCK_TIMEOUT_SECONDS", self.operation_lock_timeout_seconds, 0, 600)
        _require_int_range("HEALTH_FAILURE_THRESHOLD", self.health_failure_threshold, 1, 100)
        _require_int_range(
            "DAEMON_WATCHDOG_TIMEOUT_SECONDS",
            self.daemon_watchdog_timeout_seconds,
            120,
            86_400,
        )
        # Multi-order loops publish progress after every successful broker round trip,
        # so order count does not multiply this bound. Three full fill-timeout windows
        # cover one cancel/reconcile transition plus scheduling margin while a single
        # genuinely stuck dependency call still forces restart.
        minimum_watchdog = (
            self.order_fill_timeout_seconds * 3 + self.poll_seconds + 60
        )
        if self.daemon_watchdog_timeout_seconds < minimum_watchdog:
            raise ValueError(
                "DAEMON_WATCHDOG_TIMEOUT_SECONDS must be at least "
                f"{minimum_watchdog} for the configured order timeout and poll interval."
            )
        _require_range(
            "ACTUAL_GROSS_EXPOSURE_TOLERANCE",
            self.actual_gross_exposure_tolerance,
            0.0,
            1.0,
        )
        _require_range(
            "ACTUAL_NET_EXPOSURE_LIMIT",
            self.actual_net_exposure_limit,
            0.0,
            1.0,
            include_minimum=False,
        )
        _require_range(
            "ACTUAL_BETA_EXPOSURE_LIMIT",
            self.actual_beta_exposure_limit,
            0.0,
            2.0,
            include_minimum=False,
        )
        _require_range(
            "ACTUAL_POSITION_WEIGHT_TOLERANCE",
            self.actual_position_weight_tolerance,
            0.0,
            1.0,
        )

        operational_paths = {
            "DATABASE_PATH": self.database_path,
            "LOG_PATH": self.log_path,
            "KILL_SWITCH_PATH": self.kill_switch_path,
            "PROCESS_LOCK_PATH": self.process_lock_path,
            "OPERATION_LOCK_PATH": self.operation_lock_path,
            "KILL_SWITCH_ACK_PATH": self.kill_switch_ack_path,
            "DAEMON_HEALTH_PATH": self.daemon_health_path,
            "EMERGENCY_JOURNAL_PATH": self.effective_emergency_journal_path,
            "SIMULATED_STATE_PATH": self.simulated_state_path,
        }
        for name, path in {
            "COVARIANCE_EVIDENCE_PATH": self.covariance_evidence_path,
            "COVARIANCE_EXECUTION_PRICES_PATH": self.covariance_execution_prices_path,
            "COVARIANCE_CORPORATE_ACTIONS_PATH": self.covariance_corporate_actions_path,
            "COVARIANCE_GOVERNANCE_PUBLIC_KEYS_PATH": self.covariance_public_keys_path,
            "BORROW_EVIDENCE_PATH": self.borrow_evidence_path,
            "BORROW_TERMS_PATH": self.borrow_terms_path,
            "BORROW_GOVERNANCE_PUBLIC_KEYS_PATH": self.borrow_public_keys_path,
        }.items():
            if path is not None:
                operational_paths[name] = path
        normalized = {name: Path(path).expanduser().resolve(strict=False) for name, path in operational_paths.items()}
        if len(set(normalized.values())) != len(normalized):
            duplicates: dict[Path, list[str]] = {}
            for name, path in normalized.items():
                duplicates.setdefault(path, []).append(name)
            collided = [names for names in duplicates.values() if len(names) > 1]
            raise ValueError(f"Operational paths must be distinct; collisions: {collided!r}.")

    @property
    def mode_label(self) -> str:
        if self.broker == "simulated":
            return "simulated-execution" if self.execution_enabled else "simulated-plan-only"
        if self.alpaca_paper:
            return "alpaca-paper" if self.execution_enabled else "alpaca-paper-plan-only"
        return "alpaca-live" if self.execution_enabled else "alpaca-live-plan-only"
