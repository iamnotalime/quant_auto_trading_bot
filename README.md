# Quant Auto Trading Bot

An always-on, market-neutral quantitative trading service built around the research engine in this package. It can automatically:

1. monitor account equity and drawdown;
2. retrieve completed daily market data;
3. generate a multi-signal target portfolio after the market close;
4. persist and audit the plan in SQLite;
5. rebalance through a broker during the next trading session;
6. reduce existing risk before opening new risk;
7. reconcile fills against target quantities;
8. cancel stale managed orders; and
9. flatten managed positions when a kill switch or risk shutdown fires.

The package includes:

- an offline simulated broker;
- an Alpaca paper/live broker adapter using the official `alpaca-py` SDK;
- an independent daemon that keeps running when the browser is closed;
- an operations dashboard;
- the original Streamlit research and backtesting application;
- Docker Compose and systemd deployment examples; and
- automated tests for execution and shutdown paths.

## Important scope

This is a **public-methodology, Renaissance-inspired architecture**, not Renaissance Technologies software. It has no access to Renaissance's proprietary models, data, execution infrastructure, financing, or research process. The included signal engine operates on completed daily bars; it is not a high-frequency Medallion replica.

The repository also contains a separate dependency-free Rust kernel under
[`hft_core/`](hft_core/README.md). That kernel is the only intended latency-critical path;
the Python/Alpaca daemon below remains lower-frequency execution and must not be described
as HFT. The Rust layer is venue-neutral and cannot honestly be called live HFT until an
exact native market-data/order-entry protocol is implemented, conformance-tested, and
measured on target NIC, clock-synchronization, and deployment infrastructure.

The software does **not** guarantee profitability, a 60% CAGR, a 15% maximum live drawdown, or any level of prediction accuracy. A drawdown stop can be exceeded because of gaps, rejected orders, outages, or illiquidity. The 12% flatten threshold is deliberately below the configured 15% hard breach to provide a buffer, not a guarantee.

The exact software, sealed-research, deployment, and profit-evidence gates are defined in
[`INSTITUTIONAL_READINESS.md`](INSTITUTIONAL_READINESS.md). Synthetic data can never
receive research certification. A sealed result requires a trusted, externally anchored
and signed preregistration manifest; a first-use OOS date interval that is consumed across
exploratory/sealed modes, data edits, universes, and chronological splits; exact execution, factor,
calendar, corporate-action, borrow, and liquidity evidence; measured costs; stable
data-family/overlap identities; a persistent effective-trial ledger; and every
statistical/economic robustness check to pass. Editing prices or adding ancillary evidence
after viewing an interval cannot restore first-use status. Without the deployment-pinned governance key
registry, sealed certification is unavailable.
The sealed label cannot be made easier by lowering the app's stated project hurdle: it
requires a configured target of at least 60% CAGR and no more than 15% maximum drawdown.
Those are falsifiable rejection thresholds for this project, not promised live results.

## Safe defaults

The default configuration is deliberately harmless:

```text
BROKER=simulated
EXECUTION_ENABLED=false
```

That mode calculates and previews orders but cannot transmit them to a real broker. Live order submission is additionally locked behind an exact acknowledgement phrase.

## Architecture

```text
Completed daily bars
        │
        ▼
Multi-signal ensemble
  • 3-day reversal
  • 10-day reversal
  • residual reversal
  • 63-day momentum
  • 126-day momentum
        │
        ▼
Signal-health regime
  • rolling information coefficient
  • volatility stress
  • cross-sectional dispersion
        │
        ▼
Market-/beta-neutral target weights
  • inverse volatility
  • EWMA covariance
  • target volatility
  • position and gross caps
        │
        ▼
Persistent target plan in SQLite
        │
        ▼
Two-phase execution
  1. cancel stale managed orders
  2. close/reduce/sign-flip positions
  3. re-check account risk and buying power
  4. open/increase positions
  5. reconcile actual versus target quantities
        │
        ▼
Continuous monitoring and shutdown controls
```

The research dashboard and the trading daemon are separate processes. Closing Streamlit does not stop the daemon, and restarting Streamlit cannot bypass the daemon's persistent risk state.

## Automated daily timing

The defaults use New York time:

```text
16:15 ET             Generate a plan from completed daily bars
09:30 <= time <09:35 Execute only the plan signed for that exact exchange session
09:35 ET             Hard stop: cancel/reconcile; never start or retry a routine child
Every 60s            Monitor equity, drawdown, account state, open orders, and kill switch
```

The planning and execution stages are separated deliberately. Governed evidence signs the
exact next exchange session; a missed plan is expired rather than carried into a later
session. The 09:30-09:35 VWAP is the sealed research benchmark and capacity/risk-model
window, not a promise that live orders receive VWAP. Backtests deduct modeled costs, while
realized slippage, queue position, impact, and broker-statement reconciliation remain
external evidence that must be measured independently.

Market holidays and the exact signed next session are cross-checked against the broker
clock. Plans are deterministic and unique by completed session, which prevents repeated
generation after a restart. Client order IDs are deterministic, which reduces duplicate
order risk when a request is retried. Before every order, the Alpaca adapter verifies the
client ID; a broker lookup outage blocks submission instead of risking a duplicate. Routine
Alpaca rebalances use IOC marketable-limit orders capped at
`MARKETABLE_LIMIT_COLLAR_BPS` from a fresh, spread-checked quote midpoint. The engine and
the final pre-REST broker authorization both enforce the exclusive 09:35 deadline, and
receipt/stable-state reconciliation cancels any nonterminal routine child at that boundary.
Emergency flattening deliberately uses a separate true-market path because leaving exposure
open behind an obsolete limit can be the greater risk. If the daemon restarts while a plan
is marked `executing`, it fails closed by halting, canceling managed orders, and flattening
managed positions for manual review.

## Risk controls

Default controls include:

| Control | Default |
|---|---:|
| Target annualized volatility | 8% |
| Maximum gross leverage | 1.50× |
| Maximum position weight | 8% NAV |
| Start drawdown throttling | 4% |
| Defensive drawdown level | 7% |
| Severe drawdown level | 9% |
| Flatten managed positions | 12% |
| Hard breach flag | 15% |
| Daily-loss shutdown | 2% |
| Five-day-loss shutdown | 4% |
| Cooldown | 20 completed sessions |
| Buffered buying power | 90% of reported buying power |

A risk shutdown is persistent by default. The system does not automatically resume merely because the clock moved forward. Human review and the explicit CLI acknowledgement are required.

In a non-dedicated account, the bot only cancels bot-managed orders and closes managed strategy symbols; it does not intentionally liquidate unrelated manual positions. In `DEDICATED_ACCOUNT=true` mode, an emergency shutdown cancels every open account order and closes every open position. A dedicated brokerage account is required for live submission because buying power, margin, and account-level equity are shared across all positions.

## Project layout

```text
bot.py                         CLI and daemon entry point
bot_dashboard.py               Operations console and emergency halt control
app.py                         Research/backtest Streamlit app
auto_trader/
  config.py                    Environment configuration and live locks
  daemon.py                    Always-on scheduler and process lock
  engine.py                    Planning, execution, reconciliation, shutdowns
  risk.py                      Drawdown/loss/account risk decisions
  store.py                     SQLite persistence and audit trail
  strategy.py                  Live target-plan construction
  brokers/
    base.py                    Broker interface
    simulated.py               Offline persistent immediate-fill broker
    alpaca.py                  Official Alpaca SDK adapter
quant_app/                     Research signals, backtest, metrics, validation
  attribution.py              HAC factor-alpha attribution
  experiment.py               Persistent tamper-evident trial/holdout ledger
  governance.py               Signed manifests, trust pins, and stale-result binding
hft_core/                     Separate preallocated Rust execution kernel (venue-neutral)
runtime/                       Database, logs, broker state, kill switch
INSTITUTIONAL_READINESS.md     Acceptance gates and remaining external evidence
```

## Install locally

Python 3.11–3.13 is recommended.

### macOS or Linux

```bash
cd quant_auto_trading_bot
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install --require-hashes -r requirements.lock
cp .env.example .env
```

### Windows

```bat
cd quant_auto_trading_bot
python -m venv .venv
.venv\Scripts\activate
python -m pip install --upgrade pip
python -m pip install --require-hashes -r requirements.lock
copy .env.example .env
```

`requirements.lock` is the production source of truth used by local installs and all
three container images. Every resolved artifact is pinned and hashed. Development and
CI use `requirements-dev.lock`, which includes the production graph. The corresponding
`.in` files are the human-edited inputs; regenerate both locks deliberately after a
dependency change:

```bash
python -m piptools compile --generate-hashes --strip-extras --resolver=backtracking --output-file=requirements.lock requirements.in
python -m piptools compile --allow-unsafe --generate-hashes --strip-extras --resolver=backtracking --output-file=requirements-dev.lock requirements-dev.in
```

## Offline simulation walkthrough

Leave these settings in `.env`:

```text
BROKER=simulated
EXECUTION_ENABLED=false
```

Validate all connections and files:

```bash
python bot.py doctor
```

Generate a target plan:

```bash
python bot.py plan
```

Preview the orders without submitting them:

```bash
python bot.py execute --force
```

Enable only the offline simulated fills:

```text
EXECUTION_ENABLED=true
```

Then run an end-to-end simulated cycle:

```bash
python bot.py cycle
```

Start the always-on scheduler:

```bash
python bot.py daemon
```

Open the operations console in another terminal:

```bash
streamlit run bot_dashboard.py --server.port 8502
```

Open the research lab separately:

```bash
streamlit run app.py --server.port 8501
```

`sample_prices.csv` contains synthetic demonstration data. Its results are not evidence of an investable edge.

## Alpaca paper trading

Create an Alpaca paper account and use its paper credentials. Update `.env`:

```text
BROKER=alpaca
ALPACA_PAPER=true
ALPACA_API_KEY=your_paper_key
ALPACA_SECRET_KEY=your_paper_secret
ALPACA_ACCOUNT_ID=your_independently_verified_paper_account_id
PLAN_AUTHENTICATION_KEY=<64 lowercase hex characters from a CSPRNG>
EMERGENCY_AUTHENTICATION_KEY=<a different 64-hex CSPRNG secret>
EXECUTION_ENABLED=false
```

Generate both authentication keys independently with
`python -c "import secrets; print(secrets.token_hex(32))"`. Treat them like broker
secrets: do not commit or log them. Do not rotate the plan key while its state database
is active, or the emergency key while its journal is active. Only SHA-256 fingerprints
are included in signed deployment configuration.

Start with connectivity and plan-only checks:

```bash
python bot.py doctor
python bot.py plan
python bot.py status
```

After reviewing the generated plan, enable paper orders:

```text
EXECUTION_ENABLED=true
DEPLOYMENT_APPROVAL_PATH=runtime/governance/deployment-approval.json
DEPLOYMENT_GOVERNANCE_PUBLIC_KEYS_PATH=runtime/governance/deployment-keys.json
DEPLOYMENT_GOVERNANCE_PUBLIC_KEYS_SHA256=<independently pinned lowercase SHA-256>
COVARIANCE_EVIDENCE_PATH=runtime/governance/covariance-envelope.json
COVARIANCE_EXECUTION_PRICES_PATH=runtime/governance/execution-window-vwap.csv
COVARIANCE_CORPORATE_ACTIONS_PATH=runtime/governance/corporate-actions.csv
COVARIANCE_GOVERNANCE_PUBLIC_KEYS_PATH=runtime/governance/covariance-keys.json
COVARIANCE_GOVERNANCE_PUBLIC_KEYS_SHA256=<independently pinned lowercase SHA-256>
COVARIANCE_PROVIDER_ID=<signed provider identity>
COVARIANCE_VENUE_ID=<signed execution venue identity>
BORROW_EVIDENCE_PATH=runtime/governance/borrow-envelope.json
BORROW_TERMS_PATH=runtime/governance/borrow-terms.csv
BORROW_GOVERNANCE_PUBLIC_KEYS_PATH=runtime/governance/borrow-keys.json
BORROW_GOVERNANCE_PUBLIC_KEYS_SHA256=<independently pinned lowercase SHA-256>
BORROW_PROVIDER_ID=<signed borrow provider identity>
BORROW_VENUE_ID=<signed locate venue identity>
BORROW_MAX_TERM_AGE_SECONDS=300
MAX_LIVE_ANNUAL_BORROW_RATE=0.02
```

Paper and live orders are fail-closed behind the same signed v2 deployment approval, whose
lifetime cannot exceed seven days. Its exact schema binds the full `AppConfig` object and
hash, all non-secret daemon-policy settings, research/runtime identity, current research and
execution source hashes, deployment descriptors, the pinned container base-image digest,
`requirements.lock`, sealed-manifest/result bundle/specification hashes with
`status=passed`, paper/live mode, and Alpaca account ID. The app authenticates the signature
with the pinned registry, then compares the account ID returned by Alpaca with the separately
configured `ALPACA_ACCOUNT_ID` before it opens trading state. After duplicate-ID lookup and
fresh-quote construction, the adapter rechecks the kill marker, signed approval, and fresh
actual broker account identity immediately before the mutating REST submission.

Persisted plans are content-addressed over all economic fields and metadata, authenticated
with HMAC-SHA-256, and bound to the exact strategy/bot configuration, approved symbol
universe, deployment approval, and authenticated account. A database rewrite with a
recomputed public plan ID still fails without `PLAN_AUTHENTICATION_KEY`; legacy unkeyed plans
are rejected. Changing any bound input or replacing the approval requires a newly reviewed
approval and a newly generated plan. This control prevents unauthorized deployment or
stale-plan drift; it does not establish future profitability.

An emergency `kill` is deliberately risk-reducing even when the approval or routine strategy
configuration is expired, malformed, or damaged. It still requires the independent account
pin and creates an emergency-only broker adapter whose routine-order method stays disabled.
`kill --no-flatten` confirms cancellation of relevant open orders without closing positions;
the default kill also reconciles positions to flat. If authoritative live state is
unavailable, reconciliation uses a separate
`*.emergency-recovery.sqlite3` ledger and does not recreate the missing live database, so
normal live startup continues to fail closed until state is restored and independently
reconciled. If the routine plan-authentication key is missing or malformed, emergency
reduction never opens the authoritative database unauthenticated: it uses the fixed recovery
ledger with a domain-separated key derived from the independent emergency key. The
authenticated emergency journal is outside SQLite; its stable marker incident UUID and
pre-submit client-order records preserve idempotency across state loss and restarts. Its
keyed identity and tail-checkpoint sidecars reject single-file deletion and replay; an
unresolved authenticated incident also overrides a rewritten marker UUID before submission.

Governed Alpaca planning does not substitute adjusted daily closes for the sealed risk
model. It requires the same authenticated 09:30-09:35 raw VWAP history plus complete
split-ratio and cash-distribution panels, then reconstructs the 251 economic returns used
by sealed covariance. Eligibility additionally requires 253 complete VWAP observations,
matching sealed research's 252-lagged-return re-entry quarantine. Exact evidence/provenance hashes are authenticated in the target plan;
without that bundle, plan generation fails closed. Daily-close covariance remains an
explicitly uncertified simulated/exploratory mode. Sealed certification and governed live
cadence are daily only (`rebalance_every=1`) until a persistent shared anchor exists.

The covariance envelope has strict schema version 2 and purpose
`governed_covariance_evidence_v2`. Its RSA/PKCS#1-v1.5/SHA-256 signature covers only a
canonical JSON payload whose exact fields bind `snapshot_id`, configured `provider_id` and
`venue_id`, UTC issuance/expiry, America/New_York 09:30 decision and 09:35 VWAP semantics,
first/latest session, the exact intended `next_session`, observation count, ordered symbols,
and SHA-256 hashes of both source
files. The wide VWAP CSV must be a complete finite positive Date-by-symbol panel. The
long-form action CSV must contain exactly `Date`, `Asset`, `AsOfTimestamp`, `SplitRatio`, and
`CashDistributionPerPreActionShare`, with one explicit row for every session/symbol and a
same-session, offset-aware as-of time no later than 09:30 New York. At least 253 complete
observations are required; the shared risk forecast uses the trailing 252 prices/251 returns.
Expiry must be strictly later than the signed next session's 09:35 endpoint. At execution,
the daemon reloads the provider bundle, re-verifies its signature/freshness, requires exact
provenance and panel hashes to match the authenticated plan, and advances the monotonic
anchor again before any routine broker mutation.

For Compose, the four configured file paths must be container paths such as
`/app/deployment/covariance-envelope.json`, not host paths. Place the corresponding files in
`DEPLOYMENT_GOVERNANCE_HOST_DIR`; Compose mounts that directory read-only. Rotate a snapshot
with a single writer: fsync versioned temporary files, atomically rename the two data files
first, and atomically rename the signed envelope last. A process racing the rotation sees a
hash mismatch and fails closed. After verification, the daemon writes
`latest_session`, `issued_at`, `snapshot_id`, and `payload_sha256` to its HMAC-authenticated
state before plan construction; older signed evidence and same-time payload substitution are
rejected. Rolling back the evidence directory together with the complete authenticated state
and its external checkpoint is outside the local trust boundary and still requires an
independent signer, append-only/WORM retention, and operational reconciliation.

### Signed live borrow evidence

Every order-enabled Alpaca process also requires a strict schema-1 envelope with purpose
`governed_live_borrow_evidence_v1`. Its RSA/PKCS#1-v1.5/SHA-256 signature and independently
pinned registry bind the exact provider, venue, Alpaca account, execution session, ordered
configured universe, issuance/expiry, locate/rate/recall definitions, row count, and the
SHA-256 hash of the exact terms file. The CSV header must be exactly
`Session,Symbol,AsOfTimestamp,Available,AvailableQuantity,AnnualRate,Recalled`, with one
ordered row for every signed symbol. Boolean values are exactly `true` or `false`; rates and
share quantities must be finite and nonnegative; availability requires positive located
quantity, and a recalled term cannot also be available.

Each term must be point-in-time for the exact intended session, no later than 09:30 New
York, no more than `BORROW_MAX_TERM_AGE_SECONDS` old, and never future-dated. Verification
is valid only during `09:30 <= time < 09:35`; the envelope must remain valid beyond 09:35
and may cover no more than 24 hours. The broker timestamp must remain within five seconds
of the independent process clock before and after verification. Missing symbols, unavailable locates, recalls, and
rates above `MAX_LIVE_ANNUAL_BORROW_RATE`, or located share quantity below the current,
planned, projected, or conservative sell-child requirement reject the affected short. The
live ceiling itself may not exceed the approved strategy's sealed
`ANNUAL_SHORT_BORROW_RATE`; admitting a higher rate requires more conservative sealed
research and a new deployment approval.

The provider is reloaded and authenticated before the first routine broker mutation,
including managed-order cancellation, and again at the final pre-REST boundary for every
child. Any missing, stale, malformed, rolled-back, or policy-rejecting evidence persists a
flattening halt and invokes the separate account-wide emergency-reduction path. Emergency
orders deliberately do not depend on borrow evidence, so a failed evidence provider cannot
trap existing exposure.

For Compose, use `/app/deployment/...` for all three borrow file paths and place the files
under `DEPLOYMENT_GOVERNANCE_HOST_DIR`. Publish a new generation with a single writer: fsync
and atomically rename the terms file first, then the signed envelope. The daemon records
the verified provenance and advances per-symbol observation clocks in HMAC-authenticated
state, rejecting session/issuance rollback, same-time substitution, and a later-issued
snapshot that regresses even one symbol's clock. Coordinated rollback
of the evidence directory plus the complete database and all authentication sidecars is
outside this local trust boundary; use independent signing, append-only/WORM retention, and
broker/locate reconciliation.

Then start the daemon:

```bash
python bot.py daemon
```

Paper trading should be run through multiple market regimes and operational failure drills before live trading is considered. Paper fills still do not reproduce live queue position, market impact, borrow availability, or financing.

## Live trading lock

Live submission requires all of the following settings:

```text
BROKER=alpaca
ALPACA_PAPER=false
EXECUTION_ENABLED=true
LIVE_TRADING_ACK=I_UNDERSTAND_LIVE_TRADING_CAN_LOSE_MONEY
DEDICATED_ACCOUNT=true
PLAN_AUTHENTICATION_KEY=<the unchanged 64-hex deployment secret>
EMERGENCY_AUTHENTICATION_KEY=<a different unchanged 64-hex deployment secret>
DEPLOYMENT_APPROVAL_PATH=runtime/governance/deployment-approval.json
DEPLOYMENT_GOVERNANCE_PUBLIC_KEYS_PATH=runtime/governance/deployment-keys.json
DEPLOYMENT_GOVERNANCE_PUBLIC_KEYS_SHA256=<independently pinned lowercase SHA-256>
COVARIANCE_EVIDENCE_PATH=runtime/governance/covariance-envelope.json
COVARIANCE_EXECUTION_PRICES_PATH=runtime/governance/execution-window-vwap.csv
COVARIANCE_CORPORATE_ACTIONS_PATH=runtime/governance/corporate-actions.csv
COVARIANCE_GOVERNANCE_PUBLIC_KEYS_PATH=runtime/governance/covariance-keys.json
COVARIANCE_GOVERNANCE_PUBLIC_KEYS_SHA256=<independently pinned lowercase SHA-256>
COVARIANCE_PROVIDER_ID=<signed provider identity>
COVARIANCE_VENUE_ID=<signed execution venue identity>
BORROW_EVIDENCE_PATH=runtime/governance/borrow-envelope.json
BORROW_TERMS_PATH=runtime/governance/borrow-terms.csv
BORROW_GOVERNANCE_PUBLIC_KEYS_PATH=runtime/governance/borrow-keys.json
BORROW_GOVERNANCE_PUBLIC_KEYS_SHA256=<independently pinned lowercase SHA-256>
BORROW_PROVIDER_ID=<signed borrow provider identity>
BORROW_VENUE_ID=<signed locate venue identity>
BORROW_MAX_TERM_AGE_SECONDS=300
MAX_LIVE_ANNUAL_BORROW_RATE=0.02
```

The application refuses to initialize live order submission without the exact acknowledgement. This is a technical interlock, not a suitability assessment.

Before enabling it, at minimum:

- use a dedicated account;
- verify the universe is tradable, marginable, and shortable;
- verify market-data entitlements and timestamp freshness;
- validate rounding and minimum-order behavior in the paper account;
- compare realized paper slippage with the research assumptions;
- rehearse broker outages, stale data, rejected orders, partial fills, and kill switches;
- freeze strategy parameters and preserve an untouched evaluation period; and
- start with risk far below the configured maximums.

## CLI commands

| Command | Purpose |
|---|---|
| `python bot.py doctor` | Validate configuration, broker, clock, market data, database, and asset eligibility |
| `python bot.py plan` | Generate the newest completed-session plan |
| `python bot.py execute` | Execute the newest prior-session approved plan while the market is open |
| `python bot.py cycle` | Generate and execute once; restricted to the simulated broker |
| `python bot.py monitor` | Run one account-risk and stale-order monitor cycle |
| `python bot.py daemon` | Run the persistent scheduler and monitor |
| `python bot.py status` | Print persisted status as JSON |
| `python bot.py kill --reason ...` | Create persistent kill switch and flatten managed positions when enabled |
| `python bot.py kill --no-flatten` | Halt new activity and confirm open-order cancellation without closing positions |
| `python bot.py resume --ack RESUME_AUTOMATED_TRADING` | Clear halt/cooldown only after objective risk checks; preserve the equity high-water mark |

`--force` execution is restricted to the offline simulated broker. The production adapter will not use it to bypass a closed market.

The kill command returns exit status `0` only when its requested broker-side action is
confirmed. Exit status `2` means the filesystem marker is durable but liquidation or
order cancellation remains pending/unavailable; automation must escalate and inspect
the JSON `status` instead of treating marker creation as completed risk reduction.
Other command failures return status `1`.

## Emergency shutdown

From the command line:

```bash
python bot.py kill --reason manual_operator_shutdown
```

The daemon also watches:

```text
runtime/KILL_SWITCH
```

Creating that file triggers the same persistent halt on the next monitoring cycle. The operations dashboard provides an emergency button that creates the file. Resumption is intentionally CLI-only:

```bash
python bot.py resume --ack RESUME_AUTOMATED_TRADING
```

Review broker positions and open orders independently before resuming.

## Docker Compose

```bash
cp .env.example .env
# Set DASHBOARD_CONTROL_TOKEN to a long random secret if browser kill control is needed.
docker compose build
docker compose up -d
```

Image builds install `requirements.lock` with pip hash enforcement, so an unpinned or
hash-mismatched transitive dependency fails the build.

Services:

- `bot`: always-on daemon;
- `operations-dashboard`: port `8502`;
- `research-dashboard`: optional profile on port `8501`.

Both dashboards bind to `127.0.0.1` by default. The operations dashboard receives only
the specific non-secret settings it needs, not the Alpaca credentials. Its browser kill
control is disabled unless `DASHBOARD_CONTROL_TOKEN` is set. Put authenticated TLS in
front of either dashboard before any non-local exposure.

The bot receives every signed deployment-approval, covariance, and borrow policy setting
explicitly through its Compose environment. All corresponding files must use
`/app/deployment/...`; the host directory is a long-syntax read-only bind with
`create_host_path: false`. Pre-create and populate `DEPLOYMENT_GOVERNANCE_HOST_DIR` under
independent operator control before rendering or starting Compose. A missing directory is
an error, not an empty directory silently created by Docker.

For validation without creating `.env`, Compose accepts an alternate bot environment
file:

```bash
BOT_ENV_FILE=.env.example docker compose --env-file .env.example config --quiet
```

Start the research dashboard too:

```bash
docker compose --profile research up -d
```

Inspect status or activate a kill switch inside the daemon container:

```bash
docker compose exec bot python bot.py status
docker compose exec bot python bot.py kill --reason operator_shutdown
```

Authoritative database, broker-simulator, lock, health, and log files live in the named
`quant_runtime` volume. It is writable by the bot and mounted read-only by the operations
dashboard. Kill requests and daemon acknowledgements live in the separate
`quant_control` volume, which is the dashboard's only writable runtime capability. The
dashboard uses SQLite `mode=ro` plus `query_only` and never records halt state itself;
the daemon owns that persistence after it observes the kill marker.

The split control volume was introduced after the original single-volume layout. Before
upgrading an existing deployment, stop the services, independently verify positions and
orders, and preserve any active `KILL_SWITCH` from the root of `quant_runtime`; reissue
that halt into `quant_control` before restarting. Never use `docker compose down -v` on
a deployment whose state must be retained.

## systemd deployment

A sample unit and its separate nonsecret governance-policy template are included at:

```text
deploy/quant-auto-trader.service
deploy/governance.env.example
```

The daemon may write only `/opt/quant-auto-trading-bot/runtime`. Signed approvals,
registries, covariance/borrow artifacts, pins, provider identities, and evidence-policy
bounds live separately under `/opt/quant-auto-trader/deployment`; the unit declares that
path read-only. Never put these inputs under the daemon-writable runtime directory. Install
the reviewed artifacts and governance environment as root-owned, group-readable files:

```bash
sudo install -d -o root -g quantbot -m 0750 /opt/quant-auto-trader/deployment
sudo install -o root -g quantbot -m 0640 deploy/governance.env.example \
  /opt/quant-auto-trader/deployment/governance.env
sudoedit /opt/quant-auto-trader/deployment/governance.env
# Install every referenced signed JSON/CSV/registry with owner root:quantbot, mode 0640.
sudo install -o root -g root -m 0644 deploy/quant-auto-trader.service \
  /etc/systemd/system/quant-auto-trader.service
sudo systemctl daemon-reload
sudo systemctl enable --now quant-auto-trader
sudo systemctl status quant-auto-trader
```

Replace every placeholder before starting the unit. The base
`/opt/quant-auto-trading-bot/.env` retains broker secrets and ordinary daemon settings;
the later root-controlled `governance.env` is authoritative for signed evidence paths and
policy. Review the user, group, all paths, and permissions for the target host.

## Persistent state and audit trail

The SQLite database records:

- daemon and one-shot runs;
- target plans and configuration/data hashes;
- broker and client order IDs;
- order phases and fill status;
- account equity snapshots;
- the reviewed Alpaca cash-activity baseline and any external-cash incident;
- drawdown, daily return, and five-day return;
- risk and execution events;
- cooldown and halt state; and
- scheduler attempt dates.

Database schema version 4 retains the keyed risk/control, chained-equity, and monotonic
plan-lifecycle protections and pairs them with authenticated-inventory schema version 3.
The `*.auth.json` v3 inventory commits the current state, lifecycle/equity-chain tail,
complete mutable `orders`, `events`, and `runs` histories, and keyed per-table index heads,
so a SQLite-only writer cannot silently rewrite, replay, or delete those rows. A valid v2
sidecar is exhaustively verified before upgrade. A valid v1 sidecar is upgraded only after
keyed verification and only when all operational tables are empty. Nonempty unauthenticated
legacy history is never silently baselined; it requires an explicit audited offline
migration. Database migration remains writable plan-only/paper behavior, while live/read-only
startup refuses an older database or checkpoint schema. Back up the database, identity,
and authentication sidecars together.
Full rollback of the complete local set still requires an external monotonic/WORM anchor
to detect. There is no active-state key rotation.

The daemon uses a lock file to prevent two local scheduler instances from running simultaneously. SQLite uses rollback-journal mode with bounded busy waits so the operations dashboard can mount the state volume genuinely read-only without creating WAL sidecars. Emergency flatten attempts use persisted, crash-safe IDs: an interrupted attempt reuses its broker IDs, while a later flatten of reopened positions receives a new attempt ID. Back up the emergency journal, its `.identity` and `.checkpoint.json` sidecars, and the control marker together; detecting rollback of that complete set requires an external monotonic/WORM anchor.

Do not delete the database, simulated-broker state, or kill-switch file during a live session. Back them up securely, but never commit API keys or `.env` to source control.

### External cash and approved AUM

Alpaca risk accounting monitors the complete paginated Trading API history for cash
deposits (`CSD`), cash withdrawals (`CSW`), cash ACAT transfers (`ACATC`), and cash
journals (`JNLC`). Establish the first reviewed baseline with `EXECUTION_ENABLED=false`.
Execution-enabled startup cannot silently declare its current account history clean.

If that endpoint is unavailable or malformed, or if an activity is added, removed, or
corrected after the baseline, risk baselines are left untouched and the system requests
a persistent halt and flatten. `resume` cannot waive a cash-activity incident. Reconcile
the broker statement and activity history independently, preserve the incident database,
then initialize and approve replacement state in plan-only/paper mode. This deliberately
strict policy avoids treating deposits as profits or withdrawals as trading losses when
the legacy activity record supplies creation/settlement dates rather than a reliable
intraday P&L timestamp.

Security transfers such as `ACATS`/`FOPT` are a residual external blocker because their
activity records do not provide a defensible equity value for automatic historical P&L
repair. Do not transfer cash or securities into a running strategy account. External
broker-statement monitoring remains required for activity-feed delays and transfer types
that cannot be valued safely.

Alpaca equity is also capped at the research specification's modeled starting capital.
If account equity exceeds that approved AUM, new risk is blocked and reconciliation is
required; approve a larger capacity study before deploying more capital.

## Order sequencing

The execution engine uses two phases:

1. **Reduce phase:** close positions, shrink positions, and close the old side of sign flips.
2. **Increase phase:** after fills and a fresh risk check, open or enlarge target positions.

If the increase phase fails, the bot can halt and flatten managed positions instead of leaving a large unbalanced book. Every submitted order receives a deterministic `qauto-...` client order ID. Existing managed open orders are canceled before a new rebalance. A routine order that cannot obtain a fresh quote inside the configured spread threshold is not transmitted; a submitted limit that does not fill is canceled and reconciled within the bounded fill timeout.

Whole-share execution is the default. Rounding can create small neutrality residuals; the application checks gross, net, and position-weight tolerances before submitting orders and measures residual notional afterward.

## Research liquidity and capacity input

Fixed-bps costs are suitable only for exploratory runs. A sealed-quality run must provide
a wide 09:30-09:35 execution-window dollar-volume CSV (`Date,ASSET_A,ASSET_B,...`)
whose values are price-times-volume dollar notionals in the same currency as starting capital. The
loader preserves gaps and rejects nonnumeric, infinite, zero, and negative values. The
backtest uses a complete rolling window ending one session before the trade, never the
current session's completed volume.

Programmatic integration is explicit:

```python
from dataclasses import replace

from quant_app.backtest import run_backtest
from quant_app.config import AppConfig
from quant_app.data import load_execution_window_dollar_volume_csv
from quant_app.validation import (
    doubled_cost_config,
    parameter_perturbation_gate,
    run_parameter_perturbations,
)

dollar_volume, volume_report = load_execution_window_dollar_volume_csv(uploaded_volume_csv)
base = AppConfig()
config = replace(
    base,
    costs=replace(
        base.costs,
        starting_capital=10_000_000.0,
        transaction_cost_bps=3.0,
        annual_short_borrow_rate=0.02,
        annual_financing_rate=0.04,
        adv_lookback_days=20,
        max_participation_rate=0.01,
        square_root_impact_coefficient=1.0,
        impact_daily_volatility_floor=0.01,
    ),
)
# The three borrow inputs are complete point-in-time panels with the same ordered
# sessions and symbols as prices.
result = run_backtest(
    prices,
    config,
    execution_window_dollar_volume=dollar_volume,
    borrow_availability=borrow_availability,
    annual_borrow_rates=annual_borrow_rates,
    borrow_recalls=borrow_recalls,
)
stressed = run_backtest(
    prices,
    doubled_cost_config(config),
    execution_window_dollar_volume=dollar_volume,
    borrow_availability=borrow_availability,
    annual_borrow_rates=annual_borrow_rates,
    borrow_recalls=borrow_recalls,
    borrow_rate_stress_multiplier=2.0,
)
perturbations = run_parameter_perturbations(
    prices,
    config,
    in_sample_fraction=0.70,
    execution_window_dollar_volume=dollar_volume,
    borrow_availability=borrow_availability,
    annual_borrow_rates=annual_borrow_rates,
    borrow_recalls=borrow_recalls,
)
robustness_passed, robustness_pass_rate, variant_mask = parameter_perturbation_gate(
    perturbations,
    config,
    max_drawdown=0.15,
    prices=prices,
    in_sample_fraction=0.70,
    target_cagr=0.60,
    execution_window_dollar_volume=dollar_volume,
    borrow_availability=borrow_availability,
    annual_borrow_rates=annual_borrow_rates,
    borrow_recalls=borrow_recalls,
)
```

The nonlinear one-way impact rate is
`Y * daily_volatility * sqrt(trade_dollars / lagged_ADV)`. Missing ADV on any traded
asset receives an adverse impact charge and permanently invalidates the research path;
exceeding the configured daily participation cap is a separate hard certification
breach. Diagnostics expose linear cost, market impact, traded dollars, maximum
participation, ADV coverage, and participation-implied AUM capacity.
Same-day primary and emergency-flatten flow is aggregated by asset before convex impact
is finalized, preventing split-leg undercharging.

The generic sealed gate rejects optimistic liquidity knobs even when no realized trade
crosses the selected cap: lagged ADV must use at least 20 sessions, configured daily
participation must be at most 1%, the square-root coefficient must be at least 0.50, and
the daily impact-volatility floor must be at least 0.5%. Dollar-volume inputs may have at
most 1% missing cells. These are minimum anti-gaming gates; asset-specific calibration
from independently retained realized orders can and often should be stricter. The result
bundle includes the normalized volume, execution-price, and factor frames plus the exact
uploaded signed manifest and anchor receipt for external reconciliation.
Sealed certification also requires at least 20 effectively eligible OOS assets on every
session, at least 1 bp one-way linear cost, at least 1% annual borrow and financing,
and a bootstrap block of at least 20 sessions. Manifest v7 additionally binds an
independently retained authoritative exchange-session calendar and requires the close,
execution, execution-window-volume, corporate-action, borrow, and factor indexes to match
it exactly. It signs a 09:30 information cutoff, the exact 09:35
America/New_York strategy/factor interval and its interval-end row labels, plus the
same-session point-in-time VWAP row convention, execution venue/snapshot, and factor
snapshot. This prevents a factor file labeled at interval start from being silently
aligned one session away from the strategy returns. These signed fields remain
assertions until the underlying vendor records are independently retained and verified.
The research ZIP also retains the double-cost path, rolling and perturbation tables,
canonical governance-ledger snapshot, trusted public-key registry, exact research source
and dependency lock, and a SHA-256 inventory for every other member. The inventory detects
post-export file changes but is not a result signature; independent post-run signing and
WORM retention are still required.

Parameter robustness is not allowed to degrade to a merely positive result: at least 20
of the exact 25 preregistered `crossed_robustness_v3_25` variants (80%) must retain at
least 75% of the non-dilutable 60% CAGR target (45%), Sharpe of at least 1.0, the fixed
15% drawdown bound, and all path/capacity invariants. Hard-drawdown, stale-signal,
pricing, beta, liquidity-data, participation, and configured-gross-cap breaches fail the
affected variant. Aggregate 20/25 is necessary but not sufficient: the base and strongest
registered cost, liquidity, timing, broad-universe, borrow-scarcity, and borrow-recall
cases are mandatory. Cost, liquidity, and timing strata must each pass at least 75%, the
borrow stratum 80%, and the universe stratum 100%. The family directly haircuts supplied
execution-window volume, multiplies supplied PIT borrow rates, removes actual PIT
availability for a deterministic scarcity cohort, and injects recurring recalls into a
second cohort. Five disjoint universe omissions cover every asset once at the minimum
20-name breadth. Universe variants retain at least 80% of both input and effective
eligible base breadth, and the base eligible denominator is recomputed from the Base row
rather than trusted from a cached column.

The canonical variant configs, ordinals, evidence multipliers, omission cohorts, and
gate policy have one deterministic SHA-256 identity. Every row also binds its exact
ordered config, symbols, close/execution/liquidity, corporate-action and borrow panels,
timing semantics, and economic multipliers. That identity is embedded in the research
specification signed by the manifest. Streamlit keys perturbation, base, and double-cost
caches by the complete research-software hash; the perturbation cache also binds the suite
identity. A partial, duplicated, reordered, old-suite, changed-input, or old-software
cache result cannot be averaged into a passing rate. The pre-evaluation attempt ledger
still charges all 25 effective trials even if evaluation is interrupted; completed
ledger and result-bundle records retain the executed count, pass count/rate, and suite
identity for reconciliation.

Holdout first use is keyed by OOS interval overlap or a repeated canonical OOS outcome
fingerprint independently of the combined signed evidence hash. Any reused date or the same
asset/value panel under relabeled dates is consumed by exploratory or sealed access, so
split-shifting, in-sample edits, universe changes, or later addition of execution/factor/
calendar/borrow evidence cannot create a new holdout. Only a strictly nonoverlapping future
interval with genuinely new outcomes can be fresh. A nonempty ledger created before this policy is quarantined from
sealed certification because its historical interval bounds cannot be reconstructed safely;
migration requires independent review and a fresh governed ledger.

## Market data and universe requirements

For the Alpaca adapter, daily bars are requested with corporate-action adjustment. The current implementation uses validated latest-quote midpoints for execution sizing and routine order collars. The chosen feed still determines quote coverage; a live deployment should obtain and verify the market-data entitlement appropriate to its universe. A production deployment should independently verify:

- feed entitlement and coverage;
- timestamp freshness;
- splits, dividends, symbol changes, and delistings;
- point-in-time universe membership;
- shortability and borrow changes;
- outlier and bad-tick handling; and
- data-vendor failover.

The example ETF universe is for connectivity testing, not a recommendation. A real cross-sectional model needs a larger, point-in-time, capacity-aware universe. Restricting the universe after seeing performance creates selection bias.

## Testing

Install development dependencies and run:

```bash
python -m pip install --require-hashes -r requirements-dev.lock
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 python -m pytest -q
```

CI also audits the fully resolved production lock with `pip-audit`; keep that job
blocking when dependencies are updated.

The automated suite covers:

- self-financing holdings drift, cost-consistent weights, explicit execution timing,
  drawdowns including starting capital, adverse held-asset pricing failures, unfilled
  signal closes, and 252-observation post-gap re-entry quarantine;
- causal lagged-ADV construction, square-root impact accounting, missing-liquidity
  failures, participation-cap breaches, and AUM-capacity diagnostics;
- causality, leverage, position, dollar-neutrality, and beta-neutrality constraints;
- trial/HAC-adjusted Sharpe evidence, bootstrap bounds, factor attribution, profit-cost
  coverage, break-even costs, and 25 crossed parameter perturbations;
- signed exact-run manifests, persistent experiment/data-family/overlap claims,
  perturbation-weighted interrupted attempts, stale-session invalidation, and
  tamper-evident research-trial hashes;
- no backward filling of close or execution prices and retention of usable delisted
  histories;
- duplicate/no-plan/preflight behavior that preserves existing positions;
- terminal cancellation confirmation, cancel/fill races, partial fills, orphan cleanup,
  stable economic-intent IDs, and final order/position reconciliation;
- manual and in-flight kill switches, adverse P&L shutdowns, actual account exposure
  limits, bounded emergency flatten retries, and failed-flatten persistence;
- cross-platform kernel locks, absolute runtime paths, database identity/schema checks,
  live-mode missing-state refusal, health failure thresholds, and database-independent
  kill acknowledgement; and
- safe dashboard authentication defaults and scheduler treatment of partial execution.

CI runs the complete suite on Python 3.11, 3.12, and 3.13, compiles all source files,
checks dependency consistency, and performs a production dependency audit.

See `TEST_REPORT.txt` for the packaged verification result.

## What remains before real deployment

This package supplies execution automation, not proof of an economic edge. A credible deployment still requires:

- externally sourced point-in-time membership, delisting, corporate-action, and
  historical borrow/locate data;
- executable intraday prices plus nonlinear spread/impact/capacity estimates calibrated
  from realized orders;
- an actually untouched sealed holdout or independent second-vendor replication, with
  governance keys, immutable anchor receipts, and registry pins controlled outside the
  researcher's deployment (the app verifies artifacts but cannot manufacture trust);
- prolonged shadow/paper trading across multiple regimes and a staged capital ramp;
- independent reconciliation against broker statements;
- external monitoring and alerting;
- infrastructure redundancy; and
- legal, tax, and regulatory review for the account and jurisdiction.

A system that reaches 60% CAGR only after increasing leverage or repeatedly tuning the holdout should be rejected rather than deployed.
