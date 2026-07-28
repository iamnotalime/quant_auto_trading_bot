# Security and Operational Safety

## Credentials

- Keep `.env` outside version control.
- Use separate paper and live API keys.
- Rotate keys immediately if they appear in a terminal transcript, log, screenshot, ticket, or repository.
- Do not bake credentials into Docker images.
- Restrict filesystem permissions on `.env`, the runtime database, logs, and broker state.
- Prefer a dedicated brokerage account with no unrelated manual positions.

## Network exposure

Docker Compose binds both dashboards to localhost. Keep that binding, a private network,
or authenticated TLS termination; do not expose port 8501 or 8502 directly to the public
internet. The operations dashboard's halt control is disabled unless a long random
`DASHBOARD_CONTROL_TOKEN` is supplied, and the dashboard container does not receive
Alpaca API credentials.

The operations dashboard can request an emergency halt. Resumption is intentionally unavailable in the browser and requires the local CLI acknowledgement.
The dashboard opens only a pre-existing database with its matching identity marker. It
cannot bootstrap or repair trading state on an empty or partially lost runtime volume;
it uses SQLite `mode=ro`/`query_only` and does not persist halt or event rows. Under
Compose, the authoritative `quant_runtime` volume is mounted read-only in the dashboard,
while a separate writable `quant_control` volume carries only the kill request and daemon
acknowledgement. The filesystem kill marker therefore remains available even when
database state is unavailable without granting the dashboard a writable database path.

## Broker-execution interlock

Both Alpaca paper and live order submission require a valid, unexpired signed v2 deployment
approval, with a maximum seven-day lifetime, and a separately pinned RSA/SHA-256 public-key
registry. The approval binds the complete `AppConfig`, every non-secret daemon setting,
research/runtime identity, source and dependency-lock hashes, deployment descriptors, the
pinned container base-image digest, passed sealed-certification evidence, paper/live mode,
and the authoritative Alpaca account ID. Governance and the connected account's match to
the independent `ALPACA_ACCOUNT_ID` pin finish before the state database is created or
opened. A changed setting, code file, runtime, descriptor, lock file, account, signature, or
expiry blocks initialization. The complete approval is revalidated immediately before every
routine order. After duplicate-ID reconciliation and fresh-quote construction, the final
pre-REST callback rechecks the kill marker, approval rotation, and actual connected account
identity. Emergency risk reduction remains available after expiry so governance cannot trap
exposure.
The kill CLI uses an explicitly emergency-only broker construction: routine Alpaca
submissions have no authorization deadline and therefore remain blocked. If authoritative
live state is missing, the kill path writes only to a distinct
`*.emergency-recovery.sqlite3` audit ledger; it never recreates the missing authoritative
database, and subsequent normal live startup remains blocked pending restoration and
reconciliation.
If `PLAN_AUTHENTICATION_KEY` is missing or malformed during an emergency, the authoritative
database is never opened unauthenticated. A fixed recovery ledger instead uses a stable,
domain-separated key derived from the independent `EMERGENCY_AUTHENTICATION_KEY`; broker
credentials never define emergency order identity. The authenticated emergency journal is
outside SQLite and preserves the marker incident UUID and client IDs across state loss,
corruption, lifecycle-anchor mismatch, and process restarts. Each intent is fsync'd before
the broker submission can occur. A separate keyed journal-tail checkpoint detects replay of
an older otherwise-valid journal, and the keyed identity sentinel makes single-file journal
deletion fail closed. If a marker UUID is rewritten while an incident is unresolved, the
journal's authenticated active UUID is rebound before any replacement ID can be prepared.

Every persisted target plan is content-addressed over all economic fields and metadata,
authenticated by HMAC-SHA-256, and bound to the exact strategy/bot configuration, approved
universe, signed approval, and authenticated account. Execution verifies both the public
content hash and secret tag before any broker mutation; recomputed-hash forgeries and legacy
unkeyed plans fail closed. The raw plan key never enters an approval—only its SHA-256
fingerprint does. Approval, configuration, universe, account, key, or plan-content drift
therefore requires a new approval and plan.

Live execution additionally refuses order submission unless all of the following are set:

```text
BROKER=alpaca
ALPACA_PAPER=false
EXECUTION_ENABLED=true
LIVE_TRADING_ACK=I_UNDERSTAND_LIVE_TRADING_CAN_LOSE_MONEY
DEDICATED_ACCOUNT=true
ALPACA_ACCOUNT_ID=<independently verified broker account ID>
PLAN_AUTHENTICATION_KEY=<unchanged CSPRNG-generated 64-hex secret>
EMERGENCY_AUTHENTICATION_KEY=<different unchanged CSPRNG-generated 64-hex secret>
```

This prevents accidental activation but does not make a strategy safe or suitable.
Compose and systemd deployments also bound CPU, memory, process count, open files, and
container log growth. Treat these defaults as reviewed starting points: size them against
measured worst-case research and broker-reconciliation workloads before production.
Live execution also refuses to start if either the existing state database or its
identity sidecar is missing. Never bypass this check after storage loss; restore state
and reconcile against the broker first.

The signed approval is the sole source for all strategy fields when
`DEPLOYMENT_APPROVAL_PATH` is configured. Partial strategy variables in `.env` are ignored
in that case. Keep the approval and deployment registry outside the image, protect their
registry digest in deployment configuration, and use a short, reviewed expiry. A valid
signature is authorization evidence, not evidence of future performance.

## Signed live covariance evidence

Order-enabled Alpaca startup requires all seven covariance settings: the signed envelope,
wide 09:30-09:35 VWAP CSV, complete long-form corporate-action CSV, independently pinned
RSA public-key registry and digest, and configured provider and venue identities. They are
nonsecret deployment policy and therefore enter `bot_config_sha256` and the signed deployment
approval. Under Compose, configure `/app/deployment/...` paths only; the host governance
directory is mounted read-only.

The envelope is strict schema 2 with purpose `governed_covariance_evidence_v2`. Its
canonical payload binds the exact intended `next_session`, ordered universe, and
America/New_York decision/execution semantics. Authorization exists only for that signed
session and the exact 09:30-inclusive, 09:35-exclusive execution window; a missed session
or window is not admitted through a calendar-age tolerance.

The verifier rejects extra/missing envelope fields, duplicate JSON keys, inactive or
untrusted keys, invalid signatures, wrong provider/venue/universe/timing semantics, expired
or stale snapshots, exact-file hash mismatches, fewer than 253 complete VWAP observations,
and sparse, nonfinite, nonpositive, future, or post-09:30 action evidence. It reads the files
without modifying them. Publish each next generation through same-volume temporary files and
atomic renames, data files first and signed envelope last; a mixed generation cannot pass the
hash bindings.

Before plan construction, verified `latest_session`, `issued_at`, `snapshot_id`, and
`payload_sha256` are advanced under the StateStore HMAC and external authentication
checkpoint. An older valid signature, or a different payload at the same issue time, is a
hard failure. The full normalized provenance and its hash are also inside the authenticated
target plan. This prevents evidence-only rollback. It does not prevent an administrator from
rolling back the complete evidence set together with the matching database and external
checkpoint; independently controlled signing and append-only/WORM retention remain required.
At execution the daemon reloads the signed envelope and both hashed data files, rechecks
signature, freshness, `next_session`, exact window, and normalized hashes against the
authenticated plan, and advances the anchor again before any routine broker mutation.

## Signed live borrow evidence

Order-enabled Alpaca startup also requires the complete live-borrow trust set:

```text
BORROW_EVIDENCE_PATH=<signed envelope>
BORROW_TERMS_PATH=<exact point-in-time terms CSV>
BORROW_GOVERNANCE_PUBLIC_KEYS_PATH=<independently governed RSA registry>
BORROW_GOVERNANCE_PUBLIC_KEYS_SHA256=<independently pinned lowercase SHA-256>
BORROW_PROVIDER_ID=<signed provider identity>
BORROW_VENUE_ID=<signed venue identity>
BORROW_MAX_TERM_AGE_SECONDS=300
MAX_LIVE_ANNUAL_BORROW_RATE=<no greater than sealed ANNUAL_SHORT_BORROW_RATE>
```

These nonsecret policy fields enter `bot_config_sha256` and the signed deployment approval.
The strict schema-1, `governed_live_borrow_evidence_v1` envelope binds the exact Alpaca
account, intended session, ordered configured universe, provider/venue, issuance/expiry,
availability/rate/recall semantics, row count, and exact CSV hash. The terms file must have
the exact `Session,Symbol,AsOfTimestamp,Available,AvailableQuantity,AnnualRate,Recalled`
header and one explicit ordered row per symbol. Missing or duplicate rows, a wrong account/session/universe,
post-09:30 or stale terms, file/signature/pin tampering, expiry, unavailable locates, recalls,
rates over the deployment ceiling, insufficient account-bound located shares, or broker/process
clock skew above five seconds all fail closed.

Verification occurs before the first routine mutation and again immediately before every
child submission. A failure creates an authenticated flattening halt and invokes the
dedicated account-wide emergency path. That emergency path is intentionally evidence-
independent: do not add a borrow-provider dependency to liquidation, because the provider
failure may be the incident being mitigated.

The verified borrow provenance and exact per-symbol observation clocks advance an
HMAC-authenticated monotonic anchor before plan use and again at the execution reload.
An older session/issue time, a different payload at the same time, or any later snapshot
that regresses one symbol's observation clock fails before routine mutation.

Under Compose, all borrow paths must point inside the read-only `/app/deployment` mount.
Publish versioned files atomically with the terms file first and the signed envelope last.
The authenticated monotonic anchor retains the exact per-symbol observation clocks and
rejects signed rollback, same-time substitution, or a later-issued snapshot that regresses
any one symbol's clock. It cannot detect an administrator's
coordinated restoration of the entire evidence directory, database, identity sidecar, and
authentication checkpoint. Retain independently signed snapshots and advance an external
append-only/WORM record; reconcile every live locate, recall, rate, and forced buy-in to
provider and broker records.

For systemd, every signed approval, registry, covariance/borrow artifact, registry pin,
provider/venue identity, and evidence-policy bound belongs under the root-owned,
service-read-only `/opt/quant-auto-trader/deployment` policy path. The service account's
writable `/opt/quant-auto-trading-bot/runtime` must never contain governance inputs.

## Runtime integrity

- Run only one daemon per account and strategy database.
- Preserve `runtime/auto_trader.sqlite3`; it contains idempotency and halt state.
- Preserve `runtime/auto_trader.sqlite3.identity`; a mismatch or one-sided loss blocks startup.
- Preserve `runtime/auto_trader.sqlite3.auth.json`; it is the keyed checkpoint that
  detects SQLite-only valid-row replay/deletion. Restore it with the matching database
  and identity sidecar, never independently.
- Protect `PLAN_AUTHENTICATION_KEY` like a broker secret. Never log, commit, or rotate it
  while its state database is active. Database schema version 4 retains authenticated
  risk/control values, chained equity, and monotonic plan lifecycle. Authentication-
  inventory schema version 3 additionally commits every mutable `orders`, `events`, and
  `runs` row plus keyed per-table index heads in the external HMAC checkpoint. A valid v2
  checkpoint is exhaustively verified before upgrade. A valid v1 checkpoint is upgraded
  only after keyed verification and only when the operational tables are empty. Nonempty
  unauthenticated legacy history is refused rather than silently baselined and requires an
  explicit audited offline migration. Writable plan-only/paper startup may migrate the
  database; live/read-only startup refuses an older database or checkpoint schema. Back up
  first and retain the original key.
- Protect `EMERGENCY_AUTHENTICATION_KEY`, `EMERGENCY_JOURNAL_PATH`, its `.identity`
  sentinel, and its `.checkpoint.json` tail independently.
  Losing either requires broker-history reconciliation before a new incident may submit;
  never reuse the plan key or derive this key from Alpaca credentials.
- Preserve the tamper-evident research ledger when relying on any sealed research result.
- Initialize Alpaca cash-activity monitoring only with execution disabled. A missing,
  changed, corrected, deposited, withdrawn, cash-journaled, or cash-transferred activity
  is a persistent flatten/reconciliation incident and cannot be waived by `resume`.
- Keep broker equity at or below the starting capital bound by the approved research
  capacity specification. Capital above that AUM blocks new risk.
- Preserve `runtime/KILL_SWITCH` until positions and open orders have been independently verified.
- Treat any plan left in `executing` state as an incident; the daemon intentionally fails closed and flattens managed exposure on recovery.
- Do not delete the v2 kill marker or authenticated emergency journal while liquidation
  is unresolved. Their stable incident UUID and pre-submit intent record are the broker
  idempotency boundary even if authoritative SQLite is corrupt or unavailable.
- Back up the emergency journal, identity, checkpoint, and control marker as one set. A
  consistent rollback of the complete control set cannot be detected by files inside that
  same set; use an external monotonic/WORM anchor and broker reconciliation for that threat.
- Monitor the daemon heartbeat and broker account outside the application.
- Monitor `runtime/daemon_health.json`. At `HEALTH_FAILURE_THRESHOLD`, the daemon
  atomically creates the kill marker, persists a halt when state is available,
  attempts immediate order cancellation/exposure reconciliation, and exits non-zero.
  Docker Compose (`restart: unless-stopped`) or systemd (`Restart=always`) then
  restarts it; the replacement observes the still-durable marker before normal work.
- Alert on `DAEMON_HEALTH_FAILSAFE_TRIGGERED`, a `failsafe_triggered` health status,
  any restart loop, or a kill acknowledgement other than `flattened`/`already_flat`.
  A restart is an availability mechanism, not proof that broker exposure is flat.
- `DAEMON_WATCHDOG_TIMEOUT_SECONDS` is an in-process liveness breaker for a main
  loop stuck inside a dependency call. It creates (without replacing) the durable
  kill marker and exits immediately so both Compose and systemd restart it. Never
  Verified broker polling and reconciliation feed its progress clock. Never set it
  below `3 * ORDER_FILL_TIMEOUT_SECONDS + POLL_SECONDS + 60`.
- Sealed research in Compose reads
  `/app/governance/trusted_public_keys.json` from the read-only host directory set by
  `RESEARCH_GOVERNANCE_PUBLIC_KEYS_HOST_DIR` (default `runtime/governance`). Place
  only the public-key registry there; it is intentionally absent from the image.
  Inject `RESEARCH_GOVERNANCE_PUBLIC_KEYS_SHA256` through protected deployment
  configuration after independently hashing the reviewed registry. A missing file,
  empty hash, or digest mismatch fails sealed certification closed. Exploratory mode
  remains available with the shipped empty directory.
- Keep the daemon and state-changing CLI commands on the shared kernel-backed operation lock.
- Reconcile all fills and positions against broker records.
- Keep routine order collars and quote freshness/spread gates enabled. Treat the uncapped
  emergency-market path as an incident control, not a normal execution shortcut.
- Back up audit data, but never restore stale strategy state while orders are active.

## Incident sequence

1. Activate the kill switch: `python bot.py kill --reason incident_description`.
2. Check both its JSON result and process exit status. Status `2` proves only that the
   durable marker was accepted; broker liquidation/cancellation is still unconfirmed.
3. Independently inspect broker open orders and positions.
4. Cancel or close any residual exposure through the broker UI if automation failed.
5. Stop the daemon.
6. Preserve logs, SQLite database, configuration hash, and broker records.
7. Identify the failure before using `resume`.
8. Resume only with the explicit CLI acknowledgement and lower risk.

## Reporting vulnerabilities

Do not include live API credentials, account numbers, or unredacted broker records in a vulnerability report.
