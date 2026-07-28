# Institutional Readiness and Evidence Standard

This document defines what this repository can verify and what still requires external
market data, broker evidence, capital, and time. It deliberately does not use
"Medallion-level" as a self-awarded label. A codebase cannot prove a proprietary edge
or future profitability.

## Gate meanings

### 1. Software safety gate

The software gate is satisfied only when all automated tests, source compilation,
dashboard smoke tests, dependency consistency checks, and the simulated execution cycle
pass in the exact pinned environment. It covers causal accounting, state integrity,
configuration validation, order idempotency, cancellation races, partial fills,
kill-switch behavior, account exposure limits, and secure deployment defaults.
Production and development dependency graphs are fully resolved with artifact hashes;
CI installs those locks, audits the production graph, and builds every Linux container.

Passing this gate means the tested controls behaved as specified. It is not evidence of
alpha and does not replace paper-broker failure drills.

### 2. Sealed research gate

The dashboard can label a result `RESEARCH GATE PASSED` only when every configured
performance test and every governance test passes. In particular:

- the data are uploaded real data, not the synthetic demonstration;
- the strategy specification was frozen before the holdout was viewed;
- a detached RSA/SHA-256 signature from an active key in a deployment-pinned public-key
  registry verifies a preregistration manifest that commits to the exact strategy,
  split, close prices, execution prices, factor returns, and external anchor receipt;
- the data are attested as point-in-time and include universe changes and delistings;
- aligned point-in-time 09:35 America/New_York VWAP prices are supplied, and the signed
  manifest identifies the execution venue and vendor snapshot;
- aligned raw 09:30-09:35 execution-window dollar volume is supplied for the same calendar and universe, and
  the configured starting capital, ADV lookback, participation cap, daily-volatility
  floor, and square-root impact coefficient are bound to the sealed specification;
- at least two named, point-in-time factor-return series covering the identical
  09:35-to-next-session-09:35 interval are supplied, and the signed manifest identifies
  the market factor and factor-vendor snapshot used for the beta gate;
- cost assumptions are based on measured or broker-verified execution, with sealed
  floors of 1 bp one-way linear cost, 1% annual short borrow, and 1% annual financing;
- the persistent ledger confirms that the exact OOS interval does not overlap any prior
  exploratory or sealed view and that its canonical outcome panel was not reused under
  relabeled dates, irrespective of in-sample edits, universe, or split, plus first use of
  the signed experiment ID, data-family ID, and every signed overlap-group ID;
- at least 756 out-of-sample observations are present and at least 20 assets remain
  effectively eligible on every OOS session after mark, execution, and 252-close gates;
- an independently retained authoritative exchange-session calendar is uploaded, bound
  by hash and vendor-snapshot identity in the signed manifest, and exactly matches every
  close, execution-price, dollar-volume, and factor-return date used by the run;
- the configured project hurdle remains at least 60% CAGR with no more than 15% maximum
  drawdown; these are falsifiable research thresholds, not promised future returns;
- the out-of-sample interval spans at least three elapsed calendar years, independently
  of its row count, while an aggregate 248-255 observation-rate diagnostic remains a
  secondary sanity check; exact signed exchange-calendar equality is the anti-omission
  control rather than an average-density heuristic;
- close, execution-price, factor, and dollar-volume missingness are each at most 1%;
- the required evidence confidence is at least 95%;
- no held-asset pricing-integrity breach occurs;
- every traded asset has valid strictly lagged ADV and no requested daily trade exceeds
  the configured participation cap;
- block bootstrap validation uses at least 2,000 paths, a block of at least 20 sessions,
  and a horizon of at least three years; its joint CAGR/drawdown gate uses the 95%
  Wilson lower confidence bound rather than the raw Monte Carlo point estimate;
- the fixed project CAGR/drawdown hurdle plus the configured Calmar, leverage,
  rolling-window, bootstrap, and
  double-cost requirements pass, and the double-cost path has zero pricing, beta, ADV,
  participation, or stale-signal breach;
- the HAC/trial-adjusted Sharpe probability passes after counting every persistent
  research attempt (including interrupted runs) and the 25 perturbation variants;
- annualized pre-cost return covers total modeled costs by at least 2x;
- break-even transaction cost is at least 2x the modeled transaction cost;
- factor-adjusted annualized alpha is positive, its HAC t-stat is at least 2.0, and the
  absolute realized equal-weight market beta is at most 0.15; and
- at least 20 of the exact 25 material crossed alpha/risk/cost/liquidity/timing/universe
  perturbations retain at least 75% of the non-dilutable 60% CAGR target (45%), Sharpe
  of at least 1.0, remain inside the fixed 15% drawdown target, incur no hard-drawdown,
  stale-signal, pricing, beta, liquidity-data, participation, or configured-gross-cap
  breach, and retain at least 80% of both input and effective eligible base breadth;
  every mandatory base/strongest critical case must also pass, with minimum
  cost/liquidity/timing, borrow, and universe stratum rates of 75%, 80%, and 100%.

The completed-trial ledger is append-only in normal application use and hash-chained so
ordinary direct database edits are detected on restart. A separate attempt registry is
written before evaluation. It records the *planned effective trial count*: enabling the
`crossed_robustness_v3_25` family consumes 25 trials even if evaluation crashes
before a completed result is written. Signed experiment, data-family, and overlap-group
claims are made atomically with that attempt. A one-cell data edit, changed split, or
renamed data family therefore cannot restore eligibility when a registered family or
overlap group was already consumed.

OOS interval/repeated-outcome identity is deliberately separate from the combined signed
evidence hash. Any date overlap or the same canonical asset/value outcome panel under
relabeled dates consumes the claim, so price edits, universe changes, or
adding execution, factor, calendar, corporate-action, borrow, or liquidity evidence after
an exploratory view cannot restore first use. Only a strictly nonoverlapping future interval
can be fresh. A nonempty ledger lacking the current `close_oos_interval_or_outcomes_v2` policy
marker is quarantined from sealed certification: legacy records do not retain trustworthy
interval bounds and require independently reviewed migration to a new governed ledger.
All signed dataframe identities use typed, length-delimited scalar encoding directly under
SHA-256; no non-cryptographic intermediate row hash defines their collision resistance.

The research specification contains a canonical SHA-256 of all 25 derived configs,
ordinals, crossed dimensions, economic-evidence multipliers, five universe omissions,
actual borrow-scarcity/recall inputs, mandatory cases, and stratum thresholds. Every
perturbation row binds the exact ordered variant config, symbols, market,
corporate-action and borrow panels, timing semantics, and economics; the complete-suite
gate recomputes those identities before calculating a rate. Streamlit keys the
perturbation, base, and double-cost caches by the full research-software hash (and the
perturbation cache by the suite digest), so a partial/reordered result, changed input, or
old dependency implementation fails closed. Completed trial output and the result bundle
retain the executed count, pass count/rate, and suite digest for reconciliation.

Every displayed result is bound to a fingerprint of all data, specification, validation
controls, attestations, signed-manifest material, pinned-key state, and the complete
governance ledger. The context also includes hashes of the research source tree and
locked dependency graph. A Streamlit widget change, hot code/dependency change, or a
claim in another process invalidates the session payload before any prior certification
can be displayed.

Sealed mode is deliberately unavailable unless both
`RESEARCH_GOVERNANCE_PUBLIC_KEYS_PATH` and
`RESEARCH_GOVERNANCE_PUBLIC_KEYS_SHA256` identify a valid, non-empty key registry and
the uploaded manifest and anchor receipt verify. The pinned digest must come from
deployment configuration controlled independently of the researcher. A locally
generated key, self-issued receipt, or privileged deletion of the entire ledger is not
independent governance and must not be represented as such.

### 3. Deployment gate

Before live orders, all of the following evidence is still required outside the app:

1. a dedicated brokerage account and independent broker-statement reconciliation;
2. an extended shadow/paper period spanning materially different volatility regimes;
3. measured spread, impact, borrow, reject, partial-fill, and latency distributions;
4. tested broker/data outages, process death, database unavailability, and disaster
   recovery from backed-up state;
5. external alerting for health-sidecar failures, broker mismatches, and kill events;
6. capacity limits derived from ADV, participation, locate availability, and financing;
7. legal, tax, market-data-license, and regulatory review; and
8. a staged capital ramp with predefined rollback criteria.

Alpaca cash deposits, withdrawals, cash ACAT transfers, and cash journals are monitored
through the paginated Trading API activity history. The first baseline must be created
with execution disabled. Unavailable or changed evidence creates a persistent flatten
incident before equity baselines can move; automatic historical return repair and
in-place resume are intentionally unsupported because legacy activities expose
creation/settlement dates rather than a reliable intraday P&L timestamp. Securities
transfers and delayed broker activity publication still require external statement
reconciliation. Live account equity may not exceed the starting AUM bound by the
approved research capacity specification.

Live mode refuses to create replacement state when its database or identity sidecar is
missing. Restore and reconcile state, or initialize a new state in paper/plan-only mode
and approve it operationally before live execution.

Database schema version 4 retains authenticated risk/control values, chained equity rows,
and monotonic plan-lifecycle transitions under the independent 256-bit
`PLAN_AUTHENTICATION_KEY`. Authentication-inventory schema version 3 HMAC-commits every
mutable `orders`, `events`, and `runs` row and adds keyed per-table index heads for bounded
authenticated lookup. A valid schema-2 inventory is upgraded only after keyed exhaustive
verification. A valid schema-1 inventory is upgraded only when the operational tables are
empty; nonempty unauthenticated legacy history is refused and requires an explicit audited
offline migration. Database migration is writable plan-only/paper behavior; live/read-only
processes refuse an older database or checkpoint schema. Only key fingerprints enter signed
deployment policy. Full rollback of the database and every local sidecar remains an external
monotonic/WORM-control problem, and active-state key rotation is unsupported.

### 4. HFT deployment gate

Passing the Python software, research, or Alpaca deployment gates does not qualify the
system as HFT. The separate Rust kernel has its own non-substitutable acceptance gate.
Before any live-HFT label or order transmission, evidence must show all of the following:

1. the exact venue, product, native feed protocol, native order-entry protocol, session
   model, market-data license, and certification environment are named and version-pinned;
2. a concrete adapter has passed venue conformance for logon, sequencing, replay/snapshot
   recovery, trading states, rejects, partial fills, cancels, disconnects, and drop copy;
3. tick/lot definitions, price bands, self-trade prevention, cancel-on-disconnect, session
   boundaries, and instrument lifecycle events are enforced from authoritative reference
   data rather than guessed by the generic core;
4. the deployed binary contains no Python callback, REST broker, database, filesystem,
   allocator, or human-readable logging operation on the packet-to-order path;
5. target CPU/NIC/NUMA placement, memory locking/page prefaulting, IRQ isolation, chosen
   kernel-bypass or low-jitter stack, queue sizing, and burst backpressure have been tested;
6. applicable PTP/PPS/PHC discipline, hardware ingress/egress timestamps, offset and
   uncertainty bounds, step/holdover behavior, and an independent clock monitor have
   retained measurement evidence;
7. authenticated production-format native packets, order-entry frames, tick journals, and
   scheduler commits replay byte-for-byte through the actual reactor to the same normalized
   events, complete state, and outbound decisions; transport-owned proofs bind each sent or
   proven-unsent disposition; and the corpus covers priority reordering, loss, duplicate,
   reconnect, reject, cancel-race, retained-input, and synthetic-kill runs; retained records
   use canonical codecs, a reviewed protected-key MAC, a durable bounded sink, and an
   independently controlled authenticated latest-prefix CAS/monotonic/WORM anchor; exact
   ticket and unresolved-intent identity is replayed, all cursors are leased/burned or remain
   unused until successful CAS, crash tails rotate without reusing state, emergency-open is
   durable before safety mutation, and owned full-runtime recovery has been demonstrated;
8. sustained throughput and p50/p99/p99.9/max latency are measured on the release binary,
   target hardware, production adapter, network stack, and representative burst load; and
9. inventory, gross/net exposure, loss, stale-data, adverse-selection, unknown-order,
   session, clock, and manual kill drills disable safely and reconcile through venue-native
   acknowledgements and drop copy.

The in-repository fake adapter, borrowed native-corpus verifier, and host latency probe are
software tests only. They cannot authenticate capture provenance or satisfy venue/transport
conformance, colocation, clock, NIC, or tail-latency evidence. Until this gate passes, the
accurate status is **venue-neutral HFT core in development**.

The core now has explicit immutable instrument/refdata/valuation enforcement, exact optional
drop-copy source binding with per-report liveness, lifecycle-correction quarantine,
non-evicting execution identity, continuous mark-aware per-order reservation enforcement,
separate economic and observation clocks, causal kill timestamps, consumed-source progress,
fact-preserving worse-than-limit/instrument-error reconciliation, transactional native
transport-proof verification, and authenticated-container v2 framing. Event APIs that accept a
caller-owned output buffer preflight the complete fixed two-slot output before consuming state;
a non-reconciled fill restores its tentative drop-copy observation for exact retry. Route failure
after an applied
fact returns a consumed error with client identity and compact secondary fault evidence, and
the reactor publishes available cancel-first output for generic event errors. Transmission
faults detected after dequeue request mandatory fail-stop containment instead of silently
acknowledging the feedback. QHLR v1 supplies a
canonical live-checkpoint payload, and a non-authorizing verified-container scanner rejects
unsupported histories, unfinished intents, and every named predecessor because it owns no
predecessor semantic replay, while returning only owned-replay/manual-reconciliation evidence.

QHPA v1 adds a fixed structural committed-prefix-anchor codec, not an authenticated recovery
protocol. Its opaque tag is not verified by the library, its lifecycle/cursor fields are
claims rather than replay-derived state or leases, and QHAC v2 cannot yet rotate an unsealed
crash prefix. Runnable recovery remains explicitly forbidden. Release still requires exact
intent identity, complete lifecycle codecs and replay, cursor lease/burn or strict
no-use-until-CAS, crash-prefix terminalization/rotation, a pre-mutation emergency-open record,
a reviewed authentication provider, durable concrete sink, independent latest-prefix CAS,
and owned full-runtime replay. These controls also do not supply the licensed venue artifact,
concrete authenticated adapters, HSM keys, or target-host evidence required by this gate.

Internal runtime work also remains. Transmission errors do not yet carry a typed
Applied-versus-Unapplied disposition, so the contained outstanding FIFO can remain fail-stop.
The compact composite fault summary omits numeric risk/adverse payloads and the underlying route
failure cause. On the verified Windows GNU target, `ReactorFailure` is a 224-byte by-value return
ABI that still requires caller-owned reporting and target-hardware latency certification. The
settled 312-test Rust run verifies these fail-closed boundaries; it does not make them production
HFT evidence or establish any return claim.

## Research data contract

The adjusted-close CSV and optional execution-price CSV are both wide files:

```text
Date,ASSET_A,ASSET_B,...
2020-01-02,101.25,53.10,...
```

The execution file must use the same asset columns and calendar as the close file. Its
values must be prices actually observable at the modeled live decision latency. Missing
execution prices are never forward-filled. The app uses an explicitly labeled one-full-
bar latency proxy when execution prices are absent, and such a run cannot pass the sealed
gate.

Adjusted closes are also never filled for marks or signal ranks. A missing raw mark on a
held close-based position receives an adverse write-down, flattens the modeled holding,
and permanently invalidates the research path. In next-open mode, complete observed
execution marks remain the P&L source, but a missing signal-date close cannot open or
increase risk. An asset needs 252 consecutive observed closes before it is eligible, so
a gap quarantines it from re-entry while missing-return covariance contamination decays.

The research-liquidity CSV has the same wide shape, but every value is raw 09:30-09:35
execution-window **dollar notional** (price times shares/contracts) in the same currency as
starting AUM—not share volume and not a forward-looking ADV estimate. Non-missing values
must be finite and strictly positive. Missing observations are preserved and no value
is filled. It is optional only for exploratory use and mandatory for sealed validation;
a sealed input may have at most 1% missing cells. For a trade on session t, the engine
derives ADV from a complete configured
window ending on t-1, then charges
`Y * daily_volatility * sqrt(trade_dollars / ADV)` on every traded dollar in addition
to the linear spread/fee assumption. Missing lagged ADV receives an adverse cost and
invalidates the research path; participation above the cap also invalidates it. Double-
cost stress doubles `Y` as well as linear, borrow, and financing assumptions.
When a primary rebalance is followed by a same-session emergency flatten, convex impact
is repriced once on aggregate per-asset gross daily flow; splitting the two legs cannot
reduce the square-root impact charge.

The generic sealed gate also prevents optimistic capacity knobs: it requires at least a
20-session lagged execution-window-volume average, no more than 1% configured window participation,
`Y >= 0.50`, and a daily impact-volatility floor of at least 0.5%. These are minimum
anti-gaming policies, not proof that the assumptions are conservative for a particular
asset or order. The signed specification binds the actual values, and production use
still requires calibration against independently retained realized-order evidence.

Sealed runs also require complete aligned corporate-action and point-in-time borrow panels.
The engine applies split-share and cash-distribution economics to interval P&L while keeping
raw VWAP levels for fills; security/date borrow rates price shorts, unavailable locates block
short increases, and recalls force costed buy-ins. Every action/borrow snapshot is cut off at
09:30 New York, before the 09:30-09:35 execution window. The files still cannot prove vendor
authenticity or revision history; upstream records and independent retention remain required.

Research and governed live sizing use the same trailing 251 completed execution-window
economic returns and EWMA implementation. The governed evidence is an inseparable raw
09:30-09:35 VWAP, split-ratio, and cash-distribution bundle; exact component, economic-return,
and provenance hashes are authenticated in the target plan. Eligibility requires 253
complete VWAPs (252 lagged returns), while EWMA uses the trailing 252 VWAPs/251 returns,
matching the sealed re-entry gate and risk forecast. Live plan generation refuses a
daily-close or raw split-discontinuous covariance proxy. Sealed certification and governed
deployment both require `rebalance_every=1` until a durable common cadence anchor is
implemented. These controls prove code-path parity, not upstream authenticity or profitability.

Sealed validation also requires a wide daily factor-return CSV:

```text
Date,MKT,VALUE,MOMENTUM,...
2020-01-02,0.0041,-0.0012,0.0007,...
```

It must contain at least two unique named factors. Missing values are not filled. The
signed manifest binds its deterministic dataframe hash and names one supplied column as
the market factor. Exploratory runs may retain the equal-weight-universe diagnostic, but
that single endogenous factor can never satisfy the sealed gate.

Factor names must start with a letter, remain unique after whitespace normalization,
and cannot use spreadsheet-formula prefixes. Missing, non-numeric, infinite, and daily
factor returns outside +/-100% are rejected rather than coerced or clipped.

The signed manifest schema is strict (`schema_version: 7`; the independent public-key
registry remains schema version 1). Its payload includes globally
stable `experiment_id`, `data_family_id`, `strategy_family_id`, and non-empty
`overlap_group_ids`; UTC issuance/expiry timestamps; exact close, execution, factor,
daily-dollar-volume, combined-data, split, and specification hashes; the market-factor
column; and an anchor
provider, record ID, commitment time, and receipt hash. The specification hash itself
contains the source/dependency hash, and the manifest repeats that software hash as an
exact binding. It also records Python implementation/version, OS release/architecture,
NumPy, pandas, SciPy, and sanitized BLAS/LAPACK provider identity; no hostname or user
identity is included. The envelope signature algorithm
is `RSASSA-PKCS1-v1_5-SHA256`. The public-key registry itself is accepted only when its
bytes match the independently configured SHA-256 pin.

Registry shape (values abbreviated):

```json
{
  "schema_version": 1,
  "keys": {
    "governance-key-2026": {
      "algorithm": "RSASSA-PKCS1-v1_5-SHA256",
      "status": "active",
      "modulus_base64url": "...",
      "exponent": 65537
    }
  }
}
```

Manifest envelope shape (all shown payload fields are mandatory and additional fields
are rejected):

```json
{
  "payload": {
    "schema_version": 7,
    "purpose": "sealed_final_validation_v7",
    "experiment_id": "experiment-2026-0001",
    "data_family_id": "vendor-snapshot-family-0042",
    "strategy_family_id": "market-neutral-family-0007",
    "overlap_group_ids": ["us-equities-2020-2026"],
    "issued_at": "2026-07-01T00:00:00Z",
    "expires_at": "2027-07-01T00:00:00Z",
    "close_data_sha256": "...",
    "execution_data_sha256": "...",
    "factor_data_sha256": "...",
    "execution_window_dollar_volume_data_sha256": "...",
    "corporate_action_data_sha256": "...",
    "borrow_data_sha256": "...",
    "exchange_calendar_sha256": "...",
    "market_factor_column": "MKT",
    "combined_data_sha256": "...",
    "oos_start": "2023-01-03T00:00:00",
    "research_specification_sha256": "...",
    "research_software_sha256": "...",
    "research_ledger_id": "123e4567-e89b-12d3-a456-426614174000",
    "research_ledger_preclaim_sequence": 0,
    "research_ledger_preclaim_head_sha256": "...",
    "research_ledger_prior_effective_trials": 0,
    "planned_effective_trials": 25,
    "interval_provenance": {
      "timezone": "America/New_York",
      "strategy_return_interval": "09:35:00_to_next_session_09:35:00",
      "strategy_return_row_label": "interval_end_session_date",
      "factor_return_interval": "09:35:00_to_next_session_09:35:00",
      "factor_return_row_label": "interval_end_session_date",
      "execution_price_definition": "point_in_time_09_35_vwap",
      "execution_price_row_label": "same_session_date",
      "decision_information_cutoff": "same_session_09:30:00_before_execution_window",
      "execution_venue_id": "consolidated-us-equities",
      "execution_vendor_snapshot_id": "execution-snapshot-0042",
      "factor_vendor_snapshot_id": "factor-snapshot-0042",
      "exchange_calendar_id": "xnys-official-sessions",
      "exchange_calendar_vendor_snapshot_id": "calendar-snapshot-0042",
      "execution_liquidity_window": "09:30:00_to_09:35:00",
      "execution_liquidity_definition": "traded_dollar_notional_in_execution_window",
      "execution_liquidity_row_label": "same_session_date",
      "execution_liquidity_vendor_snapshot_id": "liquidity-snapshot-0042",
      "corporate_action_interval": "09:35:00_to_next_session_09:35:00",
      "corporate_action_split_definition": "shares_after_per_share_before",
      "corporate_action_cash_definition": "cash_per_pre_action_share",
      "corporate_action_as_of_cutoff": "same_session_at_or_before_09:30:00",
      "corporate_action_vendor_snapshot_id": "actions-snapshot-0042",
      "borrow_as_of_cutoff": "same_session_at_or_before_09:30:00",
      "borrow_rate_definition": "annualized_security_specific_rate",
      "borrow_vendor_snapshot_id": "borrow-snapshot-0042"
    },
    "anchor": {
      "provider": "governance-authority",
      "record_id": "immutable-record-0042",
      "committed_at": "2026-06-30T23:59:00Z",
      "receipt_sha256": "..."
    }
  },
  "signature": {
    "algorithm": "RSASSA-PKCS1-v1_5-SHA256",
    "key_id": "governance-key-2026",
    "value": "base64-signature"
  }
}
```

The signature covers UTF-8 JSON of `payload` with keys sorted, no insignificant
whitespace, and no NaN values. The signature is standard base64; the RSA modulus is
unpadded base64url. Keys shorter than 2048 bits, inactive keys, expired manifests,
future-dated anchors, missing receipts, and any exact-run mismatch fail closed.
Both the registry and manifest parser reject duplicate JSON object keys and non-standard
`NaN`/`Infinity` constants, avoiding cross-parser signature ambiguity.
Registry keys are restricted to 2,048-8,192-bit RSA moduli and exponent 65,537.

The signature proves that the pinned governance key asserted the interval, row-label
conventions, venue, and snapshot identifiers; it does not prove that the vendor artifacts are genuine. Those
snapshots and venue records still require independent retention and review.

### Governed deployment covariance snapshot

The broker daemon has a separate strict schema-2 signed envelope with purpose
`governed_covariance_evidence_v2` for the live covariance inputs. All seven `COVARIANCE_*`
settings are mandatory for order-enabled Alpaca startup and
are included in the signed bot/deployment configuration: envelope path, execution-window
VWAP path, complete corporate-action path, key-registry path and pinned digest, provider ID,
and venue ID. Compose values must use the read-only `/app/deployment/...` mount paths.

The canonical signed payload binds provider/venue/snapshot identities, issuance and expiry,
America/New_York 09:30 decision and 09:35 VWAP definitions, exact ordered symbols, exact
session bounds/count, the exact intended `next_session`, and raw SHA-256 hashes of both CSVs.
The expiry must extend beyond that next session's 09:35 endpoint. Runtime parsing independently
reconstructs exact axes and requires at least 253 complete positive VWAP observations plus a
same-session, by-09:30 split/cash row for every asset/date. The provider returns computed
signature, registry, envelope, payload, data, and as-of-panel hashes; caller-supplied
provenance strings never establish trust.

Plan generation cross-checks signed `next_session` against the broker's `next_open` and
HMAC-authenticates it with the full provenance and evidence-universe binding. Execution is
valid only on that exact date and during the 09:30-inclusive, 09:35-exclusive New York
window; a missed plan/window is refused rather than admitted by a calendar-age tolerance.
Before broker mutation the envelope and both hashed files are reloaded, current expiry,
signature, `next_session`, and window are revalidated, exact provenance/panel hashes are
compared with the authenticated plan, and the monotonic anchor is advanced again.

The daemon advances a monotonic HMAC-authenticated evidence anchor before constructing a
plan and commits the normalized provenance plus its hash into plan authentication. Snapshot
rotation uses atomic same-volume renames with the envelope published last, so a mixed
generation only creates a temporary fail-closed condition. Independent signing and WORM
retention are still external controls, especially against coordinated rollback of both the
entire authenticated state/checkpoint set and the evidence directory.

### Governed deployment live-borrow snapshot

Order-enabled Alpaca deployment requires all six borrow trust settings
(`BORROW_EVIDENCE_PATH`, `BORROW_TERMS_PATH`, registry path and pinned digest, provider ID,
and venue ID), plus the bounded `BORROW_MAX_TERM_AGE_SECONDS` and
`MAX_LIVE_ANNUAL_BORROW_RATE` policy. All are nonsecret signed bot/deployment configuration.
The live-rate ceiling may not exceed the sealed deployment strategy's
`ANNUAL_SHORT_BORROW_RATE`; a higher observed rate is rejected until a more conservative
research assumption has been sealed and a new deployment approval issued.

The separate strict schema-1 envelope has purpose
`governed_live_borrow_evidence_v1`. Its pinned RSA signature binds snapshot/provider/venue,
the authenticated Alpaca account, exact intended session, issuance and expiry, exact ordered
universe, availability/rate/recall definitions, row count, and the raw SHA-256 of a terms
file whose only accepted header is
`Session,Symbol,AsOfTimestamp,Available,AvailableQuantity,AnnualRate,Recalled`. Exactly one ordered row per
configured symbol is required. Each row must be same-session, offset-aware, no later than
09:30 New York, no more than 1-300 configured seconds old, and explicit about availability,
located share quantity, annual rate, and recall. Evidence is admitted only during the exact 09:30-09:35 execution
session, expires after that session's 09:35 endpoint, and has at most a 24-hour lifetime.
The server clock and independent process clock must agree within five seconds at authorization.

Before any routine broker mutation and at every child's final authorization boundary, the
daemon reloads and verifies the evidence, advances an HMAC-authenticated monotonic anchor,
audits the computed provenance, and tests every current, planned, and projected short.
Missing terms, unavailable or insufficient locates, recalls, excessive rates, stale or expired snapshots,
identity/session/universe mismatches, signature/file/pin tampering, and signed rollback all
persist a flattening halt and invoke account-wide emergency reduction. Emergency orders do
not consult the borrow provider, preserving liquidation authority during a provider outage.

Compose paths use the read-only `/app/deployment/...` mount. Operational publication uses
versioned temporary files with the terms file atomically renamed before the signed envelope.
The local per-symbol anchor detects evidence-only rollback, same-time substitution, and a
later-issued snapshot that regresses any symbol's observation clock, but
cannot detect coordinated restoration of the complete evidence directory plus database and
all authentication sidecars. Independent signing, external monotonic/WORM retention, broker
and lender reconciliation, and forced-buy-in incident review remain deployment requirements.

The systemd deployment uses the separate root-owned, service-read-only
`/opt/quant-auto-trader/deployment` directory for all signed approvals, registries,
covariance/borrow artifacts, pins, identities, and evidence-policy bounds. None may be
placed under the daemon-writable `/opt/quant-auto-trading-bot/runtime` directory.

The downloadable research archive retains the normalized close, execution, factor,
dollar-volume, and authoritative exchange-calendar frames used by the run; the double-cost
path; rolling and perturbation tables; a canonical snapshot of every governance table; the
trusted public-key registry; exact research source and dependency lock; and the uploaded
manifest and anchor receipt. `SHA256SUMS.json` inventories every other member so an
independent reviewer can detect post-export file changes and reconcile the bundle to the
recorded hashes. That inventory is not a post-run signature: independent signing and WORM
retention remain external deployment requirements.

## Execution invariants

- No-plan, duplicate, closed-market, and other preflight failures do not liquidate an
  existing portfolio.
- Automatic flattening after an execution exception occurs only after exposure may have
  changed.
- Matching open orders must reach a terminal state before replacement quantities are
  calculated.
- Target plans require both a complete content hash and a constant-time verified HMAC;
  recomputing the public hash after a database rewrite cannot authorize the forged plan.
- Routine broker authorization is performed after duplicate-ID and quote reads, immediately
  before submission, and rechecks kill state, approval identity, actual broker account, the
  exact intended session, signed exact-session borrow terms for all planned/current/projected
  shorts, and `09:30 <= time < 09:35` on a fresh broker clock.
- Governed execution requires at least 20 effective assets. Routine children are IOC
  marketable limits; 09:35 is an exclusive wall-clock deadline for submission, fill polling,
  position reflection, and final stable-state reconciliation. No routine retry begins at or
  after the endpoint.
- Governed borrow evidence must cover the exact account/session/universe and every current,
  planned, or projected short before the first routine mutation and each child. Missing,
  unavailable, quantity-insufficient, recalled, stale, excessive-rate, or unauthenticated terms halt and trigger
  evidence-independent emergency reduction.
- A filesystem kill switch interrupts an in-flight fill wait, confirms cancellation, and
  enters the flatten/reconciliation path.
- A halt-only kill persists the control state and confirms relevant open orders are terminal
  without liquidating positions, including when routine strategy configuration is invalid.
- Dedicated accounts target every orphan position to zero and reconcile all open orders.
- Emergency flattening uses bounded resnapshot/retry rounds and succeeds only after both
  positions and relevant open orders are zero.
- Client-order IDs encode the economic intent, and a broker receipt with a mismatched
  symbol, side, or quantity is rejected.
- The daemon and state-changing CLI commands share a kernel-backed operation lock.
- Actual broker gross, net, and position concentration are monitored independently of
  the latest target plan.

## What would constitute stronger profit evidence

The next evidence upgrades are not additional dashboard knobs. They are independent
data and observations:

- a genuinely untouched dataset from another vendor or market;
- cross-universe and cross-country replication;
- nonlinear impact and capacity curves built from realized orders;
- historical borrow/locate and forced-buy-in data;
- an externally retained experiment registry, signed preregistration manifests, and
  immutable data snapshots (the local verifier enforces artifacts but is not itself the
  independent authority);
- paper and small-capital live returns reconciled to broker statements; and
- independent review of research decisions, discarded trials, and operational incidents.

Until these exist, the honest status is **institutional-grade prototype with a strict
evidence gate**, not a demonstrated Medallion-equivalent strategy.
