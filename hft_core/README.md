# Quant HFT Core

`quant-hft-core` is the separate Rust latency-critical kernel. It is deliberately not a
Python extension and it does not call the Python runtime, a REST broker SDK, SQLite, or a
dashboard on the event path.

## Honest status

This crate is a tested venue-neutral execution kernel, not a deployable or
"Medallion-equivalent" HFT system. A live build is intentionally unavailable until it has
a concrete, licensed venue market-data and order-entry adapter plus target-hardware
evidence. The existing Python/Alpaca daemon remains a lower-frequency system and is not an
HFT transport.

## Required process boundary

```text
Python research and orchestration (cold path)
  model fitting, parameter approval, deployment, monitoring, replay requests
                              |
                bounded authenticated control IPC
                              v
Rust process (hot path; pinned/preallocated)
  native feed -> decode/sequence -> L3 book -> compiled Rust strategy
              -> pre-trade/adverse/inventory gates -> native order entry
                    |                         |
             binary tick journal       atomic kill state
```

Python may prepare reviewed parameters and supervise a process. It must not receive each
tick, calculate each quote, approve individual orders, or sit between a venue packet and
an outbound native order message. The hot process must continue to fail closed if the
control plane disappears.

## Requirement traceability

| Target capability | In-repository state | Still required for live use |
|---|---|---|
| Rust event-driven execution | Fixed-capacity execution state machine and bounded reactor | Bind the selected native transports and certify the deployed binary |
| Direct market data/order entry | Transactional decoder/encoder/session/feed contracts plus an allocation-free live coordinator that fail-closed binds the exact venue, immutable instrument definition, adapter session, market-data/order-entry/drop-copy channels and epochs, scheduler commits, native bytes, transport dispositions, and priority feedback | Licensed concrete venue protocol implementations, authenticated reference artifact, NIC polling/transport binding, and conformance |
| Full book/queue state | Indexed L3 MBO book; distinct private/public ID types; explicit one-to-one binding registry; engine-integrated exact price-time queue | Certified venue allocation/modify/hidden-liquidity rules and correlation method |
| Nanosecond clocks | Separate UTC/monotonic types, hardware receive fields, discipline/holdover gates | NIC PHC, PTP/PPS, egress timestamps, and target-host fault evidence |
| Low jitter | Preallocated containers, caller-owned buffers, bounded work, allocation tests | CPU/NUMA/NIC isolation, locked/pre-faulted memory, and burst measurements |
| Deterministic replay | Lossless journal v5 plus scheduler-commit v1, actual-reactor replay, retained/synthetic-kill scheduling, capture-to-run/input ordering, recovery boundaries, exact egress, complete state equality, a transactional native-packet/native-order corpus verifier, authenticated-container framing, a canonical QHLR checkpoint codec, a non-authorizing verified-container scanner, and structural QHPA committed-prefix-anchor framing | Reviewed MAC/HSM integration, canonical codecs for every retained fact, a durable concrete audit sink, authenticated latest-prefix CAS, crash-safe cursor ownership and rotation, owned full-runtime replay, authenticated production captures, plus target-venue, transport-proof, and hardware replay evidence |
| Real-time safety | Base-currency risk, session P&L, adverse monitor, continuous mark-revalued per-order limits, inventory gates, cancel-first kill handling, fact-preserving reconciled-fill faults, and fixed-capacity independent drop-copy reconciliation | Concrete licensed drop-copy session/liveness, venue/account limits, independent kill path, and failure drills |
| Python cold path only | Rust has no Python dependency; opaque authenticated-gate decisions carry a replayable heartbeat lease, while live engine/reactor/coordinator paths reject journal-replay provenance | Reviewed MAC/HSM/key service and authenticated OS IPC implementation |

## In-repository guarantees

- integer nanosecond timestamps and bounded clock-discipline/holdover checks;
- compile-time-capacity containers and SPSC transport;
- immutable authenticated-artifact instrument contracts covering venue/product/authority,
  effective dates, normalized/native scales, tick/lot increments, bands, continuous state,
  STP, cancel-on-disconnect, settlement currency, per-tick value, and contract multiplier;
  engine/session/encoder/recovery identities must agree exactly, and timer-observed expiry
  clears intent and prepares cancels;
- an indexed strict-sequence L3 order book, an identity-exact fixed-capacity MBO queue
  tracker for price-time/replace-loses-priority venues, distinct private order-entry
  and public MBO ID namespaces, an explicit adapter-authenticated correlation registry,
  and a separately named conservative aggregate estimator when identity is unavailable;
- versioned, endian-defined, checksummed normalized tick records that retain venue,
  clock, control, timer, owned-MBO binding, and transmission inputs, with deterministic
  validation across independent source/session sequence domains plus a global capture
  ordinal;
- a fixed authenticated-container v2 codec whose MAC-protected header binds a unique
  container/generation, exact configuration and software digests, venue adapter/session,
  market-data, order-entry, and optional independent drop-copy channel/session epochs,
  exact authoritative venue/product/reference-data authority/version/artifact digest,
  clock epoch, and rotation parent;
  variable records bind type, global ordinal, container identity, and the prior tag,
  while the terminal seal binds the full count and chain and must exactly match a
  caller-supplied external latest anchor before any payload is exposed;
- a canonical allocation-free QHLR v1 checkpoint payload codec with an exact 32-byte
  envelope header, 184-byte checkpoint body, and CRC32C. It binds every checkpoint
  identity, reference-data source, sequence source, cursor, clock epoch, and phase in one
  canonical representation. Its CRC detects accidental corruption only; authenticity and
  rollback protection come only from a verified authenticated container and external anchor;
- a non-authorizing recovery scanner that consumes a `VerifiedAuditContainer`, accepts only
  one final canonical live checkpoint, binds it to the authenticated header and validates
  its cursors, treats every native intent as unfinished, and returns either owned-replay or
  manual-reconciliation evidence rather than a runnable coordinator. It rejects all
  unsupported facts and every header that names a predecessor because this API owns no
  predecessor semantic replay; because it starts from a terminally sealed container, it
  cannot observe a crash-unsealed intent tail;
- a provider-neutral QHPA v1 committed-prefix-anchor codec with a fixed 296-byte canonical
  record: 264 structural bytes and an opaque 256-bit deployment tag. It validates framing,
  header identity, ordinals, cursors, and internal summary consistency only. It does not
  calculate or verify a MAC, prove durability or freshness, perform latest-anchor CAS,
  derive lifecycle state from replay, lease cursors, resolve an exact intent, authorize
  recovery, or solve crash-prefix rotation;
- explicit recovery/snapshot boundaries and an allocation-free replay-consumer contract
  that fingerprints both resulting state and outbound decisions;
- a fail-latched, caller-buffered native corpus verifier that consumes every captured
  market-data, snapshot, and order-entry byte; requires exact normalized events; binds
  each encoded order to its canonical scheduler commit, source, command slot, venue
  sequence, and bytes; and accepts sent/proven-unsent feedback only through a
  transactional transport-owned proof verifier; its exact-MBO mode separately verifies
  canonical local correlation events immediately after the venue message that proved them;
- transactional native decoder gates that require an exact contiguous reported prefix,
  reject any populated unused output slot, restore codec state, and scrub the complete
  caller-owned output array before session/feed state can commit;
- a reservation-first live native coordinator that executes each already-authenticated
  canonical event through the real reactor, persists the source and scheduler decision
  before submission, records the exact native intent before calling transport, and accepts
  a returned disposition only after transactional proof verification binds the exact context,
  proof, status, and timestamp; verifier rejection, ambiguity, or contradiction quiesces,
  records a proof fault, retains the venue sequence, and emits no feedback, while verified
  proven-unsent evidence may roll back and transport feedback drains through the priority lane
  without allocating; coordinator construction and every live or safety call bind the
  exact venue/session/adapter/reference-data identity and exact market-data/order-entry/
  optional-drop-copy protocol, channel, and authenticated session epoch before reserving audit
  capacity or mutating; authenticated checkpoint values are coordinator metadata rather than
  full runtime snapshots, so `Ready`, `SafetyPending`, and `KilledRecovery` restoration is
  rejected until a typed recovery session owns and binds the complete reactor, venue session,
  adapter, transport, and control replay, while only non-runnable `Ambiguous`/`Failed` metadata
  can currently be reconstructed for fail-stop reconciliation;
- an optional fixed-capacity drop-copy gate with its own exact source/session sequence domain;
  either channel may lead, but new risk remains closed until per-client reports match exactly,
  each pending report carries an independent nonzero replayable deadline, exact equality
  survives, and the first later timer or relevant event expires it; cross-variant/economic/
  duplicate/capacity/sequence/session faults latch the dedicated first fault and prepare
  cancels without applying lifecycle or risk twice; if primary order-entry application rejects
  a fill before reconciliation, its tentative drop-copy observation is rolled back so the same
  authoritative report can be retried without a false duplicate or false synchronization;
- explicit lifecycle bust/correct facts pair only by exact correction identity, target, kind,
  and canonical digest, immediately quarantine and cancel, and never manufacture an inverse
  fill or mutate target-order inventory, risk, P&L, or adverse state;
- non-evicting execution-ID retention rejects capacity exhaustion before first-fill venue
  binding or accounting mutation, so an old active-order execution cannot be replayed as new;
- fills remain authoritative facts when later validation fails: risk, lifecycle, adverse,
  source-sequence, and cancel-first state are reconciled before a typed failure is returned.
  Worse-than-limit execution prices and invalid instrument economics therefore fail closed
  without hiding the fill or making its sequence reusable, and an unreconciled atomic risk
  rejection rolls back tentative trade identity and first-fill venue binding. A later route
  synchronization failure returns `OrderRouteAfterReconciled` with the client identity and a
  compact secondary order/instrument-fault summary while preserving consumed source progress;
- a fixed 184-byte scheduler commit that CRC-binds each source capture to a gap-checked
  commit ordinal, non-saturating reactor run/input ordinals, priority/normal route, exact
  stop and outstanding state, and up to two canonical outbound commands;
- fixed-rate base-currency instrument economics, portfolio-wide exchange-time stale-mark
  checks, session P&L, inventory/notional limits, and per-order open-notional reservations
  valued at `max(limit, authenticated mark)` and transactionally revalued before mark commit;
  every accepted mark continuously enforces the per-order maximum against the revalued
  reservation, commits the observed fact, and then fail-latches/cancels on a breach;
  adverse horizons use exchange time rather than processing delay, reject live per-source
  exchange-time regression, fail closed when a delayed fill has crossed the retained mark
  frontier, and allow only a same-instrument mark frontier to expire rolling losses;
- a transactional external-authenticator control gate with monotonic command sequencing,
  configuration identity, expiry, heartbeat liveness, arm/disarm, and kill actions; accepted
  arm/heartbeat leases survive normalization and replay, and expiry in either the timer path or
  a later market event disarms, latches the first venue-disconnect fault, and cancels first;
  the accepted decision payload and origin are opaque, journal decoding can create only
  replay provenance, and every live application API rejects that provenance fail-closed;
- monotonic first-fault kill state, retained-input and source-less infrastructure safety
  trips with canonical scheduler commits, native cancel submission and retry, killed-mode
  acknowledgement/fill ingestion, transport-ambiguity quiescence, and fixed-size latency
  histograms; zero or regressing adverse/control/clock observations use the last safe causal
  time for the kill fact, and consumed fatal session or reconciled order-entry facts advance
  their source progress, clear desired risk, and preserve cancel-first output. Every event entry
  point that accepts a caller-owned output buffer preflights and clears the full fixed two-slot
  output before state changes;
  generic reactor event faults publish any valid cancel-first batch before returning the
  original typed error. A mismatch or engine fault after transmission feedback is dequeued
  requests mandatory internal-safety containment and leaves its outstanding FIFO fail-stop; and
- allocation audits covering representative initialized book, exact queue, clock,
  telemetry, ring, risk, lifecycle, control, execution-engine, and scheduler-commit
  operations, plus repeated native packet decode and scheduler-bound native order encoding
  with transactional transport proof.

Replay v5 rejects global omissions/reordering, source-domain gaps/regressions, and invalid
snapshot/recovery transitions. Its fixed 180-byte record losslessly round-trips every
typed market-data, snapshot, order-entry, drop-copy, owned-MBO correlation, clock,
authenticated-control, scheduler, and transmission-feedback input currently accepted by
the reactor. Scheduler-commit v1 preserves application order when the priority lane
overtakes an earlier captured normal event. Its fail-latched verifier checks the complete
source-record CRC, executes through `HotPathReactor`, byte-compares the resulting commit,
and verifies complete deterministic reactor state. The certification trace covers clock,
snapshot, session/control gates, two-sided decisions, exact transport feedback, private
accepts, explicit owned-MBO correlation, and exact queue initialization. Reversed feedback
and a normal event before unresolved transport feedback are rejected. Its `ReplayConsumer`
contract is also tested with deterministic state and outbound-decision contributions.

Scheduler-commit v1 targets the fixed two-slot, one-input audited run mode. Its retained
input and source-less synthetic safety-kill routes are committed and replayed through the
actual reactor, including exact cancel FIFO feedback and retained-input release. The native
corpus verifier is a software boundary over borrowed capture records; it does not define an
authenticated packet-capture record schema or prove that bytes reached (or did not reach)
a NIC, kernel-bypass queue, or exchange. Authenticated-container v2 supplies framing,
identity binding, tag chaining, terminal sealing, and exact expected-anchor comparison.
QHLR supplies one canonical checkpoint payload, the current scanner supplies non-authorizing
single-container evidence, and QHPA supplies structural committed-prefix framing only. None
supplies MAC key custody, filesystem durability, a monotonic freshness service, or a complete
crash-recovery protocol. Release still requires canonical codecs and replay-derived lifecycle
for every retained fact (including exact unresolved-intent identity), externally owned cursor
leases/burn or strict no-use-until-CAS, safe terminalization/rotation of an unsealed crash
prefix, a pre-mutation emergency-open record, a reviewed authentication provider, durable
bounded sink, independent latest-prefix CAS, and an owned full-runtime replay. Binding the
selected venue's licensed production decoder and transport-proof implementation, then replaying
authenticated target-environment journals, also remains a release gate. These guarantees are
narrow: they describe tested software behavior.
They do not establish an economic edge or a latency percentile on production hardware.
Mark revaluation currently performs bounded full-capacity order-table passes; allocation
freedom is tested, but production-capacity tail latency for those passes is still a target-
hardware acceptance item.
Transmission feedback also lacks a typed Applied-versus-Unapplied error disposition, so a
post-dequeue failure cannot be resumed by inference and may leave the FIFO permanently fail-stop.
The compact reconciled-fault summary omits numeric risk/adverse payloads and the underlying route
failure cause. On the verified Windows GNU target, the by-value `ReactorFailure` return ABI is
224 bytes; a caller-owned report redesign and target-latency certification remain internal
release work.
The threat model, persistence ordering, and concrete sink work are specified in
[`AUTHENTICATED_AUDIT_CONTAINER.md`](AUTHENTICATED_AUDIT_CONTAINER.md).

The live coordinator likewise begins at an authenticated, normalized event and ends at a
synchronous transport disposition. It does not poll a NIC, authenticate a raw live packet,
implement kernel bypass, prove clock quality, or certify cancel-on-disconnect. Those remain
deployment boundaries and cannot be inferred from the in-process tests.

## Forbidden on the hot path

- Python callbacks or FFI into Python;
- REST broker APIs, browser protocols, or SDK retries;
- heap allocation after initialization;
- blocking filesystem/database calls or human-readable logging;
- wall-clock discovery without a disciplined hardware timestamp source; and
- automatic recovery from a feed gap, clock fault, risk breach, or unknown order state.

## Build and verify

```powershell
cargo +1.97.0-x86_64-pc-windows-gnu fmt --manifest-path hft_core/Cargo.toml --all -- --check
cargo +1.97.0-x86_64-pc-windows-gnu check --manifest-path hft_core/Cargo.toml --locked --all-targets --all-features
cargo +1.97.0-x86_64-pc-windows-gnu clippy --manifest-path hft_core/Cargo.toml --locked --all-targets --all-features -- -D warnings
cargo +1.97.0-x86_64-pc-windows-gnu build --release --manifest-path hft_core/Cargo.toml --locked --lib --all-features
cargo +1.97.0-x86_64-pc-windows-gnu test --manifest-path hft_core/Cargo.toml --locked --lib --tests --features allocation-audit
```

The authoritative settled run used an isolated exact Rust 1.97 Windows GNU toolchain and
passed all five commands above, including 312 library/integration tests. Release builds use
one codegen unit, fat LTO, abort-on-panic, and overflow checks. `latency_probe` remains an
opt-in executable behind the `latency-probe-bin` feature; it was not executed in that run and
no standalone latency metric is claimed. Only isolated target-hardware measurements with the
production adapter, network stack, CPU/NUMA placement, and clock setup count as a deployment
latency gate.

## Gates before any live-HFT claim

1. Select the exact venue, product, account model, and native protocol versions.
2. Implement and conformance-test the licensed native feed and order-entry adapters,
   including session recovery and venue-specific reject semantics.
3. Bind instrument definitions, tick/lot scales, trading states, price bands, self-trade
   prevention, cancel-on-disconnect, and drop-copy reconciliation.
4. Deploy on the target server/NIC with CPU isolation, NUMA affinity, locked memory,
   pre-faulted pages, kernel-bypass or the chosen low-jitter network stack, and measured
   backpressure behavior.
5. Discipline the NIC PHC and system clock with PTP/PPS as applicable; retain hardware
   ingress/egress timestamps and prove fault thresholds under holdover/step tests.
6. Run packet-loss, gap/recovery, duplicate/reorder, disconnect, reject, partial-fill,
   cancel-race, kill, and restart drills against venue certification environments.
7. Persist every retained fact through canonical codecs and a durable bounded sink using a
   reviewed protected-key MAC. Before using any cursor or mutating emergency state, durably
   commit a replayable ticket/intent/emergency-open fact and atomically CAS an authenticated
   latest prefix in an independent monotonic or WORM store. Demonstrate exact intent identity,
   cursor lease/burn or strict no-use-until-CAS, crash-tail retirement, safe prefix rotation,
   and owned full-runtime replay; then replay native packets and order-entry frames byte-for-
   byte, verify proof-bearing dispositions, and reproduce normalized events, scheduler commits,
   complete state, and outbound decisions.
8. Publish sustained and tail latency measurements on the deployment build and hardware,
   including warmup, load, packet bursts, and fault modes.

Until every applicable gate has evidence, the correct label is **venue-neutral HFT core in
development**, not production HFT.

The concrete implementation and certification inputs are enumerated in
[`VENUE_ADAPTER_REQUIREMENTS.md`](VENUE_ADAPTER_REQUIREMENTS.md).
