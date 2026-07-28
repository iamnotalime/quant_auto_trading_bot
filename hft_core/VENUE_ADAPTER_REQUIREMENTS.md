# Concrete venue adapter acceptance contract

The Rust core deliberately does not guess a venue protocol. A concrete adapter is eligible
for live certification only when every item below is bound to a named venue, product,
account, environment, and protocol release.

## Required identity

- legal venue and certification environment;
- market-data protocol name/version, channel IDs, products, and licensed schema hash;
- order-entry protocol name/version, session/account identity, and certified schema hash;
- drop-copy protocol/session and reconciliation ownership;
- price, quantity, contract, currency, and timestamp scales; and
- the exact binary/config digest deployed with those bindings.

The adapter must expose this identity through `VenueDescriptor`; startup must reject any
runtime identity or capability mismatch.

Every `TransactionalCodec` checkpoint must be a durable full-state savepoint covering
parser, encoder, authentication, anti-replay, and sequence state. An inner venue call or
commit must not invalidate an older checkpoint, because whole-frame verification can
reject after several individually valid decoder/correlator operations and must restore the
entire adapter atomically.

## Market-data contract

- native packet framing, authentication/integrity rules, and hardware ingress timestamp;
- independent sequence namespace for every channel/session epoch;
- duplicate, reorder, loss, replay-range, snapshot, and reconnect rules;
- complete MBO add/modify/cancel/execute semantics, including whether quantity reductions
  retain priority and whether replaces receive a new identifier;
- trading-state, price-band, auction, halt, bust/correct, and instrument-definition events;
- hidden, reserve, implied, pro-rata, size-time, or other allocation behavior; and
- an explicit rule that correlates an owned order-entry acknowledgement with its public MBO
  representation when the venue supports that correlation.

The implementation must keep private `VenueOrderId` and public `MarketByOrderId`
namespaces distinct and emit an `OwnedMboBinding` using either an explicit native field or
a named, certified deterministic rule. Numeric equality is not correlation evidence. The
binding's order-entry sequence must match the managed order's acceptance sequence before
the engine enables exact queue tracking. An exact-model adapter must implement
`NativeOwnedMboCorrelator`, advertise both `MARKET_DATA_L3` and
`OWNED_MBO_CORRELATION`, and pass `validate_exact_mbo_adapter` before opening transport.

If cancellation identity or owned-order correlation is unavailable, the adapter must not
select the exact price-time queue model. It must select a named conservative model and the
deployment evidence must quantify its bias.

## Order-entry contract

- authenticated logon/logoff, heartbeat/test request, inbound/outbound sequencing, replay,
  reset, and session-epoch transitions;
- new, cancel, venue-supported mass cancel, and cancel-on-disconnect encoding;
- every acknowledgement, reject, fill, partial fill, cancel race, duplicate execution,
  trade bust/correct, and unknown-order transition;
- self-trade prevention, maximum-message-rate, throttle, price/size band, and fat-finger
  behavior;
- transport-owned proof distinguishing `Sent` from `ProvenUnsent`; it must bind the exact
  session/protocol identity, scheduler commit/source/command slot, venue sequence, encoded
  byte prefix, and disposition timestamp. `ProvenUnsent` is permitted only when no byte was
  submitted to, consumed by, or observable to the peer; timeout, missing acknowledgement,
  and ambiguous queue ownership are never treated as unsent; and
- independent drop-copy reconciliation and a physically/operationally independent kill
  route where the venue/account supports one.

The production `NativeOrderTransport`, audit sink, and codec calls used by the live
coordinator must be bounded, nonblocking, and allocation-free after initialization. The
configured encoded-frame capacity must be protocol-derived and load-tested because byte
clearing and dirty-tail validation are bounded by that capacity. A native intent must be
durably reserved and recorded before submission; an ambiguous descriptor/peer outcome must
quiesce immediately and must never create synthetic feedback. A killed coordinator must
continue accepting authenticated acknowledgements, cancels, and fills so lifecycle and
inventory can converge, while definitively unsent kill cancels remain retryable.

All records for one reservation must become synchronously visible in program order within
one documented recovery domain before the corresponding audit call returns. Recovery must
scan incomplete tickets: a durable native intent without a disposition is terminally
ambiguous, never proven unsent; a source or scheduler record without a finished ticket must
be replayed according to its last durable application ordinal. Hardware persistence failure
after reservation is a fail-stop condition and must invoke certified cancel-on-disconnect or
an independent kill route rather than continuing with an unaudited transport.

## Deterministic conformance corpus

Certification must retain immutable native packet and expected-output fixtures for:

1. clean logon, snapshot, incremental recovery, quoting, partial fill, cancel, and logout;
2. every packet truncation boundary and invalid enum/scale/timestamp field;
3. duplicate, reordered, missing, wrapped, and session-reset sequences;
4. snapshot begin/end mismatch and buffered-incremental overlap;
5. reject, throttle, disconnect, heartbeat expiry, cancel-on-disconnect, and mass cancel;
6. fill-versus-cancel, replace-versus-fill, duplicate trade, bust, and correction races;
7. output-buffer exhaustion and decoder/encoder/correlator transactional rollback,
   including rejection after nested codec commits;
8. exact native-packet-to-normalized-event ordering, local owned-MBO binding association,
   scheduler command-slot consumption, sent/proven-unsent transport proofs, and encoded
   order bytes; and
9. live versus replay equality for book, exact queue, inventory/risk, lifecycle state, and
   outbound native decisions, with an authenticated manifest that detects a wholly omitted
   packet, scheduler commit, or output frame.

All fixtures must pass with zero heap allocations after initialization, strict linting, and
sanitizer/fuzz campaigns outside the production binary. Passing the venue's own conformance
environment and target-NIC load test is mandatory; repository unit tests do not substitute
for either.

## Deployment evidence

- NIC model/firmware, queue/RSS/flow-steering map, CPU/NUMA affinity, memory locking and page
  prefaulting, interrupt or polling policy, and chosen kernel-bypass/low-jitter stack;
- PTP grandmaster, NIC PHC discipline, UTC/TAI/leap handling, ingress and egress timestamp
  provenance, uncertainty bounds, and holdover/step drills;
- sustained and burst throughput with zero silent loss plus p50/p99/p99.9/p99.99 and maximum
  receive-to-decision and decision-to-wire latency; and
- restart, failover, control-plane loss, drop-copy divergence, and first-fault kill evidence.

Until those artifacts exist for one selected venue, the correct status is a venue-neutral
HFT core in development, not a live HFT system.
