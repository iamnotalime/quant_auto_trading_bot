# Authenticated retained-audit boundary

## Threat model and current bypasses

Journal v5 and scheduler-commit v1 CRC32C fields detect accidental corruption. They do
not authenticate an origin. Anyone able to edit retained bytes can change a field and
recompute its CRC. Because the CRC records are independent, an editor can also splice
records from another file, rewrite ordinals and CRCs, or construct a different stream.
The replay state rejects many accidental gaps and illegal semantic transitions, but it
cannot distinguish an attacker-built, internally consistent stream from the original.

A journal ending at a clean semantic boundary is accepted without an authenticated
expected length. Removing a complete suffix can therefore remain valid. Replacing the
entire journal with an older complete journal is also invisible locally. The
non-cryptographic replay digest does not close either hole. A scheduler commit's source
CRC has the same limitation and can be rewritten together with its source record.

`NativeLiveAudit` is currently a behavioral trait, not a concrete persistence
implementation. Its reservation, ordering, durability, and emergency-lane requirements
are contracts on the implementer. The repository tests use a fixed in-memory sink. The
checkpoint verifier is likewise an external interface; an implementation that always
returns success, validates only CRC, or accepts a caller-selected historical seal does
not establish authenticity or freshness. Even authentic coordinator checkpoint metadata
does not commit the complete reactor, venue session, adapter, transport, or control-gate
state. The core therefore rejects restoration of every runnable phase; only non-runnable
`Ambiguous` and `Failed` metadata can currently be reconstructed.

The canonical QHLR checkpoint codec and recovery scanner do not change that boundary.
QHLR's CRC32C is only an accidental-corruption check. The scanner consumes an already
`VerifiedAuditContainer` by value and returns evidence only; it neither constructs nor
authorizes a coordinator. It accepts exactly one final checkpoint, treats every intent as
unfinished, rejects unsupported facts and every header that names a predecessor because it
owns no predecessor semantic replay, and cannot see bytes stranded after the latest terminal
seal.

## Container v2 construction

`src/audit_container.rs` supplies an allocation-free framing and verification boundary:

1. A fixed authenticated header binds a unique container ID and generation, MAC
   algorithm/key IDs, first global record ordinal, monotonic-clock epoch, configuration
   digest, certified software digest, exact venue adapter/session, exact market-data and
   order-entry protocol/channel/session epochs, optional exact independent drop-copy
   protocol/channel/session epoch, exact authoritative instrument-definition binding
   (venue, instrument, native product, authority, artifact version and digest), and the
   prior rotated container's seal.
2. Every variable-length record authenticates its type, exact length, global ordinal,
   container ID/generation, prior tag, and payload. The prior-tag field forms one ordered
   chain starting at the header tag.
3. A fixed terminal seal authenticates the header tag, final chain tag, exact record
   count, and first/last ordinals. Verification requires the seal to be the final byte;
   a missing/partial seal and any trailing data are rejected.
4. Verification takes the exact expected header from deployment configuration and the
   exact expected terminal anchor from an independent freshness domain. Payload views
   are returned only after every tag, chain link, count, identity, seal, and anchor has
   passed.
5. Rotation generation `n` authenticates container `n-1`'s terminal seal tag. The caller
   must also verify the predecessor container/anchor under its declared key; a link is
   not a substitute for verifying the parent.

The library intentionally supplies no fallback checksum authenticator. A deployment must
implement `AuditAuthenticator` with a reviewed 256-bit MAC provider and
constant-time verification. The deterministic authenticator in the tests is explicitly a
test double and is not available from the library.

## QHLR checkpoint and non-authorizing recovery scan

`src/native_audit_codec.rs` supplies a canonical allocation-free QHLR v1 envelope for the
current live checkpoint. The complete checkpoint record is 220 bytes: a 32-byte header, a
184-byte body, and a four-byte CRC32C. It binds the scope ticket, venue/session identity,
authoritative instrument definition, market-data/order-entry/optional-drop-copy sources,
clock epoch, capture/frame/commit cursors, and recorded coordinator phase. Strict decoding
rejects unknown flags, reserved bytes, malformed optional values, invalid domains/phases,
length mismatch, trailing bytes, and CRC mismatch. The surrounding QHAC verification and
independent latest anchor, not QHLR, provide authenticity and freshness.

`src/native_recovery.rs` consumes a terminally verified container and accepts only a single
final QHLR checkpoint. It binds the checkpoint to the authenticated QHAC header and performs
the cursor checks possible without runtime owners. `Ready`, `SafetyPending`, and
`KilledRecovery` produce `OwnedReplayRequired`; `Ambiguous` and `Failed` produce
`ManualReconciliation`. These values are evidence classifications, never permission to run.
Every native intent remains uncertain because canonical disposition replay is not yet
implemented. Known or unknown extra facts, multiple/non-final checkpoints, and all rotated
headers that name a predecessor fail closed because this API owns no predecessor semantic replay.

## QHPA v1 structural committed-prefix anchor

`src/audit_prefix.rs` supplies stage-one, provider-neutral QHPA framing. One record is exactly
296 bytes: bytes `0..264` are the canonical message and bytes `264..296` hold an opaque
deployment-provided 256-bit tag. The codec validates exact lengths/version/reserved fields,
known flags, binding to the QHAC header identity and header tag, anchor sequencing, committed
file length, record ordinals and chain tag, summary state, and next-cursor claims.

That validation is structural only. The library neither creates nor verifies the tag and
does not flush a record, publish it with compare-and-swap, establish freshness, replay the
claimed prefix, or authorize recovery. The single ticket-state field and unresolved-intent
count are summary claims; they do not retain exact intent identity or prove lifecycle closure.
The next-cursor fields are claims, not externally owned leases. QHPA v1 is therefore a wire
contract on which the missing protocol can be built, not a crash-recovery verifier.

## Terminal-seal persistence order

For a finalized retained segment, the concrete sink must perform these operations in
order and fail-stop on any uncertain result:

1. Create a new, preallocated object for a never-reused container ID/generation.
2. Append and durably commit the authenticated header.
3. Append each complete authenticated record exactly once in returned order. Never
   advance/reuse the writer after an uncertain write result.
4. Append the terminal seal and durably flush the entire segment and its filesystem/object
   metadata.
5. Only after step 4 succeeds, atomically publish the returned `AuditAnchor` to the
   independent latest-only store.
6. Recovery first obtains the expected deployment header and latest anchor from trusted
   configuration/anchor services, then calls `verify_audit_container`. It must not select
   an anchor from the journal being verified.

Publishing the anchor before the seal is durable can make a recoverable segment appear
missing. Publishing neither after a successful seal leaves a valid newer file vulnerable
to rollback. Retrying an uncertain append by reusing a writer state can fork the chain;
the Rust writer is deliberately non-`Clone`, but the concrete I/O state machine must also
prevent retry forks after process or device failures.

This terminal-seal sequence is necessary for a cleanly finalized segment, but it is not a
crash-prefix protocol. A process can durably append a native intent and fail before producing
or publishing a terminal seal; `VerifiedAuditContainer` then exposes only the older anchored
history and the current scanner cannot observe the uncertain intent. A production design must
anchor each safe committed prefix often enough to make that tail recoverable without treating
an absent terminal seal as proof that no submission occurred.

## Release-blocking committed-prefix protocol

Before QHPA can participate in automatic recovery, the persistence/replay design must add and
prove all of the following as one protocol:

- canonical `Genesis`, `TicketOpen`/reservation-begin, exact intent, disposition, abort/fault,
  `EmergencyOpen`, checkpoint, and terminalization codecs, with lifecycle state derived by
  replay rather than trusted from the QHPA summary;
- exact unresolved-intent evidence that retains the ticket, record/frame identity, and
  transport context or digest. Ambiguity and proof faults remain sticky until an authenticated
  reconciliation fact closes that exact identity;
- globally monotonic cursor ownership. Either an independent service leases/burns record,
  frame, capture, commit, and ticket ranges, or the implementation proves strict
  no-use-until-successful-CAS for every domain. A durable pre-CAS tail must never permit an old
  anchor to reuse an ordinal after restart;
- crash-tail retirement and rotation semantics. QHAC v2 currently requires a predecessor
  terminal seal, so it cannot directly rotate away an unsealed crash prefix. Recovery needs
  authenticated exact-prefix terminalization or a later header protocol that binds the new
  generation to the verified prefix anchor;
- a pre-mutation `EmergencyOpen` commit. The emergency path may not mutate safety state first
  and attempt to explain it afterward;
- a reviewed authentication provider with protected keys and constant-time verification,
  an externally configured expected key/policy, durable append/flush behavior, and atomic
  authenticated latest-prefix CAS in an independent monotonic/WORM freshness domain; and
- a bounded concrete audit sink plus full canonical codecs and semantic replay for every
  `NativeLiveAudit` fact, returning the exact reconstructed runtime owners before any runnable
  coordinator can exist.

## Concrete `NativeLiveAudit` integration still required

The bounded next integration should stay venue/deployment-specific and add:

- versioned, canonical payload codecs for every remaining `NativeLiveAudit` call. QHLR now
  covers `NativeLiveCheckpoint`; raw ingress bytes, source events, scheduler commits, borrowed
  native intent bytes, transport-proof bytes, dispositions, every fault, abort marker, ticket
  lifecycle, emergency-open, and terminalization remain. The transmission fault contract must
  say whether feedback was Applied or Unapplied; the current reactor requests mandatory
  fail-stop containment after a post-dequeue fault, but its unresolved FIFO cannot be recovered
  by inference. Retained composite faults must also encode the full numeric risk/adverse
  payloads and underlying route cause rather than only the compact runtime summary;
- a concrete fixed-capacity sink that maps one reserved ticket to an unambiguous record
  sequence and proves all borrowed tails are copied before return;
- a semantic committed-prefix verifier that authenticates QHPA through the deployment
  provider, replays every exact ticket/intent/disposition lifecycle, proves predecessor
  closure and latest-anchor freshness, and reconstructs capture/frame/commit/ticket cursors
  without reuse. The current scanner is intentionally non-authorizing and terminal-seal-only;
- a certified append backend for the selected host (for example preallocated persistent
  memory or a bounded dedicated audit device path), with measured flush/failure behavior,
  an independently provisioned emergency slot, and fail-stop/cancel-on-disconnect wiring;
- a production `NativeLiveCheckpointVerifier` that verifies the exact container payload,
  latest externally stored anchor, and rotation/key policy; and
- an in-library recovery session that consumes the complete authenticated source,
  scheduler, native-ingress/egress, disposition, fault, and checkpoint trace while owning
  the exact reconstructed reactor, venue session, adapter, transport, and control state,
  then returns those same owners with the runnable coordinator so caller substitution is
  impossible.

Those codecs cannot be generic over an opaque `NativeOrderTransport::Proof`; the selected
transport must provide its canonical proof encoding and verification policy.

## External controls that software framing cannot replace

- protected MAC keys, reviewed implementation, key rotation, revocation, and
  algorithm policy (normally HSM/KMS-backed);
- a monotonic, independently replicated, or WORM latest-anchor store outside the journal
  writer's administrative and failure domain;
- atomic file/object creation, durable append/flush semantics, retention locks, backups,
  access control, and evidence that storage firmware honors those semantics;
- CSPRNG/unique allocation for container IDs and an authoritative non-reused generation
  counter;
- target-host crash/power-loss/fault-injection drills and operational reconciliation.

Without these external controls and the complete committed-prefix protocol, QHAC v2, QHLR
v1, and QHPA v1 are correctly bounded codecs (plus a narrow non-authorizing scanner), not
proof that a production audit history is durable, non-repudiable, rollback-free, or safe to
resume.
