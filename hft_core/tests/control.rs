use core::alloc::{GlobalAlloc, Layout};
use core::cell::Cell;
use std::alloc::System;

use quant_hft_core::control::{
    AuthenticationError, ConfigDigest, ControlAuthenticator, ControlCommand, ControlDecision,
    ControlError, ControlGate, ControlGateConfig, ControlIdentity, ControlKillReason, ControlPhase,
    ControlProtocolVersion, EngineControlAction, VerifiedControl,
};
use quant_hft_core::kill::{KillCode, KillLatch};
use quant_hft_core::{Sequence, TimestampNs};

const FRAME_BYTES: usize = 99;
const IDENTITY: ControlIdentity = ControlIdentity {
    controller_id: 11,
    engine_id: 22,
    deployment_id: 33,
};
const DIGEST: ConfigDigest = ConfigDigest([0xA5; 32]);

thread_local! {
    static TRACK_ALLOCATIONS: Cell<bool> = const { Cell::new(false) };
    static ALLOCATION_COUNT: Cell<usize> = const { Cell::new(0) };
}

struct ThreadTrackingAllocator;

#[global_allocator]
static ALLOCATOR: ThreadTrackingAllocator = ThreadTrackingAllocator;

unsafe impl GlobalAlloc for ThreadTrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record_allocation();
        // SAFETY: This allocator delegates the unchanged layout to the system allocator.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record_allocation();
        // SAFETY: This allocator delegates the unchanged layout to the system allocator.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: `pointer` and `layout` originated from the delegated system allocator.
        unsafe { System.dealloc(pointer, layout) };
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        record_allocation();
        // SAFETY: The allocation originated from `System`; its original layout and requested
        // new size are forwarded unchanged.
        unsafe { System.realloc(pointer, layout, new_size) }
    }
}

fn record_allocation() {
    TRACK_ALLOCATIONS.with(|tracking| {
        if tracking.get() {
            ALLOCATION_COUNT.with(|count| count.set(count.get().saturating_add(1)));
        }
    });
}

fn begin_allocation_count() {
    TRACK_ALLOCATIONS.with(|tracking| tracking.set(false));
    ALLOCATION_COUNT.with(|count| count.set(0));
    TRACK_ALLOCATIONS.with(|tracking| tracking.set(true));
}

fn end_allocation_count() -> usize {
    TRACK_ALLOCATIONS.with(|tracking| tracking.set(false));
    ALLOCATION_COUNT.with(Cell::get)
}

#[derive(Debug, Default)]
struct FakeMacAuthenticator {
    committed_verifications: u64,
}

impl ControlAuthenticator for FakeMacAuthenticator {
    type Checkpoint = u64;

    fn checkpoint(&self) -> Self::Checkpoint {
        self.committed_verifications
    }

    fn restore(&mut self, checkpoint: Self::Checkpoint) {
        self.committed_verifications = checkpoint;
    }

    fn verify_and_decode(
        &mut self,
        frame: &[u8],
        scratch: &mut [u8],
    ) -> Result<VerifiedControl, AuthenticationError> {
        self.committed_verifications = self.committed_verifications.wrapping_add(1);
        if scratch.len() < 8 {
            return Err(AuthenticationError::ScratchTooSmall {
                required: 8,
                provided: scratch.len(),
            });
        }
        if frame.len() != FRAME_BYTES {
            return Err(AuthenticationError::MalformedFrame);
        }
        let supplied_tag = read_u64(frame, 91).ok_or(AuthenticationError::MalformedFrame)?;
        if supplied_tag != fake_mac(&frame[..91]) {
            return Err(AuthenticationError::InvalidProof);
        }
        scratch[..8].copy_from_slice(&supplied_tag.to_le_bytes());
        let command = match frame[90] {
            1 => ControlCommand::Arm,
            2 => ControlCommand::Disarm,
            3 => ControlCommand::Heartbeat,
            4 => ControlCommand::Kill,
            _ => return Err(AuthenticationError::UnsupportedEncoding),
        };
        let mut digest = [0_u8; 32];
        digest.copy_from_slice(&frame[26..58]);
        Ok(VerifiedControl {
            protocol_version: ControlProtocolVersion(
                read_u16(frame, 0).ok_or(AuthenticationError::MalformedFrame)?,
            ),
            identity: ControlIdentity {
                controller_id: read_u64(frame, 2).ok_or(AuthenticationError::MalformedFrame)?,
                engine_id: read_u64(frame, 10).ok_or(AuthenticationError::MalformedFrame)?,
                deployment_id: read_u64(frame, 18).ok_or(AuthenticationError::MalformedFrame)?,
            },
            config_digest: ConfigDigest(digest),
            config_epoch: read_u64(frame, 58).ok_or(AuthenticationError::MalformedFrame)?,
            command_sequence: Sequence(
                read_u64(frame, 66).ok_or(AuthenticationError::MalformedFrame)?,
            ),
            issued_at: TimestampNs(read_u64(frame, 74).ok_or(AuthenticationError::MalformedFrame)?),
            expires_at: TimestampNs(
                read_u64(frame, 82).ok_or(AuthenticationError::MalformedFrame)?,
            ),
            command,
        })
    }
}

type Gate = ControlGate<128, 64>;

#[test]
fn authenticated_arm_heartbeat_and_disarm_emit_typed_actions() {
    let mut gate = gate();
    let mut authenticator = FakeMacAuthenticator::default();
    let kill = KillLatch::new();
    let mut scratch = [0xCC; 32];

    let arm = process(
        &mut gate,
        &mut authenticator,
        frame(10, 95, 150, 5, ControlCommand::Arm),
        &mut scratch,
        100,
        &kill,
    )
    .unwrap();
    assert_eq!(
        arm.action(),
        EngineControlAction::Arm {
            config_epoch: 5,
            config_digest: DIGEST,
            lease_deadline: TimestampNs(150),
        }
    );
    assert_eq!(gate.phase(), ControlPhase::Armed);
    assert_eq!(gate.liveness_deadline(), TimestampNs(150));
    assert!(scratch.iter().all(|byte| *byte == 0));

    let heartbeat = process(
        &mut gate,
        &mut authenticator,
        frame(11, 120, 180, 5, ControlCommand::Heartbeat),
        &mut scratch,
        125,
        &kill,
    )
    .unwrap();
    assert_eq!(
        heartbeat.action(),
        EngineControlAction::Heartbeat {
            lease_deadline: TimestampNs(175),
        }
    );
    assert_eq!(gate.liveness_deadline(), TimestampNs(175));

    let disarm = process(
        &mut gate,
        &mut authenticator,
        frame(12, 130, 190, 5, ControlCommand::Disarm),
        &mut scratch,
        135,
        &kill,
    )
    .unwrap();
    assert_eq!(disarm.action(), EngineControlAction::Disarm);
    assert_eq!(gate.phase(), ControlPhase::Disarmed);
    assert_eq!(gate.expected_sequence(), Sequence(13));
    assert_eq!(authenticator.committed_verifications, 3);
    assert!(!kill.is_triggered());
}

#[test]
fn invalid_mac_cannot_reach_apply_and_restores_authenticator() {
    let mut gate = gate();
    let mut authenticator = FakeMacAuthenticator::default();
    let kill = KillLatch::new();
    let mut scratch = [0xCC; 32];
    let mut invalid = frame(10, 95, 150, 5, ControlCommand::Arm);
    invalid[98] ^= 1;

    let failure = process(
        &mut gate,
        &mut authenticator,
        invalid,
        &mut scratch,
        100,
        &kill,
    )
    .unwrap_err();
    assert_eq!(
        failure.error,
        ControlError::AuthenticationFailed(AuthenticationError::InvalidProof)
    );
    assert_eq!(
        failure.kill_request.reason,
        ControlKillReason::AuthenticationFailure
    );
    assert!(failure.kill_first_fault_acquired);
    assert_eq!(authenticator.committed_verifications, 0);
    assert_eq!(gate.expected_sequence(), Sequence(10));
    assert_eq!(gate.phase(), ControlPhase::Killed);
    assert!(scratch.iter().all(|byte| *byte == 0));
    assert_eq!(kill.snapshot().unwrap().code, KillCode::InternalInvariant);
}

#[test]
fn replay_and_clock_rollback_are_fail_closed_and_transactional() {
    let mut replay_gate = gate();
    let mut replay_auth = FakeMacAuthenticator::default();
    let replay_kill = KillLatch::new();
    let mut scratch = [0_u8; 32];
    let arm = frame(10, 95, 150, 5, ControlCommand::Arm);
    process(
        &mut replay_gate,
        &mut replay_auth,
        arm,
        &mut scratch,
        100,
        &replay_kill,
    )
    .unwrap();
    let failure = process(
        &mut replay_gate,
        &mut replay_auth,
        arm,
        &mut scratch,
        101,
        &replay_kill,
    )
    .unwrap_err();
    assert_eq!(
        failure.error,
        ControlError::SequenceMismatch {
            expected: Sequence(11),
            received: Sequence(10),
        }
    );
    assert_eq!(replay_auth.committed_verifications, 1);
    assert_eq!(replay_gate.expected_sequence(), Sequence(11));

    let mut rollback_gate = gate();
    let mut rollback_auth = FakeMacAuthenticator::default();
    let rollback_kill = KillLatch::new();
    process(
        &mut rollback_gate,
        &mut rollback_auth,
        arm,
        &mut scratch,
        100,
        &rollback_kill,
    )
    .unwrap();
    let rollback = process(
        &mut rollback_gate,
        &mut rollback_auth,
        frame(11, 96, 151, 5, ControlCommand::Heartbeat),
        &mut scratch,
        99,
        &rollback_kill,
    )
    .unwrap_err();
    assert_eq!(
        rollback.error,
        ControlError::ClockRollback {
            previous: TimestampNs(100),
            received: TimestampNs(99),
        }
    );
    assert_eq!(rollback_auth.committed_verifications, 1);
}

#[test]
fn future_expired_and_wrong_digest_frames_fail() {
    let mut scratch = [0_u8; 32];

    let mut future_gate = gate();
    let mut future_auth = FakeMacAuthenticator::default();
    let future_kill = KillLatch::new();
    let future = process(
        &mut future_gate,
        &mut future_auth,
        frame(10, 111, 150, 5, ControlCommand::Arm),
        &mut scratch,
        100,
        &future_kill,
    )
    .unwrap_err();
    assert_eq!(
        future.error,
        ControlError::IssuedInFuture {
            issued_at: TimestampNs(111),
            maximum_allowed: TimestampNs(110),
        }
    );
    assert_eq!(future_auth.committed_verifications, 0);

    let mut expired_gate = gate();
    let mut expired_auth = FakeMacAuthenticator::default();
    let expired_kill = KillLatch::new();
    let expired = process(
        &mut expired_gate,
        &mut expired_auth,
        frame(10, 80, 90, 5, ControlCommand::Arm),
        &mut scratch,
        100,
        &expired_kill,
    )
    .unwrap_err();
    assert_eq!(
        expired.error,
        ControlError::Expired {
            expires_at: TimestampNs(90),
            checked_at: TimestampNs(100),
        }
    );

    let mut digest_gate = gate();
    let mut digest_auth = FakeMacAuthenticator::default();
    let digest_kill = KillLatch::new();
    let mut wrong_digest = verified(10, 95, 150, 5, ControlCommand::Arm);
    wrong_digest.config_digest = ConfigDigest([0x5A; 32]);
    let digest_failure = process(
        &mut digest_gate,
        &mut digest_auth,
        encode(wrong_digest),
        &mut scratch,
        100,
        &digest_kill,
    )
    .unwrap_err();
    assert_eq!(digest_failure.error, ControlError::ConfigDigestMismatch);
    assert_eq!(digest_auth.committed_verifications, 0);
}

#[test]
fn stale_config_cannot_rearm_after_a_newer_epoch() {
    let mut gate = gate();
    let mut authenticator = FakeMacAuthenticator::default();
    let kill = KillLatch::new();
    let mut scratch = [0_u8; 32];
    process(
        &mut gate,
        &mut authenticator,
        frame(10, 95, 150, 6, ControlCommand::Arm),
        &mut scratch,
        100,
        &kill,
    )
    .unwrap();
    process(
        &mut gate,
        &mut authenticator,
        frame(11, 105, 160, 6, ControlCommand::Disarm),
        &mut scratch,
        110,
        &kill,
    )
    .unwrap();
    let stale = process(
        &mut gate,
        &mut authenticator,
        frame(12, 115, 170, 5, ControlCommand::Arm),
        &mut scratch,
        120,
        &kill,
    )
    .unwrap_err();
    assert_eq!(
        stale.error,
        ControlError::ConfigEpochRollback {
            highest: 6,
            received: 5,
        }
    );
    assert_eq!(authenticator.committed_verifications, 2);
    assert_eq!(gate.phase(), ControlPhase::Killed);
    assert_eq!(gate.expected_sequence(), Sequence(12));
}

#[test]
fn heartbeat_expiry_requests_kill_and_cannot_be_resurrected() {
    let mut gate = gate();
    let mut authenticator = FakeMacAuthenticator::default();
    let kill = KillLatch::new();
    let mut scratch = [0_u8; 32];
    process(
        &mut gate,
        &mut authenticator,
        frame(10, 95, 150, 5, ControlCommand::Arm),
        &mut scratch,
        100,
        &kill,
    )
    .unwrap();
    let failure = gate.check_liveness(TimestampNs(151), &kill).unwrap_err();
    assert_eq!(
        failure.error,
        ControlError::LivenessExpired {
            deadline: TimestampNs(150),
            checked_at: TimestampNs(151),
        }
    );
    assert_eq!(
        failure.kill_request.reason,
        ControlKillReason::LivenessExpired
    );
    assert_eq!(gate.phase(), ControlPhase::Killed);
    assert_eq!(kill.snapshot().unwrap().code, KillCode::VenueDisconnect);
}

#[test]
fn manual_kill_respects_an_existing_first_fault() {
    let mut gate = gate();
    let mut authenticator = FakeMacAuthenticator::default();
    let kill = KillLatch::new();
    assert!(kill.trigger(KillCode::RiskLimit, TimestampNs(90)));
    let mut scratch = [0_u8; 32];
    let decision = process(
        &mut gate,
        &mut authenticator,
        frame(10, 95, 150, 5, ControlCommand::Kill),
        &mut scratch,
        100,
        &kill,
    )
    .unwrap();
    assert!(matches!(
        decision.action(),
        EngineControlAction::Kill(request) if request.reason == ControlKillReason::Manual
    ));
    assert_eq!(decision.kill_first_fault_acquired(), Some(false));
    assert_eq!(gate.phase(), ControlPhase::Killed);
    assert_eq!(kill.snapshot().unwrap().code, KillCode::RiskLimit);
}

#[test]
fn verified_control_call_performs_no_heap_allocation() {
    let mut gate = gate();
    let mut authenticator = FakeMacAuthenticator::default();
    let kill = KillLatch::new();
    let mut scratch = [0_u8; 32];
    let encoded = frame(10, 95, 150, 5, ControlCommand::Arm);

    // Initialize thread-local counters before entering the measured section.
    let _ = end_allocation_count();
    begin_allocation_count();
    let result = gate.verify_and_apply(
        &mut authenticator,
        &encoded,
        &mut scratch,
        TimestampNs(100),
        &kill,
    );
    let allocations = end_allocation_count();

    assert!(result.is_ok());
    assert_eq!(allocations, 0);
}

fn gate() -> Gate {
    Gate::new(ControlGateConfig {
        protocol_version: ControlProtocolVersion(1),
        identity: IDENTITY,
        config_digest: DIGEST,
        minimum_config_epoch: 5,
        first_command_sequence: Sequence(10),
        max_future_skew_ns: 10,
        max_command_lifetime_ns: 100,
        heartbeat_timeout_ns: 50,
    })
    .unwrap()
}

fn process(
    gate: &mut Gate,
    authenticator: &mut FakeMacAuthenticator,
    frame: [u8; FRAME_BYTES],
    scratch: &mut [u8],
    now: u64,
    kill: &KillLatch,
) -> Result<ControlDecision, quant_hft_core::control::ControlFailure> {
    gate.verify_and_apply(authenticator, &frame, scratch, TimestampNs(now), kill)
}

fn frame(
    sequence: u64,
    issued_at: u64,
    expires_at: u64,
    config_epoch: u64,
    command: ControlCommand,
) -> [u8; FRAME_BYTES] {
    encode(verified(
        sequence,
        issued_at,
        expires_at,
        config_epoch,
        command,
    ))
}

fn verified(
    sequence: u64,
    issued_at: u64,
    expires_at: u64,
    config_epoch: u64,
    command: ControlCommand,
) -> VerifiedControl {
    VerifiedControl {
        protocol_version: ControlProtocolVersion(1),
        identity: IDENTITY,
        config_digest: DIGEST,
        config_epoch,
        command_sequence: Sequence(sequence),
        issued_at: TimestampNs(issued_at),
        expires_at: TimestampNs(expires_at),
        command,
    }
}

fn encode(control: VerifiedControl) -> [u8; FRAME_BYTES] {
    let mut output = [0_u8; FRAME_BYTES];
    write_u16(&mut output, 0, control.protocol_version.0);
    write_u64(&mut output, 2, control.identity.controller_id);
    write_u64(&mut output, 10, control.identity.engine_id);
    write_u64(&mut output, 18, control.identity.deployment_id);
    output[26..58].copy_from_slice(&control.config_digest.0);
    write_u64(&mut output, 58, control.config_epoch);
    write_u64(&mut output, 66, control.command_sequence.0);
    write_u64(&mut output, 74, control.issued_at.0);
    write_u64(&mut output, 82, control.expires_at.0);
    output[90] = match control.command {
        ControlCommand::Arm => 1,
        ControlCommand::Disarm => 2,
        ControlCommand::Heartbeat => 3,
        ControlCommand::Kill => 4,
    };
    let tag = fake_mac(&output[..91]);
    write_u64(&mut output, 91, tag);
    output
}

// Test-only deterministic tag. This is intentionally not a production MAC.
fn fake_mac(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xCBF2_9CE4_8422_2325, |state, byte| {
        state
            .wrapping_mul(0x0000_0100_0000_01B3)
            .wrapping_add(u64::from(*byte))
    })
}

fn write_u64(output: &mut [u8], offset: usize, value: u64) {
    output[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn write_u16(output: &mut [u8], offset: usize, value: u16) {
    output[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn read_u64(input: &[u8], offset: usize) -> Option<u64> {
    let bytes = input.get(offset..offset + 8)?;
    let mut value = [0_u8; 8];
    value.copy_from_slice(bytes);
    Some(u64::from_le_bytes(value))
}

fn read_u16(input: &[u8], offset: usize) -> Option<u16> {
    let bytes = input.get(offset..offset + 2)?;
    let mut value = [0_u8; 2];
    value.copy_from_slice(bytes);
    Some(u16::from_le_bytes(value))
}
