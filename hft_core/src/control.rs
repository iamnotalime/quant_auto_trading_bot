//! Authenticated cold-control boundary for the allocation-free hot engine.
//!
//! This module does not define cryptography, key storage, transport, or IPC. A
//! production deployment must supply a reviewed [`ControlAuthenticator`] backed by
//! protected keys and an authenticated OS IPC channel. The gate only accepts frames
//! through that authenticator; its state-application function is intentionally private.

use crate::kill::{KillCode, KillLatch};
use crate::types::{Sequence, TimestampNs};

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct ControlProtocolVersion(pub u16);

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct ControlIdentity {
    pub controller_id: u64,
    pub engine_id: u64,
    pub deployment_id: u64,
}

impl ControlIdentity {
    #[must_use]
    pub const fn is_valid(self) -> bool {
        self.controller_id != 0 && self.engine_id != 0 && self.deployment_id != 0
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct ConfigDigest(pub [u8; 32]);

impl ConfigDigest {
    #[must_use]
    pub fn is_zero(self) -> bool {
        self.0.iter().all(|byte| *byte == 0)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControlGateConfig {
    pub protocol_version: ControlProtocolVersion,
    pub identity: ControlIdentity,
    pub config_digest: ConfigDigest,
    pub minimum_config_epoch: u64,
    pub first_command_sequence: Sequence,
    pub max_future_skew_ns: u64,
    pub max_command_lifetime_ns: u64,
    pub heartbeat_timeout_ns: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlCommand {
    Arm,
    Disarm,
    Heartbeat,
    Kill,
}

/// Fixed-size decoded representation produced by a trusted authenticator.
///
/// Constructing this value alone grants no authority: the gate exposes no public
/// method that accepts it. It is consumed only as the return value of
/// [`ControlAuthenticator::verify_and_decode`] during [`ControlGate::verify_and_apply`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedControl {
    pub protocol_version: ControlProtocolVersion,
    pub identity: ControlIdentity,
    pub config_digest: ConfigDigest,
    pub config_epoch: u64,
    pub command_sequence: Sequence,
    pub issued_at: TimestampNs,
    pub expires_at: TimestampNs,
    pub command: ControlCommand,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthenticationError {
    InvalidProof,
    MalformedFrame,
    ScratchTooSmall { required: usize, provided: usize },
    UnsupportedEncoding,
    InternalFailure,
}

/// External authentication boundary. Implementations may be stateless by using
/// `Checkpoint = ()`. Stateful codecs must checkpoint every parser, anti-replay,
/// hardware-token, and authentication counter so rejection can restore exact state.
pub trait ControlAuthenticator {
    type Checkpoint: Copy;

    fn checkpoint(&self) -> Self::Checkpoint;
    fn restore(&mut self, checkpoint: Self::Checkpoint);

    /// Authenticate and decode one caller-owned frame without allocating.
    ///
    /// # Errors
    ///
    /// Returns [`AuthenticationError`] when proof, framing, scratch capacity, or the
    /// external authentication service fails.
    fn verify_and_decode(
        &mut self,
        frame: &[u8],
        scratch: &mut [u8],
    ) -> Result<VerifiedControl, AuthenticationError>;

    fn commit(&mut self, _checkpoint: Self::Checkpoint) {}
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlPhase {
    Disarmed,
    Armed,
    Killed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlKillReason {
    AuthenticationFailure,
    ProtocolViolation,
    SequenceViolation,
    TimeViolation,
    ConfigurationViolation,
    InvalidState,
    LivenessExpired,
    Manual,
}

impl ControlKillReason {
    const fn latch_code(self) -> KillCode {
        match self {
            Self::Manual => KillCode::Manual,
            Self::LivenessExpired => KillCode::VenueDisconnect,
            Self::AuthenticationFailure
            | Self::ProtocolViolation
            | Self::SequenceViolation
            | Self::TimeViolation
            | Self::ConfigurationViolation
            | Self::InvalidState => KillCode::InternalInvariant,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControlKillRequest {
    pub reason: ControlKillReason,
    pub requested_at: TimestampNs,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EngineControlAction {
    Arm {
        config_epoch: u64,
        config_digest: ConfigDigest,
        lease_deadline: TimestampNs,
    },
    Disarm,
    Heartbeat {
        lease_deadline: TimestampNs,
    },
    Kill(ControlKillRequest),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ControlDecisionOrigin {
    AuthenticatedGate,
    JournalReplay,
}

/// Immutable result of one authenticated control-gate transition.
///
/// All payload fields are private so an accepted decision cannot be used as a
/// provenance carrier for a caller-modified action or timestamp. Journal replay
/// reconstructs the same payload with a distinct internal origin; live engine paths
/// reject that replay origin.
#[derive(Clone, Copy, Debug)]
pub struct ControlDecision {
    action: EngineControlAction,
    accepted_sequence: Sequence,
    next_sequence: Sequence,
    accepted_at: TimestampNs,
    kill_first_fault_acquired: Option<bool>,
    origin: ControlDecisionOrigin,
}

impl ControlDecision {
    pub(crate) const fn from_authenticated_event(
        action: EngineControlAction,
        accepted_sequence: Sequence,
        next_sequence: Sequence,
        accepted_at: TimestampNs,
        kill_first_fault_acquired: Option<bool>,
    ) -> Self {
        Self {
            action,
            accepted_sequence,
            next_sequence,
            accepted_at,
            kill_first_fault_acquired,
            origin: ControlDecisionOrigin::AuthenticatedGate,
        }
    }

    #[must_use]
    pub const fn action(self) -> EngineControlAction {
        self.action
    }

    #[must_use]
    pub const fn accepted_sequence(self) -> Sequence {
        self.accepted_sequence
    }

    #[must_use]
    pub const fn next_sequence(self) -> Sequence {
        self.next_sequence
    }

    #[must_use]
    pub const fn accepted_at(self) -> TimestampNs {
        self.accepted_at
    }

    #[must_use]
    pub const fn kill_first_fault_acquired(self) -> Option<bool> {
        self.kill_first_fault_acquired
    }

    pub(crate) const fn from_journal_replay(
        action: EngineControlAction,
        accepted_sequence: Sequence,
        next_sequence: Sequence,
        accepted_at: TimestampNs,
        kill_first_fault_acquired: Option<bool>,
    ) -> Self {
        Self {
            action,
            accepted_sequence,
            next_sequence,
            accepted_at,
            kill_first_fault_acquired,
            origin: ControlDecisionOrigin::JournalReplay,
        }
    }

    pub(crate) const fn origin(self) -> ControlDecisionOrigin {
        self.origin
    }
}

impl PartialEq for ControlDecision {
    fn eq(&self, other: &Self) -> bool {
        self.action == other.action
            && self.accepted_sequence == other.accepted_sequence
            && self.next_sequence == other.next_sequence
            && self.accepted_at == other.accepted_at
            && self.kill_first_fault_acquired == other.kill_first_fault_acquired
    }
}

impl Eq for ControlDecision {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlError {
    FrameCapacity {
        maximum: usize,
        received: usize,
    },
    ScratchCapacity {
        maximum: usize,
        received: usize,
    },
    AuthenticationFailed(AuthenticationError),
    ProtocolVersion {
        expected: ControlProtocolVersion,
        received: ControlProtocolVersion,
    },
    IdentityMismatch,
    ConfigDigestMismatch,
    ConfigEpochBelowMinimum {
        minimum: u64,
        received: u64,
    },
    ConfigEpochRollback {
        highest: u64,
        received: u64,
    },
    SequenceMismatch {
        expected: Sequence,
        received: Sequence,
    },
    SequenceExhausted,
    InvalidTimestamp(TimestampNs),
    ClockRollback {
        previous: TimestampNs,
        received: TimestampNs,
    },
    IssuedTimeRollback {
        previous: TimestampNs,
        received: TimestampNs,
    },
    IssuedInFuture {
        issued_at: TimestampNs,
        maximum_allowed: TimestampNs,
    },
    InvalidValidityWindow {
        issued_at: TimestampNs,
        expires_at: TimestampNs,
    },
    CommandLifetimeExceeded {
        maximum_ns: u64,
        received_ns: u64,
    },
    Expired {
        expires_at: TimestampNs,
        checked_at: TimestampNs,
    },
    TimeOverflow,
    InvalidState {
        phase: ControlPhase,
        command: ControlCommand,
    },
    KillAlreadyTriggered,
    LivenessExpired {
        deadline: TimestampNs,
        checked_at: TimestampNs,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControlFailure {
    pub error: ControlError,
    pub kill_request: ControlKillRequest,
    pub kill_first_fault_acquired: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlConfigError {
    Identity,
    Version,
    Digest,
    Epoch,
    Sequence,
    Bound,
    Capacity,
}

/// Fixed-state authenticated gate. The const capacities bound all caller-controlled
/// work; no method stores frames, owns a growable buffer, or allocates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControlGate<const MAX_FRAME_BYTES: usize, const MAX_SCRATCH_BYTES: usize> {
    config: ControlGateConfig,
    phase: ControlPhase,
    expected_sequence: Sequence,
    highest_config_epoch: u64,
    last_issued_at: TimestampNs,
    last_observed_utc: TimestampNs,
    liveness_deadline: TimestampNs,
}

impl<const MAX_FRAME_BYTES: usize, const MAX_SCRATCH_BYTES: usize>
    ControlGate<MAX_FRAME_BYTES, MAX_SCRATCH_BYTES>
{
    /// Build a disarmed gate with compile-time frame and scratch limits.
    ///
    /// # Errors
    ///
    /// Returns [`ControlConfigError`] when identity, protocol, digest, epoch,
    /// sequence, time bounds, or capacities are unsafe.
    pub fn new(config: ControlGateConfig) -> Result<Self, ControlConfigError> {
        if !config.identity.is_valid() {
            return Err(ControlConfigError::Identity);
        }
        if config.protocol_version.0 == 0 {
            return Err(ControlConfigError::Version);
        }
        if config.config_digest.is_zero() {
            return Err(ControlConfigError::Digest);
        }
        if config.minimum_config_epoch == 0 {
            return Err(ControlConfigError::Epoch);
        }
        if config.first_command_sequence.0 == 0 {
            return Err(ControlConfigError::Sequence);
        }
        if config.max_future_skew_ns == 0
            || config.max_command_lifetime_ns == 0
            || config.heartbeat_timeout_ns == 0
        {
            return Err(ControlConfigError::Bound);
        }
        if MAX_FRAME_BYTES == 0 || MAX_SCRATCH_BYTES == 0 {
            return Err(ControlConfigError::Capacity);
        }
        Ok(Self {
            phase: ControlPhase::Disarmed,
            expected_sequence: config.first_command_sequence,
            highest_config_epoch: config.minimum_config_epoch,
            config,
            last_issued_at: TimestampNs::ZERO,
            last_observed_utc: TimestampNs::ZERO,
            liveness_deadline: TimestampNs::ZERO,
        })
    }

    #[must_use]
    pub const fn phase(self) -> ControlPhase {
        self.phase
    }

    #[must_use]
    pub const fn expected_sequence(self) -> Sequence {
        self.expected_sequence
    }

    #[must_use]
    pub const fn highest_config_epoch(self) -> u64 {
        self.highest_config_epoch
    }

    #[must_use]
    pub const fn liveness_deadline(self) -> TimestampNs {
        self.liveness_deadline
    }

    /// Authenticate, validate, and atomically apply one cold-control frame.
    ///
    /// There is deliberately no public API accepting [`VerifiedControl`] directly.
    /// Authentication state is restored on every rejected frame, including failures
    /// that occur after successful proof verification.
    ///
    /// # Errors
    ///
    /// Returns [`ControlFailure`] and requests the first-fault kill latch for every
    /// authentication, protocol, sequence, time, configuration, state, or liveness
    /// violation.
    pub fn verify_and_apply<A: ControlAuthenticator>(
        &mut self,
        authenticator: &mut A,
        frame: &[u8],
        scratch: &mut [u8],
        now: TimestampNs,
        kill: &KillLatch,
    ) -> Result<ControlDecision, ControlFailure> {
        Self::scrub_scratch(scratch);
        if let Err(error) = self.preflight_call(frame, scratch, now) {
            Self::scrub_scratch(scratch);
            return Err(self.reject(error, now, kill));
        }

        let checkpoint = authenticator.checkpoint();
        let verified = match authenticator.verify_and_decode(frame, scratch) {
            Ok(verified) => verified,
            Err(error) => {
                authenticator.restore(checkpoint);
                Self::scrub_scratch(scratch);
                return Err(self.reject(ControlError::AuthenticationFailed(error), now, kill));
            }
        };
        if kill.is_triggered() && verified.command != ControlCommand::Kill {
            authenticator.restore(checkpoint);
            Self::scrub_scratch(scratch);
            return Err(self.reject(ControlError::KillAlreadyTriggered, now, kill));
        }

        let mut candidate = *self;
        let decision = match candidate.apply_verified(verified, now) {
            Ok(decision) => decision,
            Err(error) => {
                authenticator.restore(checkpoint);
                Self::scrub_scratch(scratch);
                return Err(self.reject(error, now, kill));
            }
        };
        authenticator.commit(checkpoint);
        *self = candidate;
        Self::scrub_scratch(scratch);

        let kill_first_fault_acquired = match decision.action() {
            EngineControlAction::Kill(request) => {
                Some(kill.trigger(request.reason.latch_code(), request.requested_at))
            }
            EngineControlAction::Arm { .. }
            | EngineControlAction::Disarm
            | EngineControlAction::Heartbeat { .. } => None,
        };
        Ok(ControlDecision {
            kill_first_fault_acquired,
            origin: ControlDecisionOrigin::AuthenticatedGate,
            ..decision
        })
    }

    /// Poll the armed heartbeat deadline. Expiry permanently kills this gate.
    ///
    /// # Errors
    ///
    /// Returns a kill-requesting [`ControlFailure`] for clock rollback or liveness
    /// expiry. Disarmed and already-killed gates have no active deadline.
    pub fn check_liveness(
        &mut self,
        now: TimestampNs,
        kill: &KillLatch,
    ) -> Result<(), ControlFailure> {
        if now == TimestampNs::ZERO {
            return Err(self.reject(ControlError::InvalidTimestamp(now), now, kill));
        }
        if self.last_observed_utc != TimestampNs::ZERO && now < self.last_observed_utc {
            return Err(self.reject(
                ControlError::ClockRollback {
                    previous: self.last_observed_utc,
                    received: now,
                },
                now,
                kill,
            ));
        }
        if self.phase == ControlPhase::Armed && now > self.liveness_deadline {
            return Err(self.reject(
                ControlError::LivenessExpired {
                    deadline: self.liveness_deadline,
                    checked_at: now,
                },
                now,
                kill,
            ));
        }
        self.last_observed_utc = now;
        Ok(())
    }

    fn preflight_call(
        &self,
        frame: &[u8],
        scratch: &[u8],
        now: TimestampNs,
    ) -> Result<(), ControlError> {
        if frame.is_empty() || frame.len() > MAX_FRAME_BYTES {
            return Err(ControlError::FrameCapacity {
                maximum: MAX_FRAME_BYTES,
                received: frame.len(),
            });
        }
        if scratch.is_empty() || scratch.len() > MAX_SCRATCH_BYTES {
            return Err(ControlError::ScratchCapacity {
                maximum: MAX_SCRATCH_BYTES,
                received: scratch.len(),
            });
        }
        if now == TimestampNs::ZERO {
            return Err(ControlError::InvalidTimestamp(now));
        }
        if self.last_observed_utc != TimestampNs::ZERO && now < self.last_observed_utc {
            return Err(ControlError::ClockRollback {
                previous: self.last_observed_utc,
                received: now,
            });
        }
        if self.phase == ControlPhase::Armed && now > self.liveness_deadline {
            return Err(ControlError::LivenessExpired {
                deadline: self.liveness_deadline,
                checked_at: now,
            });
        }
        Ok(())
    }

    fn scrub_scratch(scratch: &mut [u8]) {
        let scrubbed = scratch.len().min(MAX_SCRATCH_BYTES);
        scratch[..scrubbed].fill(0);
    }

    fn apply_verified(
        &mut self,
        verified: VerifiedControl,
        now: TimestampNs,
    ) -> Result<ControlDecision, ControlError> {
        self.validate_envelope(verified, now)?;
        let next_sequence = Sequence(
            self.expected_sequence
                .0
                .checked_add(1)
                .ok_or(ControlError::SequenceExhausted)?,
        );
        let action = self.apply_command(verified, now)?;
        self.expected_sequence = next_sequence;
        self.highest_config_epoch = self.highest_config_epoch.max(verified.config_epoch);
        self.last_issued_at = verified.issued_at;
        self.last_observed_utc = now;
        Ok(ControlDecision {
            action,
            accepted_sequence: verified.command_sequence,
            next_sequence,
            accepted_at: now,
            kill_first_fault_acquired: None,
            origin: ControlDecisionOrigin::AuthenticatedGate,
        })
    }

    fn validate_envelope(
        self,
        verified: VerifiedControl,
        now: TimestampNs,
    ) -> Result<(), ControlError> {
        if verified.protocol_version != self.config.protocol_version {
            return Err(ControlError::ProtocolVersion {
                expected: self.config.protocol_version,
                received: verified.protocol_version,
            });
        }
        if verified.identity != self.config.identity {
            return Err(ControlError::IdentityMismatch);
        }
        if verified.config_digest != self.config.config_digest {
            return Err(ControlError::ConfigDigestMismatch);
        }
        if verified.config_epoch < self.config.minimum_config_epoch {
            return Err(ControlError::ConfigEpochBelowMinimum {
                minimum: self.config.minimum_config_epoch,
                received: verified.config_epoch,
            });
        }
        if verified.config_epoch < self.highest_config_epoch {
            return Err(ControlError::ConfigEpochRollback {
                highest: self.highest_config_epoch,
                received: verified.config_epoch,
            });
        }
        if verified.command_sequence != self.expected_sequence {
            return Err(ControlError::SequenceMismatch {
                expected: self.expected_sequence,
                received: verified.command_sequence,
            });
        }
        self.validate_times(verified, now)
    }

    fn validate_times(
        self,
        verified: VerifiedControl,
        now: TimestampNs,
    ) -> Result<(), ControlError> {
        if verified.issued_at == TimestampNs::ZERO {
            return Err(ControlError::InvalidTimestamp(verified.issued_at));
        }
        if verified.expires_at == TimestampNs::ZERO {
            return Err(ControlError::InvalidTimestamp(verified.expires_at));
        }
        if self.last_issued_at != TimestampNs::ZERO && verified.issued_at < self.last_issued_at {
            return Err(ControlError::IssuedTimeRollback {
                previous: self.last_issued_at,
                received: verified.issued_at,
            });
        }
        if verified.expires_at <= verified.issued_at {
            return Err(ControlError::InvalidValidityWindow {
                issued_at: verified.issued_at,
                expires_at: verified.expires_at,
            });
        }
        let lifetime = verified
            .expires_at
            .checked_duration_since(verified.issued_at)
            .ok_or(ControlError::InvalidValidityWindow {
                issued_at: verified.issued_at,
                expires_at: verified.expires_at,
            })?;
        if lifetime > self.config.max_command_lifetime_ns {
            return Err(ControlError::CommandLifetimeExceeded {
                maximum_ns: self.config.max_command_lifetime_ns,
                received_ns: lifetime,
            });
        }
        let maximum_allowed = now
            .checked_add(self.config.max_future_skew_ns)
            .unwrap_or(TimestampNs(u64::MAX));
        if verified.issued_at > maximum_allowed {
            return Err(ControlError::IssuedInFuture {
                issued_at: verified.issued_at,
                maximum_allowed,
            });
        }
        if now > verified.expires_at {
            return Err(ControlError::Expired {
                expires_at: verified.expires_at,
                checked_at: now,
            });
        }
        Ok(())
    }

    fn apply_command(
        &mut self,
        verified: VerifiedControl,
        now: TimestampNs,
    ) -> Result<EngineControlAction, ControlError> {
        match verified.command {
            ControlCommand::Arm if self.phase == ControlPhase::Disarmed => {
                self.liveness_deadline = now
                    .checked_add(self.config.heartbeat_timeout_ns)
                    .ok_or(ControlError::TimeOverflow)?;
                self.phase = ControlPhase::Armed;
                Ok(EngineControlAction::Arm {
                    config_epoch: verified.config_epoch,
                    config_digest: verified.config_digest,
                    lease_deadline: self.liveness_deadline,
                })
            }
            ControlCommand::Disarm if self.phase == ControlPhase::Armed => {
                self.phase = ControlPhase::Disarmed;
                self.liveness_deadline = TimestampNs::ZERO;
                Ok(EngineControlAction::Disarm)
            }
            ControlCommand::Heartbeat if self.phase == ControlPhase::Armed => {
                self.liveness_deadline = now
                    .checked_add(self.config.heartbeat_timeout_ns)
                    .ok_or(ControlError::TimeOverflow)?;
                Ok(EngineControlAction::Heartbeat {
                    lease_deadline: self.liveness_deadline,
                })
            }
            ControlCommand::Kill => {
                self.phase = ControlPhase::Killed;
                self.liveness_deadline = TimestampNs::ZERO;
                Ok(EngineControlAction::Kill(ControlKillRequest {
                    reason: ControlKillReason::Manual,
                    requested_at: now,
                }))
            }
            command => Err(ControlError::InvalidState {
                phase: self.phase,
                command,
            }),
        }
    }

    fn reject(
        &mut self,
        error: ControlError,
        now: TimestampNs,
        kill: &KillLatch,
    ) -> ControlFailure {
        let reason = kill_reason(error);
        self.phase = ControlPhase::Killed;
        self.liveness_deadline = TimestampNs::ZERO;
        let request = ControlKillRequest {
            reason,
            requested_at: now,
        };
        let acquired = kill.trigger(reason.latch_code(), now);
        ControlFailure {
            error,
            kill_request: request,
            kill_first_fault_acquired: acquired,
        }
    }
}

const fn kill_reason(error: ControlError) -> ControlKillReason {
    match error {
        ControlError::AuthenticationFailed(_) => ControlKillReason::AuthenticationFailure,
        ControlError::ProtocolVersion { .. }
        | ControlError::IdentityMismatch
        | ControlError::FrameCapacity { .. }
        | ControlError::ScratchCapacity { .. } => ControlKillReason::ProtocolViolation,
        ControlError::SequenceMismatch { .. } | ControlError::SequenceExhausted => {
            ControlKillReason::SequenceViolation
        }
        ControlError::ConfigDigestMismatch
        | ControlError::ConfigEpochBelowMinimum { .. }
        | ControlError::ConfigEpochRollback { .. } => ControlKillReason::ConfigurationViolation,
        ControlError::InvalidTimestamp(_)
        | ControlError::ClockRollback { .. }
        | ControlError::IssuedTimeRollback { .. }
        | ControlError::IssuedInFuture { .. }
        | ControlError::InvalidValidityWindow { .. }
        | ControlError::CommandLifetimeExceeded { .. }
        | ControlError::Expired { .. }
        | ControlError::TimeOverflow => ControlKillReason::TimeViolation,
        ControlError::InvalidState { .. } | ControlError::KillAlreadyTriggered => {
            ControlKillReason::InvalidState
        }
        ControlError::LivenessExpired { .. } => ControlKillReason::LivenessExpired,
    }
}
