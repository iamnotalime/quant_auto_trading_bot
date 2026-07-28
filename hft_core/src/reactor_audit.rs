//! Fixed-width scheduler commits binding capture records to reactor application order.
//!
//! CRC32C detects accidental corruption only. Production authenticity and rollback
//! protection require an authenticated append-only container and an external anchor.

use crate::engine_replay::EngineReplayRoute;
use crate::event_codec::{EventCodecError, ReplayInput, decode_replay_input};
use crate::events::{CaptureOrdinal, NormalizedEvent};
use crate::journal::{RECORD_LEN, crc32c, encode_record};
use crate::order_command_codec::{
    ORDER_COMMAND_WIRE_LEN, decode_order_command, encode_order_command,
};
use crate::reactor::{
    HotPathReactor, InputOrdinal, MAX_REACTOR_COMMANDS_PER_INPUT, ReactorEgress, ReactorInputKind,
    ReactorRunReport, ReactorStop, RunOrdinal,
};
use crate::reactor_replay::{
    ReactorReplayError, ReactorReplayOutcome, dispatch_reactor_replay_event,
    dispatch_reactor_replay_retention, dispatch_reactor_replay_safety_kill,
};
use crate::venue::OrderCommand;

pub const SCHEDULER_COMMIT_MAGIC: [u8; 4] = *b"QHSC";
pub const SCHEDULER_COMMIT_VERSION: u16 = 1;
pub const SCHEDULER_COMMIT_HEADER_LEN: usize = 68;
pub const SCHEDULER_COMMIT_RECORD_LEN: usize = 184;

const CHECKSUM_OFFSET: usize = 180;
const FIRST_COMMAND_OFFSET: usize = 68;
const SECOND_COMMAND_OFFSET: usize = FIRST_COMMAND_OFFSET + ORDER_COMMAND_WIRE_LEN;
const SCHEDULER_COMMIT_HEADER_LEN_WIRE: u16 = 68;
const SCHEDULER_COMMIT_RECORD_LEN_WIRE: u32 = 184;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum SchedulerRoute {
    NoEngineInput = 0,
    Normal = 1,
    PriorityTransmission = 2,
    RetainedNormal = 3,
    SafetyKill = 4,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SchedulerCommit {
    pub commit_ordinal: u64,
    pub route: SchedulerRoute,
    pub input_kind: Option<ReactorInputKind>,
    pub run_ordinal: Option<RunOrdinal>,
    pub input_ordinal: Option<InputOrdinal>,
    pub egress_input_ordinal: Option<InputOrdinal>,
    pub capture_ordinal: CaptureOrdinal,
    pub source_event_crc32c: u32,
    pub commands: [Option<OrderCommand>; MAX_REACTOR_COMMANDS_PER_INPUT],
    pub outstanding_transmissions: u8,
    pub event_retained: bool,
    pub mandatory_kill_pending: bool,
    pub stop: Option<ReactorStop>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchedulerCommitError {
    BufferTooSmall { required: usize, available: usize },
    InvalidMagic,
    UnsupportedVersion(u16),
    InvalidHeaderLength(u16),
    InvalidRecordLength(u32),
    ChecksumMismatch { recorded: u32, calculated: u32 },
    InvalidRoute(u8),
    InvalidInputKind(u8),
    InvalidStop(u8),
    InvalidFlags(u8),
    InvalidCommand,
    InvalidRecord,
    IntegerOutOfRange(u64),
    SourceEvent(EventCodecError),
    SourceMismatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchedulerReplayError {
    ReplayFailed,
    InvalidFirstCommitOrdinal,
    CommitOrdinalMismatch { expected: u64, actual: u64 },
    CommitOrdinalExhausted,
    RetainedBindingMissing,
    RetainedBindingUnexpected,
    RetainedBindingAlreadyPending,
    RetainedSourceMismatch,
    Commit(SchedulerCommitError),
    Reactor(ReactorReplayError),
    CommitMismatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RetainedSourceBinding {
    capture_ordinal: CaptureOrdinal,
    source_event_crc32c: u32,
}

/// Fail-latched verifier for application-ordered scheduler commits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SchedulerCommitVerifier {
    next_commit_ordinal: u64,
    retained_source: Option<RetainedSourceBinding>,
    failed: bool,
}

impl SchedulerCommitVerifier {
    /// Create a verifier at the expected first scheduler commit.
    ///
    /// # Errors
    ///
    /// Returns an error because zero is reserved and cannot identify a commit.
    #[allow(
        clippy::result_large_err,
        reason = "verifier creation shares the exact fixed replay failure type"
    )]
    pub const fn new(expected_first_commit_ordinal: u64) -> Result<Self, SchedulerReplayError> {
        if expected_first_commit_ordinal == 0 {
            return Err(SchedulerReplayError::InvalidFirstCommitOrdinal);
        }
        Ok(Self {
            next_commit_ordinal: expected_first_commit_ordinal,
            retained_source: None,
            failed: false,
        })
    }

    #[must_use]
    pub const fn is_failed(self) -> bool {
        self.failed
    }

    #[must_use]
    pub const fn next_commit_ordinal(self) -> u64 {
        self.next_commit_ordinal
    }

    /// Verify source binding, execute through the real reactor, and require the
    /// resulting scheduler commit to equal the recorded commit exactly.
    ///
    /// Journal framing and source-sequence validation remain the responsibility of
    /// [`crate::journal::ReplayState`] before commits reach this verifier.
    ///
    /// # Errors
    ///
    /// Any source, ordinal, reactor, or result mismatch permanently latches failure.
    #[allow(
        clippy::result_large_err,
        reason = "certification retains the exact fixed reactor failure"
    )]
    pub fn verify_and_dispatch<
        const MAX_BOOK_ORDERS: usize,
        const MAX_BOOK_LEVELS: usize,
        const MAX_ORDERS: usize,
        const MAX_RECENT_TRADES: usize,
        const MAX_FILLS: usize,
    >(
        &mut self,
        reactor: &mut HotPathReactor<
            MAX_BOOK_ORDERS,
            MAX_BOOK_LEVELS,
            MAX_ORDERS,
            MAX_RECENT_TRADES,
            MAX_FILLS,
        >,
        source_event: NormalizedEvent,
        expected_commit: SchedulerCommit,
        egress: &mut [Option<ReactorEgress>; MAX_REACTOR_COMMANDS_PER_INPUT],
    ) -> Result<ReactorReplayOutcome, SchedulerReplayError> {
        if self.failed {
            return Err(SchedulerReplayError::ReplayFailed);
        }
        if expected_commit.commit_ordinal != self.next_commit_ordinal {
            return self.fail(SchedulerReplayError::CommitOrdinalMismatch {
                expected: self.next_commit_ordinal,
                actual: expected_commit.commit_ordinal,
            });
        }
        let Some(next) = self.next_commit_ordinal.checked_add(1) else {
            return self.fail(SchedulerReplayError::CommitOrdinalExhausted);
        };
        if let Err(error) = expected_commit.validate() {
            return self.fail(SchedulerReplayError::Commit(error));
        }
        if expected_commit.route == SchedulerRoute::SafetyKill {
            return self.fail(SchedulerReplayError::CommitMismatch);
        }
        if let Err(error) = expected_commit.verify_source(source_event) {
            return self.fail(SchedulerReplayError::Commit(error));
        }
        let completes_retained =
            expected_commit.route == SchedulerRoute::Normal && self.retained_source.is_some();
        match (expected_commit.route, self.retained_source) {
            (SchedulerRoute::RetainedNormal, Some(_)) => {
                return self.fail(SchedulerReplayError::RetainedBindingAlreadyPending);
            }
            (SchedulerRoute::Normal, Some(binding))
                if binding.capture_ordinal != expected_commit.capture_ordinal
                    || binding.source_event_crc32c != expected_commit.source_event_crc32c =>
            {
                return self.fail(SchedulerReplayError::RetainedSourceMismatch);
            }
            _ => {}
        }
        let replay = if expected_commit.route == SchedulerRoute::RetainedNormal {
            dispatch_reactor_replay_retention(reactor, source_event)
        } else {
            dispatch_reactor_replay_event(reactor, source_event, egress)
        };
        let outcome = match replay {
            Ok(outcome) => outcome,
            Err(error) => return self.fail(SchedulerReplayError::Reactor(error)),
        };
        let actual_commit = match SchedulerCommit::from_replay_outcome(
            self.next_commit_ordinal,
            source_event,
            outcome,
            egress,
        ) {
            Ok(commit) => commit,
            Err(error) => return self.fail(SchedulerReplayError::Commit(error)),
        };
        if actual_commit != expected_commit {
            return self.fail(SchedulerReplayError::CommitMismatch);
        }
        if expected_commit.route == SchedulerRoute::RetainedNormal {
            self.retained_source = Some(RetainedSourceBinding {
                capture_ordinal: expected_commit.capture_ordinal,
                source_event_crc32c: expected_commit.source_event_crc32c,
            });
        } else if completes_retained {
            self.retained_source = None;
        }
        self.next_commit_ordinal = next;
        Ok(outcome)
    }

    /// Execute one source-less mandatory safety-kill run and require its scheduler
    /// commit to equal the recorded commit exactly.
    ///
    /// # Errors
    ///
    /// Any ordinal, route, reactor, or result mismatch permanently latches failure.
    #[allow(
        clippy::result_large_err,
        reason = "certification retains the exact fixed reactor failure"
    )]
    pub fn verify_and_dispatch_safety<
        const MAX_BOOK_ORDERS: usize,
        const MAX_BOOK_LEVELS: usize,
        const MAX_ORDERS: usize,
        const MAX_RECENT_TRADES: usize,
        const MAX_FILLS: usize,
    >(
        &mut self,
        reactor: &mut HotPathReactor<
            MAX_BOOK_ORDERS,
            MAX_BOOK_LEVELS,
            MAX_ORDERS,
            MAX_RECENT_TRADES,
            MAX_FILLS,
        >,
        expected_commit: SchedulerCommit,
        egress: &mut [Option<ReactorEgress>; MAX_REACTOR_COMMANDS_PER_INPUT],
    ) -> Result<ReactorReplayOutcome, SchedulerReplayError> {
        if self.failed {
            return Err(SchedulerReplayError::ReplayFailed);
        }
        if expected_commit.commit_ordinal != self.next_commit_ordinal {
            return self.fail(SchedulerReplayError::CommitOrdinalMismatch {
                expected: self.next_commit_ordinal,
                actual: expected_commit.commit_ordinal,
            });
        }
        let Some(next) = self.next_commit_ordinal.checked_add(1) else {
            return self.fail(SchedulerReplayError::CommitOrdinalExhausted);
        };
        if let Err(error) = expected_commit.validate() {
            return self.fail(SchedulerReplayError::Commit(error));
        }
        if expected_commit.route != SchedulerRoute::SafetyKill {
            return self.fail(SchedulerReplayError::CommitMismatch);
        }
        match (expected_commit.event_retained, self.retained_source) {
            (true, None) => {
                return self.fail(SchedulerReplayError::RetainedBindingMissing);
            }
            (false, Some(_)) => {
                return self.fail(SchedulerReplayError::RetainedBindingUnexpected);
            }
            _ => {}
        }
        if !expected_commit.event_retained {
            if reactor.has_retained_event() || reactor.mandatory_kill_pending() {
                return self.fail(SchedulerReplayError::CommitMismatch);
            }
            if !reactor.trip_internal_safety() {
                return self.fail(SchedulerReplayError::CommitMismatch);
            }
        }
        let outcome = match dispatch_reactor_replay_safety_kill(reactor, egress) {
            Ok(outcome) => outcome,
            Err(error) => return self.fail(SchedulerReplayError::Reactor(error)),
        };
        let actual_commit =
            match SchedulerCommit::from_safety_outcome(self.next_commit_ordinal, outcome, egress) {
                Ok(commit) => commit,
                Err(error) => return self.fail(SchedulerReplayError::Commit(error)),
            };
        if actual_commit != expected_commit {
            return self.fail(SchedulerReplayError::CommitMismatch);
        }
        self.next_commit_ordinal = next;
        Ok(outcome)
    }

    #[allow(
        clippy::result_large_err,
        reason = "certification retains the exact fixed reactor failure"
    )]
    fn fail<T>(&mut self, error: SchedulerReplayError) -> Result<T, SchedulerReplayError> {
        self.failed = true;
        Err(error)
    }
}

impl SchedulerCommit {
    /// Build a commit from one successful audited single-step reactor call.
    ///
    /// # Errors
    ///
    /// Returns an error if the source, report, route, ordinals, egress, or scheduler
    /// state cannot be represented canonically.
    pub fn from_replay_outcome(
        commit_ordinal: u64,
        source_event: NormalizedEvent,
        outcome: ReactorReplayOutcome,
        egress: &[Option<ReactorEgress>; MAX_REACTOR_COMMANDS_PER_INPUT],
    ) -> Result<Self, SchedulerCommitError> {
        let (source_route, input_kind) = source_route(source_event)?;
        let route = route_from_engine(outcome.route);
        if route != source_route
            && !(route == SchedulerRoute::RetainedNormal && source_route == SchedulerRoute::Normal)
        {
            return Err(SchedulerCommitError::InvalidRecord);
        }
        let source_event_crc32c = source_checksum(source_event)?;
        let (commands, egress_input_ordinal) = audit_egress(egress)?;
        let command_count = populated_commands(&commands)?;
        if command_count != outcome.commands {
            return Err(SchedulerCommitError::InvalidRecord);
        }

        let commit = match outcome.report {
            Some(report) => {
                validate_report(route, input_kind, report, command_count)?;
                Self {
                    commit_ordinal,
                    route,
                    input_kind,
                    run_ordinal: report.run_ordinal,
                    input_ordinal: report.last_input_ordinal,
                    egress_input_ordinal,
                    capture_ordinal: source_event.capture_ordinal,
                    source_event_crc32c,
                    commands,
                    outstanding_transmissions: u8_from_usize(report.outstanding_transmissions)?,
                    event_retained: report.event_retained,
                    mandatory_kill_pending: report.mandatory_kill_pending,
                    stop: Some(report.stop),
                }
            }
            None => Self {
                commit_ordinal,
                route,
                input_kind,
                run_ordinal: None,
                input_ordinal: None,
                egress_input_ordinal,
                capture_ordinal: source_event.capture_ordinal,
                source_event_crc32c,
                commands,
                outstanding_transmissions: 0,
                event_retained: false,
                mandatory_kill_pending: false,
                stop: None,
            },
        };
        commit.validate()?;
        Ok(commit)
    }

    /// Build a source-less commit from one successful mandatory safety-kill run.
    ///
    /// # Errors
    ///
    /// Returns an error if the report, route, ordinals, egress, or scheduler state
    /// cannot be represented canonically.
    pub fn from_safety_outcome(
        commit_ordinal: u64,
        outcome: ReactorReplayOutcome,
        egress: &[Option<ReactorEgress>; MAX_REACTOR_COMMANDS_PER_INPUT],
    ) -> Result<Self, SchedulerCommitError> {
        if route_from_engine(outcome.route) != SchedulerRoute::SafetyKill {
            return Err(SchedulerCommitError::InvalidRecord);
        }
        let (commands, egress_input_ordinal) = audit_egress(egress)?;
        let command_count = populated_commands(&commands)?;
        if command_count != outcome.commands {
            return Err(SchedulerCommitError::InvalidRecord);
        }
        let Some(report) = outcome.report else {
            return Err(SchedulerCommitError::InvalidRecord);
        };
        validate_report(
            SchedulerRoute::SafetyKill,
            Some(ReactorInputKind::SafetyKill),
            report,
            command_count,
        )?;
        let commit = Self {
            commit_ordinal,
            route: SchedulerRoute::SafetyKill,
            input_kind: Some(ReactorInputKind::SafetyKill),
            run_ordinal: report.run_ordinal,
            input_ordinal: report.last_input_ordinal,
            egress_input_ordinal,
            capture_ordinal: CaptureOrdinal(0),
            source_event_crc32c: 0,
            commands,
            outstanding_transmissions: u8_from_usize(report.outstanding_transmissions)?,
            event_retained: report.event_retained,
            mandatory_kill_pending: report.mandatory_kill_pending,
            stop: Some(report.stop),
        };
        commit.validate()?;
        Ok(commit)
    }

    /// Check that this commit names the exact canonical source journal record.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerCommitError::SourceMismatch`] for a different capture
    /// ordinal, route, input kind, or canonical record checksum.
    pub fn verify_source(self, source_event: NormalizedEvent) -> Result<(), SchedulerCommitError> {
        if self.capture_ordinal != source_event.capture_ordinal
            || self.source_event_crc32c != source_checksum(source_event)?
        {
            return Err(SchedulerCommitError::SourceMismatch);
        }
        let (route, input_kind) = source_route(source_event)?;
        let route_matches = self.route == route
            || (self.route == SchedulerRoute::RetainedNormal && route == SchedulerRoute::Normal);
        if !route_matches || self.input_kind != input_kind {
            return Err(SchedulerCommitError::SourceMismatch);
        }
        Ok(())
    }

    fn validate(self) -> Result<(), SchedulerCommitError> {
        if self.commit_ordinal == 0 {
            return Err(SchedulerCommitError::InvalidRecord);
        }
        match self.route {
            SchedulerRoute::SafetyKill
                if self.capture_ordinal.0 != 0 || self.source_event_crc32c != 0 =>
            {
                return Err(SchedulerCommitError::InvalidRecord);
            }
            SchedulerRoute::SafetyKill => {}
            _ if self.capture_ordinal.0 == 0 => {
                return Err(SchedulerCommitError::InvalidRecord);
            }
            _ => {}
        }
        let command_count = populated_commands(&self.commands)?;
        for command in self.commands.into_iter().flatten() {
            let mut encoded = [0_u8; ORDER_COMMAND_WIRE_LEN];
            encode_order_command(command, &mut encoded)
                .map_err(|_| SchedulerCommitError::InvalidCommand)?;
        }
        if self.outstanding_transmissions > 2 {
            return Err(SchedulerCommitError::InvalidRecord);
        }
        match self.route {
            SchedulerRoute::NoEngineInput => validate_no_engine_commit(self, command_count)?,
            SchedulerRoute::Normal | SchedulerRoute::PriorityTransmission => {
                validate_processed_commit(self, command_count)?;
            }
            SchedulerRoute::RetainedNormal => validate_retained_commit(self, command_count)?,
            SchedulerRoute::SafetyKill => validate_safety_commit(self, command_count)?,
        }
        Ok(())
    }
}

fn validate_no_engine_commit(
    commit: SchedulerCommit,
    command_count: usize,
) -> Result<(), SchedulerCommitError> {
    if commit.input_kind.is_some()
        || commit.run_ordinal.is_some()
        || commit.input_ordinal.is_some()
        || commit.egress_input_ordinal.is_some()
        || command_count != 0
        || commit.outstanding_transmissions != 0
        || commit.event_retained
        || commit.mandatory_kill_pending
        || commit.stop.is_some()
    {
        return Err(SchedulerCommitError::InvalidRecord);
    }
    Ok(())
}

fn validate_processed_commit(
    commit: SchedulerCommit,
    command_count: usize,
) -> Result<(), SchedulerCommitError> {
    let Some(run_ordinal) = commit.run_ordinal else {
        return Err(SchedulerCommitError::InvalidRecord);
    };
    let Some(input_ordinal) = commit.input_ordinal else {
        return Err(SchedulerCommitError::InvalidRecord);
    };
    if run_ordinal.0 == 0 || input_ordinal.0 == 0 || commit.stop.is_none() {
        return Err(SchedulerCommitError::InvalidRecord);
    }
    if commit.route == SchedulerRoute::PriorityTransmission
        && commit.input_kind != Some(ReactorInputKind::Transmission)
    {
        return Err(SchedulerCommitError::InvalidRecord);
    }
    if commit.route == SchedulerRoute::Normal
        && matches!(
            commit.input_kind,
            None | Some(ReactorInputKind::Transmission | ReactorInputKind::SafetyKill)
        )
    {
        return Err(SchedulerCommitError::InvalidRecord);
    }
    match (command_count, commit.egress_input_ordinal) {
        (0, None) => {}
        (1 | 2, Some(egress_ordinal)) if egress_ordinal == input_ordinal => {}
        _ => return Err(SchedulerCommitError::InvalidRecord),
    }
    validate_stop(
        commit.stop.expect("checked stop"),
        command_count,
        commit.outstanding_transmissions,
    )
}

fn validate_retained_commit(
    commit: SchedulerCommit,
    command_count: usize,
) -> Result<(), SchedulerCommitError> {
    let Some(run_ordinal) = commit.run_ordinal else {
        return Err(SchedulerCommitError::InvalidRecord);
    };
    if run_ordinal.0 == 0
        || commit.input_ordinal.is_some()
        || commit.egress_input_ordinal.is_some()
        || command_count != 0
        || commit.outstanding_transmissions != 0
        || !commit.event_retained
        || !commit.mandatory_kill_pending
        || !matches!(
            commit.stop,
            Some(ReactorStop::MandatoryKillRequired {
                required_egress: MAX_REACTOR_COMMANDS_PER_INPUT,
                available_egress: 1,
            })
        )
        || matches!(
            commit.input_kind,
            None | Some(ReactorInputKind::Transmission | ReactorInputKind::SafetyKill)
        )
    {
        return Err(SchedulerCommitError::InvalidRecord);
    }
    Ok(())
}

fn validate_safety_commit(
    commit: SchedulerCommit,
    command_count: usize,
) -> Result<(), SchedulerCommitError> {
    let Some(run_ordinal) = commit.run_ordinal else {
        return Err(SchedulerCommitError::InvalidRecord);
    };
    if run_ordinal.0 == 0
        || commit.input_kind != Some(ReactorInputKind::SafetyKill)
        || commit.input_ordinal.is_some()
        || commit.mandatory_kill_pending
    {
        return Err(SchedulerCommitError::InvalidRecord);
    }
    match (
        command_count,
        commit.egress_input_ordinal,
        commit.stop,
        commit.outstanding_transmissions,
    ) {
        (0, None, Some(ReactorStop::MandatoryKillApplied), 0) => Ok(()),
        (
            count @ (1 | 2),
            Some(InputOrdinal(0)),
            Some(ReactorStop::TransmissionBoundary {
                published,
                outstanding,
            }),
            recorded_outstanding,
        ) if published == count
            && outstanding == count
            && usize::from(recorded_outstanding) == count =>
        {
            Ok(())
        }
        _ => Err(SchedulerCommitError::InvalidRecord),
    }
}

/// Encode one canonical scheduler commit without allocation.
///
/// # Errors
///
/// Returns a capacity or canonical-validation error.
pub fn encode_scheduler_commit(
    commit: SchedulerCommit,
    output: &mut [u8],
) -> Result<usize, SchedulerCommitError> {
    commit.validate()?;
    if output.len() < SCHEDULER_COMMIT_RECORD_LEN {
        return Err(SchedulerCommitError::BufferTooSmall {
            required: SCHEDULER_COMMIT_RECORD_LEN,
            available: output.len(),
        });
    }
    let record = &mut output[..SCHEDULER_COMMIT_RECORD_LEN];
    record.fill(0);
    record[0..4].copy_from_slice(&SCHEDULER_COMMIT_MAGIC);
    write_u16(record, 4, SCHEDULER_COMMIT_VERSION);
    write_u16(record, 6, SCHEDULER_COMMIT_HEADER_LEN_WIRE);
    write_u32(record, 8, SCHEDULER_COMMIT_RECORD_LEN_WIRE);
    record[12] = commit.route as u8;
    record[13] = commit.input_kind.map_or(0, input_kind_code);
    let (stop_code, stop_arg0, stop_arg1) = encode_stop(commit.stop)?;
    record[14] = stop_code;
    let command_count = populated_commands(&commit.commands)?;
    record[15] = u8_from_usize(command_count)?;
    record[16] = u8::from(commit.event_retained)
        | (u8::from(commit.mandatory_kill_pending) << 1)
        | (u8::from(commit.egress_input_ordinal.is_some()) << 2);
    record[17] = commit.outstanding_transmissions;
    record[18] = stop_arg0;
    record[19] = stop_arg1;
    write_u32(record, 20, commit.source_event_crc32c);
    write_u64(record, 24, commit.commit_ordinal);
    write_u64(
        record,
        32,
        commit.run_ordinal.map_or(0, |ordinal| ordinal.0),
    );
    write_u64(
        record,
        40,
        commit.input_ordinal.map_or(0, |ordinal| ordinal.0),
    );
    write_u64(
        record,
        48,
        commit.egress_input_ordinal.map_or(0, |ordinal| ordinal.0),
    );
    write_u64(record, 56, commit.capture_ordinal.0);
    for (index, command) in commit.commands.into_iter().enumerate() {
        let Some(command) = command else { continue };
        let offset = command_offset(index);
        let slot: &mut [u8; ORDER_COMMAND_WIRE_LEN] = (&mut record
            [offset..offset + ORDER_COMMAND_WIRE_LEN])
            .try_into()
            .map_err(|_| SchedulerCommitError::InvalidRecord)?;
        encode_order_command(command, slot).map_err(|_| SchedulerCommitError::InvalidCommand)?;
    }
    let checksum = crc32c(&record[..CHECKSUM_OFFSET]);
    write_u32(record, CHECKSUM_OFFSET, checksum);
    Ok(SCHEDULER_COMMIT_RECORD_LEN)
}

/// Decode and validate one fixed scheduler commit.
///
/// # Errors
///
/// Returns the first framing, corruption, enum, command, or canonical-state error.
pub fn decode_scheduler_commit(
    input: &[u8],
) -> Result<(SchedulerCommit, usize), SchedulerCommitError> {
    if input.len() < 12 {
        return Err(SchedulerCommitError::BufferTooSmall {
            required: 12,
            available: input.len(),
        });
    }
    if input[0..4] != SCHEDULER_COMMIT_MAGIC {
        return Err(SchedulerCommitError::InvalidMagic);
    }
    let version = read_u16(input, 4);
    if version != SCHEDULER_COMMIT_VERSION {
        return Err(SchedulerCommitError::UnsupportedVersion(version));
    }
    let header_len = read_u16(input, 6);
    if usize::from(header_len) != SCHEDULER_COMMIT_HEADER_LEN {
        return Err(SchedulerCommitError::InvalidHeaderLength(header_len));
    }
    let record_len = read_u32(input, 8);
    if usize::try_from(record_len).ok() != Some(SCHEDULER_COMMIT_RECORD_LEN) {
        return Err(SchedulerCommitError::InvalidRecordLength(record_len));
    }
    if input.len() < SCHEDULER_COMMIT_RECORD_LEN {
        return Err(SchedulerCommitError::BufferTooSmall {
            required: SCHEDULER_COMMIT_RECORD_LEN,
            available: input.len(),
        });
    }
    let record = &input[..SCHEDULER_COMMIT_RECORD_LEN];
    let recorded = read_u32(record, CHECKSUM_OFFSET);
    let calculated = crc32c(&record[..CHECKSUM_OFFSET]);
    if recorded != calculated {
        return Err(SchedulerCommitError::ChecksumMismatch {
            recorded,
            calculated,
        });
    }
    if record[64..68].iter().any(|byte| *byte != 0) || record[16] & !0b111 != 0 {
        return Err(SchedulerCommitError::InvalidFlags(record[16]));
    }
    let route = decode_route(record[12])?;
    let input_kind = decode_input_kind(record[13])?;
    let command_count = usize::from(record[15]);
    if command_count > MAX_REACTOR_COMMANDS_PER_INPUT {
        return Err(SchedulerCommitError::InvalidRecord);
    }
    let mut commands = [None; MAX_REACTOR_COMMANDS_PER_INPUT];
    for (index, command) in commands.iter_mut().enumerate() {
        let offset = command_offset(index);
        let slot: &[u8; ORDER_COMMAND_WIRE_LEN] = record[offset..offset + ORDER_COMMAND_WIRE_LEN]
            .try_into()
            .map_err(|_| SchedulerCommitError::InvalidRecord)?;
        if index < command_count {
            *command =
                Some(decode_order_command(slot).map_err(|_| SchedulerCommitError::InvalidCommand)?);
        } else if slot.iter().any(|byte| *byte != 0) {
            return Err(SchedulerCommitError::InvalidCommand);
        }
    }
    let stop = decode_stop(record[14], record[18], record[19])?;
    let egress_ordinal_raw = read_u64(record, 48);
    let egress_input_ordinal = if record[16] & 4 != 0 {
        Some(InputOrdinal(egress_ordinal_raw))
    } else {
        if egress_ordinal_raw != 0 {
            return Err(SchedulerCommitError::InvalidRecord);
        }
        None
    };
    let commit = SchedulerCommit {
        commit_ordinal: read_u64(record, 24),
        route,
        input_kind,
        run_ordinal: nonzero_run(read_u64(record, 32)),
        input_ordinal: nonzero_input(read_u64(record, 40)),
        egress_input_ordinal,
        capture_ordinal: CaptureOrdinal(read_u64(record, 56)),
        source_event_crc32c: read_u32(record, 20),
        commands,
        outstanding_transmissions: record[17],
        event_retained: record[16] & 1 != 0,
        mandatory_kill_pending: record[16] & 2 != 0,
        stop,
    };
    commit.validate()?;
    Ok((commit, SCHEDULER_COMMIT_RECORD_LEN))
}

fn source_route(
    event: NormalizedEvent,
) -> Result<(SchedulerRoute, Option<ReactorInputKind>), SchedulerCommitError> {
    match decode_replay_input(event).map_err(SchedulerCommitError::SourceEvent)? {
        ReplayInput::Reactor(input) => Ok((SchedulerRoute::Normal, Some(input.kind()))),
        ReplayInput::Transmission(_) => Ok((
            SchedulerRoute::PriorityTransmission,
            Some(ReactorInputKind::Transmission),
        )),
        ReplayInput::NoEngineInput => Ok((SchedulerRoute::NoEngineInput, None)),
    }
}

fn source_checksum(event: NormalizedEvent) -> Result<u32, SchedulerCommitError> {
    let mut encoded = [0_u8; RECORD_LEN];
    encode_record(event, &mut encoded).map_err(|_| SchedulerCommitError::InvalidRecord)?;
    Ok(read_u32(&encoded, RECORD_LEN - 4))
}

const fn route_from_engine(route: EngineReplayRoute) -> SchedulerRoute {
    match route {
        EngineReplayRoute::Normal => SchedulerRoute::Normal,
        EngineReplayRoute::PriorityTransmission => SchedulerRoute::PriorityTransmission,
        EngineReplayRoute::NoEngineInput => SchedulerRoute::NoEngineInput,
        EngineReplayRoute::RetainedNormal => SchedulerRoute::RetainedNormal,
        EngineReplayRoute::SafetyKill => SchedulerRoute::SafetyKill,
    }
}

fn audit_egress(
    egress: &[Option<ReactorEgress>; MAX_REACTOR_COMMANDS_PER_INPUT],
) -> Result<
    (
        [Option<OrderCommand>; MAX_REACTOR_COMMANDS_PER_INPUT],
        Option<InputOrdinal>,
    ),
    SchedulerCommitError,
> {
    let mut commands = [None; MAX_REACTOR_COMMANDS_PER_INPUT];
    let mut egress_ordinal = None;
    let mut seen_empty = false;
    for (index, item) in egress.iter().copied().enumerate() {
        match item {
            Some(item) if !seen_empty => {
                let expected_index = u8::try_from(index).expect("two command slots");
                if item.command_index != expected_index
                    || egress_ordinal.is_some_and(|ordinal| ordinal != item.input_ordinal)
                {
                    return Err(SchedulerCommitError::InvalidRecord);
                }
                egress_ordinal = Some(item.input_ordinal);
                commands[index] = Some(item.command);
            }
            Some(_) => return Err(SchedulerCommitError::InvalidRecord),
            None => seen_empty = true,
        }
    }
    Ok((commands, egress_ordinal))
}

fn validate_report(
    route: SchedulerRoute,
    input_kind: Option<ReactorInputKind>,
    report: ReactorRunReport,
    command_count: usize,
) -> Result<(), SchedulerCommitError> {
    let Some(run_ordinal) = report.run_ordinal else {
        return Err(SchedulerCommitError::InvalidRecord);
    };
    if run_ordinal.0 == 0 || report.commands_published != command_count {
        return Err(SchedulerCommitError::InvalidRecord);
    }
    match route {
        SchedulerRoute::Normal
            if report.last_input_ordinal.is_some()
                && report.events_processed == 1
                && report.transmissions_processed == 0 => {}
        SchedulerRoute::PriorityTransmission
            if input_kind == Some(ReactorInputKind::Transmission)
                && report.last_input_ordinal.is_some()
                && report.events_processed == 0
                && report.transmissions_processed == 1 => {}
        SchedulerRoute::RetainedNormal
            if !matches!(
                input_kind,
                None | Some(ReactorInputKind::Transmission | ReactorInputKind::SafetyKill)
            ) && report.last_input_ordinal.is_none()
                && report.events_processed == 0
                && report.transmissions_processed == 0
                && report.commands_published == 0
                && report.outstanding_transmissions == 0
                && report.event_retained
                && report.mandatory_kill_pending
                && matches!(
                    report.stop,
                    ReactorStop::MandatoryKillRequired {
                        required_egress: MAX_REACTOR_COMMANDS_PER_INPUT,
                        available_egress: 1,
                    }
                ) => {}
        SchedulerRoute::SafetyKill
            if input_kind == Some(ReactorInputKind::SafetyKill)
                && report.last_input_ordinal.is_none()
                && report.events_processed == 0
                && report.transmissions_processed == 0
                && !report.mandatory_kill_pending
                && safety_report_stop_is_valid(report, command_count) => {}
        _ => return Err(SchedulerCommitError::InvalidRecord),
    }
    Ok(())
}

fn safety_report_stop_is_valid(report: ReactorRunReport, command_count: usize) -> bool {
    match (command_count, report.stop) {
        (0, ReactorStop::MandatoryKillApplied) => report.outstanding_transmissions == 0,
        (
            count @ (1 | 2),
            ReactorStop::TransmissionBoundary {
                published,
                outstanding,
            },
        ) => {
            published == count && outstanding == count && report.outstanding_transmissions == count
        }
        _ => false,
    }
}

fn populated_commands(
    commands: &[Option<OrderCommand>; MAX_REACTOR_COMMANDS_PER_INPUT],
) -> Result<usize, SchedulerCommitError> {
    let populated = commands.iter().filter(|slot| slot.is_some()).count();
    if commands.iter().take(populated).all(Option::is_some)
        && commands.iter().skip(populated).all(Option::is_none)
    {
        Ok(populated)
    } else {
        Err(SchedulerCommitError::InvalidRecord)
    }
}

fn validate_stop(
    stop: ReactorStop,
    command_count: usize,
    outstanding: u8,
) -> Result<(), SchedulerCommitError> {
    match stop {
        ReactorStop::TransmissionBoundary {
            published,
            outstanding: stop_outstanding,
        } if published == command_count && stop_outstanding == usize::from(outstanding) => Ok(()),
        ReactorStop::InputDrained
        | ReactorStop::EventBudgetExhausted
        | ReactorStop::TransmissionBudgetExhausted
        | ReactorStop::MandatoryKillApplied
        | ReactorStop::MandatoryKillRequired { .. }
        | ReactorStop::EmergencyEgressRequired { .. }
            if command_count == 0 =>
        {
            Ok(())
        }
        ReactorStop::AwaitingTransmission {
            outstanding: stop_outstanding,
        } if command_count == 0 && stop_outstanding == usize::from(outstanding) => Ok(()),
        _ => Err(SchedulerCommitError::InvalidRecord),
    }
}

fn encode_stop(stop: Option<ReactorStop>) -> Result<(u8, u8, u8), SchedulerCommitError> {
    match stop {
        None => Ok((0, 0, 0)),
        Some(ReactorStop::InputDrained) => Ok((1, 0, 0)),
        Some(ReactorStop::EventBudgetExhausted) => Ok((2, 0, 0)),
        Some(ReactorStop::TransmissionBudgetExhausted) => Ok((3, 0, 0)),
        Some(ReactorStop::AwaitingTransmission { outstanding }) => {
            Ok((4, u8_from_usize(outstanding)?, 0))
        }
        Some(ReactorStop::TransmissionBoundary {
            published,
            outstanding,
        }) => Ok((5, u8_from_usize(published)?, u8_from_usize(outstanding)?)),
        Some(ReactorStop::MandatoryKillRequired {
            required_egress,
            available_egress,
        }) => Ok((
            6,
            u8_from_usize(required_egress)?,
            u8_from_usize(available_egress)?,
        )),
        Some(ReactorStop::MandatoryKillApplied) => Ok((7, 0, 0)),
        Some(ReactorStop::EmergencyEgressRequired {
            required_egress,
            available_egress,
        }) => Ok((
            8,
            u8_from_usize(required_egress)?,
            u8_from_usize(available_egress)?,
        )),
        Some(ReactorStop::Failed) => Err(SchedulerCommitError::InvalidRecord),
    }
}

fn decode_stop(code: u8, arg0: u8, arg1: u8) -> Result<Option<ReactorStop>, SchedulerCommitError> {
    let stop = match code {
        0 if arg0 == 0 && arg1 == 0 => return Ok(None),
        1 if arg0 == 0 && arg1 == 0 => ReactorStop::InputDrained,
        2 if arg0 == 0 && arg1 == 0 => ReactorStop::EventBudgetExhausted,
        3 if arg0 == 0 && arg1 == 0 => ReactorStop::TransmissionBudgetExhausted,
        4 if arg0 != 0 && arg1 == 0 => ReactorStop::AwaitingTransmission {
            outstanding: usize::from(arg0),
        },
        5 if arg0 != 0 => ReactorStop::TransmissionBoundary {
            published: usize::from(arg0),
            outstanding: usize::from(arg1),
        },
        6 if arg0 != 0 => ReactorStop::MandatoryKillRequired {
            required_egress: usize::from(arg0),
            available_egress: usize::from(arg1),
        },
        7 if arg0 == 0 && arg1 == 0 => ReactorStop::MandatoryKillApplied,
        8 if arg0 != 0 => ReactorStop::EmergencyEgressRequired {
            required_egress: usize::from(arg0),
            available_egress: usize::from(arg1),
        },
        _ => return Err(SchedulerCommitError::InvalidStop(code)),
    };
    Ok(Some(stop))
}

const fn input_kind_code(kind: ReactorInputKind) -> u8 {
    match kind {
        ReactorInputKind::Clock => 1,
        ReactorInputKind::Snapshot => 2,
        ReactorInputKind::MarketData => 3,
        ReactorInputKind::OrderEntry => 4,
        ReactorInputKind::OwnedMboBinding => 5,
        ReactorInputKind::Control => 6,
        ReactorInputKind::Transmission => 7,
        ReactorInputKind::Timer => 8,
        ReactorInputKind::SafetyKill => 9,
        ReactorInputKind::DropCopy => 10,
    }
}

fn decode_input_kind(code: u8) -> Result<Option<ReactorInputKind>, SchedulerCommitError> {
    Ok(match code {
        0 => None,
        1 => Some(ReactorInputKind::Clock),
        2 => Some(ReactorInputKind::Snapshot),
        3 => Some(ReactorInputKind::MarketData),
        4 => Some(ReactorInputKind::OrderEntry),
        5 => Some(ReactorInputKind::OwnedMboBinding),
        6 => Some(ReactorInputKind::Control),
        7 => Some(ReactorInputKind::Transmission),
        8 => Some(ReactorInputKind::Timer),
        9 => Some(ReactorInputKind::SafetyKill),
        10 => Some(ReactorInputKind::DropCopy),
        _ => return Err(SchedulerCommitError::InvalidInputKind(code)),
    })
}

const fn decode_route(code: u8) -> Result<SchedulerRoute, SchedulerCommitError> {
    match code {
        0 => Ok(SchedulerRoute::NoEngineInput),
        1 => Ok(SchedulerRoute::Normal),
        2 => Ok(SchedulerRoute::PriorityTransmission),
        3 => Ok(SchedulerRoute::RetainedNormal),
        4 => Ok(SchedulerRoute::SafetyKill),
        _ => Err(SchedulerCommitError::InvalidRoute(code)),
    }
}

const fn nonzero_run(value: u64) -> Option<RunOrdinal> {
    if value == 0 {
        None
    } else {
        Some(RunOrdinal(value))
    }
}

const fn nonzero_input(value: u64) -> Option<InputOrdinal> {
    if value == 0 {
        None
    } else {
        Some(InputOrdinal(value))
    }
}

fn u8_from_usize(value: usize) -> Result<u8, SchedulerCommitError> {
    u8::try_from(value).map_err(|_| {
        SchedulerCommitError::IntegerOutOfRange(u64::try_from(value).unwrap_or(u64::MAX))
    })
}

const fn command_offset(index: usize) -> usize {
    if index == 0 {
        FIRST_COMMAND_OFFSET
    } else {
        SECOND_COMMAND_OFFSET
    }
}

fn write_u16(output: &mut [u8], offset: usize, value: u16) {
    output[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(output: &mut [u8], offset: usize, value: u32) {
    output[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(output: &mut [u8], offset: usize, value: u64) {
    output[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn read_u16(input: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(input[offset..offset + 2].try_into().expect("fixed field"))
}

fn read_u32(input: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(input[offset..offset + 4].try_into().expect("fixed field"))
}

fn read_u64(input: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(input[offset..offset + 8].try_into().expect("fixed field"))
}
