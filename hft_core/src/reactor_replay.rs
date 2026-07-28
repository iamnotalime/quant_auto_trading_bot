//! Allocation-free replay through the actual single-writer hot-path reactor.
//!
//! Unlike direct engine replay, this adapter retains the reactor's outstanding-command
//! FIFO, priority-feedback contract, input ordinals, counters, and fixed egress
//! preflight. Records supplied here must be in reactor application order. An ingress
//! capture that was reordered by the live priority scheduler additionally needs a
//! scheduler commit trace before it can be certified as application ordered.

use crate::engine_replay::EngineReplayRoute;
use crate::event_codec::{EventCodecError, ReplayInput, decode_replay_input};
use crate::events::NormalizedEvent;
use crate::reactor::{
    HotPathReactor, MAX_REACTOR_COMMANDS_PER_INPUT, ReactorBudget, ReactorEgress, ReactorFailure,
    ReactorInput, ReactorRunReport, TransmissionInput,
};
use crate::spsc::SpscRing;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReactorReplayError {
    Codec(EventCodecError),
    /// A normal input cannot be consumed while live transport results are unresolved.
    OutstandingTransmission {
        outstanding: usize,
    },
    /// Synthetic safety work must be committed before another captured normal input.
    MandatoryKillPending,
    NoMandatoryKillPending,
    RetainedInputMismatch,
    RetentionNotRequired {
        maximum_commands: usize,
    },
    RetentionRequiresNormalInput,
    RingInvariant,
    Reactor(ReactorFailure),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReactorReplayOutcome {
    pub route: EngineReplayRoute,
    pub commands: usize,
    pub report: Option<ReactorRunReport>,
}

/// Apply one normalized, application-ordered record through [`HotPathReactor`].
///
/// A fixed two-slot egress array is mandatory, matching the reactor's worst-case
/// per-input output contract. The caller must clear or consume prior egress before the
/// next call; dirty slots are rejected by the reactor itself.
///
/// # Errors
///
/// Returns a codec error, an outstanding-transport barrier, an impossible local-ring
/// failure, or the exact reactor failure with partial-progress report.
#[allow(
    clippy::result_large_err,
    reason = "replay certification retains the reactor's fixed detailed failure"
)]
pub fn dispatch_reactor_replay_event<
    const MAX_BOOK_ORDERS: usize,
    const MAX_BOOK_LEVELS: usize,
    const MAX_ORDERS: usize,
    const MAX_RECENT_TRADES: usize,
    const MAX_FILLS: usize,
>(
    reactor: &mut HotPathReactor<
        MAX_BOOK_ORDERS,
        MAX_BOOK_LEVELS,
        MAX_ORDERS,
        MAX_RECENT_TRADES,
        MAX_FILLS,
    >,
    event: NormalizedEvent,
    egress: &mut [Option<ReactorEgress>; MAX_REACTOR_COMMANDS_PER_INPUT],
) -> Result<ReactorReplayOutcome, ReactorReplayError> {
    match decode_replay_input(event).map_err(ReactorReplayError::Codec)? {
        ReplayInput::Reactor(input) => dispatch_normal(reactor, input, egress),
        ReplayInput::Transmission(input) => dispatch_transmission(reactor, input, egress),
        ReplayInput::NoEngineInput => Ok(ReactorReplayOutcome {
            route: EngineReplayRoute::NoEngineInput,
            commands: 0,
            report: None,
        }),
    }
}

/// Reproduce a live undersized-egress preflight that retains one normal event and
/// requests a mandatory safety kill before any engine mutation.
///
/// # Errors
///
/// Returns an error for a non-normal or zero-output input, an unresolved prior state,
/// a codec/ring fault, or any unexpected reactor result.
#[allow(
    clippy::result_large_err,
    reason = "replay certification retains the reactor's fixed detailed failure"
)]
pub fn dispatch_reactor_replay_retention<
    const MAX_BOOK_ORDERS: usize,
    const MAX_BOOK_LEVELS: usize,
    const MAX_ORDERS: usize,
    const MAX_RECENT_TRADES: usize,
    const MAX_FILLS: usize,
>(
    reactor: &mut HotPathReactor<
        MAX_BOOK_ORDERS,
        MAX_BOOK_LEVELS,
        MAX_ORDERS,
        MAX_RECENT_TRADES,
        MAX_FILLS,
    >,
    event: NormalizedEvent,
) -> Result<ReactorReplayOutcome, ReactorReplayError> {
    let ReplayInput::Reactor(input) =
        decode_replay_input(event).map_err(ReactorReplayError::Codec)?
    else {
        return Err(ReactorReplayError::RetentionRequiresNormalInput);
    };
    let maximum_commands = input.maximum_commands();
    if maximum_commands < MAX_REACTOR_COMMANDS_PER_INPUT {
        return Err(ReactorReplayError::RetentionNotRequired { maximum_commands });
    }
    let outstanding = reactor.outstanding_transmissions();
    if outstanding != 0 {
        return Err(ReactorReplayError::OutstandingTransmission { outstanding });
    }
    if reactor.mandatory_kill_pending() {
        return Err(ReactorReplayError::MandatoryKillPending);
    }
    if reactor.has_retained_event() {
        return Err(ReactorReplayError::RetainedInputMismatch);
    }

    let mut event_ring = SpscRing::<ReactorInput, 2>::new();
    let mut transmission_ring = SpscRing::<TransmissionInput, 2>::new();
    let (mut event_producer, mut event_consumer) = event_ring.split();
    let (_transmission_producer, mut transmission_consumer) = transmission_ring.split();
    event_producer
        .try_push(input)
        .map_err(|_| ReactorReplayError::RingInvariant)?;
    let mut undersized_egress = [None; MAX_REACTOR_COMMANDS_PER_INPUT - 1];
    let report = reactor
        .run_replay(
            &mut event_consumer,
            &mut transmission_consumer,
            single_step_budget(),
            &mut undersized_egress,
        )
        .map_err(ReactorReplayError::Reactor)?;
    if report.commands_published != 0
        || report.events_processed != 0
        || !report.event_retained
        || !report.mandatory_kill_pending
        || !matches!(
            report.stop,
            crate::reactor::ReactorStop::MandatoryKillRequired { .. }
        )
    {
        return Err(ReactorReplayError::RingInvariant);
    }
    Ok(ReactorReplayOutcome {
        route: EngineReplayRoute::RetainedNormal,
        commands: 0,
        report: Some(report),
    })
}

/// Execute a source-less mandatory safety-kill run through the real reactor.
///
/// # Errors
///
/// Returns an error unless mandatory safety work is pending and all prior transport
/// feedback is resolved, or when the reactor rejects the run.
#[allow(
    clippy::result_large_err,
    reason = "replay certification retains the reactor's fixed detailed failure"
)]
pub fn dispatch_reactor_replay_safety_kill<
    const MAX_BOOK_ORDERS: usize,
    const MAX_BOOK_LEVELS: usize,
    const MAX_ORDERS: usize,
    const MAX_RECENT_TRADES: usize,
    const MAX_FILLS: usize,
>(
    reactor: &mut HotPathReactor<
        MAX_BOOK_ORDERS,
        MAX_BOOK_LEVELS,
        MAX_ORDERS,
        MAX_RECENT_TRADES,
        MAX_FILLS,
    >,
    egress: &mut [Option<ReactorEgress>; MAX_REACTOR_COMMANDS_PER_INPUT],
) -> Result<ReactorReplayOutcome, ReactorReplayError> {
    let outstanding = reactor.outstanding_transmissions();
    if outstanding != 0 {
        return Err(ReactorReplayError::OutstandingTransmission { outstanding });
    }
    if !reactor.mandatory_kill_pending() {
        return Err(ReactorReplayError::NoMandatoryKillPending);
    }
    let mut event_ring = SpscRing::<ReactorInput, 2>::new();
    let mut transmission_ring = SpscRing::<TransmissionInput, 2>::new();
    let (_event_producer, mut event_consumer) = event_ring.split();
    let (_transmission_producer, mut transmission_consumer) = transmission_ring.split();
    let report = reactor
        .run_replay(
            &mut event_consumer,
            &mut transmission_consumer,
            single_step_budget(),
            egress,
        )
        .map_err(ReactorReplayError::Reactor)?;
    if report.events_processed != 0
        || report.transmissions_processed != 0
        || report.mandatory_kill_pending
        || !matches!(
            report.stop,
            crate::reactor::ReactorStop::MandatoryKillApplied
                | crate::reactor::ReactorStop::TransmissionBoundary { .. }
        )
    {
        return Err(ReactorReplayError::RingInvariant);
    }
    Ok(ReactorReplayOutcome {
        route: EngineReplayRoute::SafetyKill,
        commands: report.commands_published,
        report: Some(report),
    })
}

#[allow(
    clippy::result_large_err,
    reason = "replay certification retains the reactor's fixed detailed failure"
)]
fn dispatch_normal<
    const MAX_BOOK_ORDERS: usize,
    const MAX_BOOK_LEVELS: usize,
    const MAX_ORDERS: usize,
    const MAX_RECENT_TRADES: usize,
    const MAX_FILLS: usize,
>(
    reactor: &mut HotPathReactor<
        MAX_BOOK_ORDERS,
        MAX_BOOK_LEVELS,
        MAX_ORDERS,
        MAX_RECENT_TRADES,
        MAX_FILLS,
    >,
    input: ReactorInput,
    egress: &mut [Option<ReactorEgress>; MAX_REACTOR_COMMANDS_PER_INPUT],
) -> Result<ReactorReplayOutcome, ReactorReplayError> {
    let outstanding = reactor.outstanding_transmissions();
    if outstanding != 0 {
        return Err(ReactorReplayError::OutstandingTransmission { outstanding });
    }
    if reactor.mandatory_kill_pending() {
        return Err(ReactorReplayError::MandatoryKillPending);
    }

    let mut event_ring = SpscRing::<ReactorInput, 2>::new();
    let mut transmission_ring = SpscRing::<TransmissionInput, 2>::new();
    let (mut event_producer, mut event_consumer) = event_ring.split();
    let (_transmission_producer, mut transmission_consumer) = transmission_ring.split();
    match reactor.retained_event() {
        Some(retained) if retained != input => {
            return Err(ReactorReplayError::RetainedInputMismatch);
        }
        Some(_) => {}
        None => event_producer
            .try_push(input)
            .map_err(|_| ReactorReplayError::RingInvariant)?,
    }
    let report = reactor
        .run_replay(
            &mut event_consumer,
            &mut transmission_consumer,
            single_step_budget(),
            egress,
        )
        .map_err(ReactorReplayError::Reactor)?;
    Ok(ReactorReplayOutcome {
        route: EngineReplayRoute::Normal,
        commands: report.commands_published,
        report: Some(report),
    })
}

#[allow(
    clippy::result_large_err,
    reason = "replay certification retains the reactor's fixed detailed failure"
)]
fn dispatch_transmission<
    const MAX_BOOK_ORDERS: usize,
    const MAX_BOOK_LEVELS: usize,
    const MAX_ORDERS: usize,
    const MAX_RECENT_TRADES: usize,
    const MAX_FILLS: usize,
>(
    reactor: &mut HotPathReactor<
        MAX_BOOK_ORDERS,
        MAX_BOOK_LEVELS,
        MAX_ORDERS,
        MAX_RECENT_TRADES,
        MAX_FILLS,
    >,
    input: TransmissionInput,
    egress: &mut [Option<ReactorEgress>; MAX_REACTOR_COMMANDS_PER_INPUT],
) -> Result<ReactorReplayOutcome, ReactorReplayError> {
    let mut event_ring = SpscRing::<ReactorInput, 2>::new();
    let mut transmission_ring = SpscRing::<TransmissionInput, 2>::new();
    let (_event_producer, mut event_consumer) = event_ring.split();
    let (mut transmission_producer, mut transmission_consumer) = transmission_ring.split();
    transmission_producer
        .try_push(input)
        .map_err(|_| ReactorReplayError::RingInvariant)?;
    let report = reactor
        .run_replay(
            &mut event_consumer,
            &mut transmission_consumer,
            transmission_step_budget(),
            egress,
        )
        .map_err(ReactorReplayError::Reactor)?;
    Ok(ReactorReplayOutcome {
        route: EngineReplayRoute::PriorityTransmission,
        commands: report.commands_published,
        report: Some(report),
    })
}

const fn single_step_budget() -> ReactorBudget {
    ReactorBudget {
        max_events: 1,
        max_transmissions: 1,
    }
}

/// Keep a priority-lane feedback record and any internally retained normal event in
/// distinct audited runs. This gives each mutation exactly one source binding instead
/// of allowing the final transport acknowledgement to release a retained event in the
/// same report.
const fn transmission_step_budget() -> ReactorBudget {
    ReactorBudget {
        max_events: 0,
        max_transmissions: 1,
    }
}
