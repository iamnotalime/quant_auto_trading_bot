//! Bounded single-writer reactor for the execution hot path.
//!
//! Native feed handlers, order-entry transports, and the authenticated control gate
//! remain outside this module. They publish fixed-size, already decoded inputs to two
//! SPSC lanes: a normal event lane and a priority transmission-feedback lane. The
//! priority lane prevents market-data backlog from blocking resolution of commands
//! that the engine has prepared but has not yet proven sent or unsent.
//!
//! The reactor performs no I/O and owns no growable storage. It stops immediately
//! after publishing commands into caller-owned egress slots. If those slots cannot
//! hold an event's fixed worst-case output, it retains that event before engine
//! mutation and enters a mandatory-kill state. A later call with sufficient clean
//! egress applies the kill and prepares bounded emergency cancels before normal event
//! processing can resume.

use crate::clock::ClockSample;
use crate::control::ControlDecision;
use crate::engine::{EngineError, ExecutionEngine, TransmissionStatus};
use crate::kill::KillCode;
use crate::spsc::Consumer;
use crate::types::MonotonicTimestampNs;
use crate::venue::{
    InboundMessage, MarketDataMessage, OrderCommand, OwnedMboBinding, SnapshotMessage,
};

pub const MAX_REACTOR_COMMANDS_PER_INPUT: usize = 2;

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct InputOrdinal(pub u64);

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct RunOrdinal(pub u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClockInput {
    pub sample: ClockSample,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MarketDataInput {
    pub message: MarketDataMessage,
    pub monotonic_now: MonotonicTimestampNs,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SnapshotInput {
    pub message: SnapshotMessage,
    pub monotonic_now: MonotonicTimestampNs,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OrderEntryInput {
    pub message: InboundMessage,
    pub monotonic_now: MonotonicTimestampNs,
}

/// Independently sequenced execution report used only to reconcile the primary
/// order-entry channel. The engine never applies its payload to lifecycle/risk twice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DropCopyInput {
    pub message: InboundMessage,
    pub monotonic_now: MonotonicTimestampNs,
}

/// Adapter-authenticated correlation between a managed private order and its public
/// MBO identity. This is a normal-lane input so its capture order is deterministic
/// relative to order-entry acknowledgements and public feed events.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OwnedMboBindingInput {
    pub binding: OwnedMboBinding,
    pub monotonic_now: MonotonicTimestampNs,
}

/// An action already accepted by the authenticated cold-control gate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControlInput {
    decision: ControlDecision,
}

impl ControlInput {
    #[must_use]
    pub const fn new(decision: ControlDecision) -> Self {
        Self { decision }
    }

    #[must_use]
    pub const fn decision(self) -> ControlDecision {
        self.decision
    }
}

/// Exact transport result for a command previously published by this reactor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransmissionInput {
    pub command: OrderCommand,
    pub status: TransmissionStatus,
    pub monotonic_now: MonotonicTimestampNs,
}

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct TimerId(pub u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimerAction {
    /// Retry bounded cancel preparation after the engine kill latch is set.
    KillCancelSweep,
    /// Enforce the authenticated cold-control heartbeat lease in the hot engine.
    ControlLivenessCheck,
    /// Enforce the oldest unresolved order-entry/drop-copy pairing deadline.
    DropCopyLivenessCheck,
}

/// Notification from an external monotonic scheduler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimerInput {
    pub timer_id: TimerId,
    pub action: TimerAction,
    pub scheduled_at: MonotonicTimestampNs,
    pub fired_at: MonotonicTimestampNs,
}

/// Normal-priority input lane. Transmission feedback deliberately has a separate,
/// higher-priority lane and cannot be queued behind market data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReactorInput {
    Clock(ClockInput),
    Snapshot(SnapshotInput),
    MarketData(MarketDataInput),
    OrderEntry(OrderEntryInput),
    DropCopy(DropCopyInput),
    OwnedMboBinding(OwnedMboBindingInput),
    Control(ControlInput),
    Timer(TimerInput),
}

impl ReactorInput {
    #[must_use]
    pub const fn kind(self) -> ReactorInputKind {
        match self {
            Self::Clock(_) => ReactorInputKind::Clock,
            Self::Snapshot(_) => ReactorInputKind::Snapshot,
            Self::MarketData(_) => ReactorInputKind::MarketData,
            Self::OrderEntry(_) => ReactorInputKind::OrderEntry,
            Self::DropCopy(_) => ReactorInputKind::DropCopy,
            Self::OwnedMboBinding(_) => ReactorInputKind::OwnedMboBinding,
            Self::Control(_) => ReactorInputKind::Control,
            Self::Timer(_) => ReactorInputKind::Timer,
        }
    }

    pub(crate) const fn maximum_commands(self) -> usize {
        // Every input may expose a defensive engine failure after the kill latch is
        // acquired. Reserve the bounded cancel-first batch even when the success path
        // (for example a clock sample, owned-MBO bind, arm, or heartbeat) emits nothing.
        match self {
            Self::Clock(_)
            | Self::Snapshot(_)
            | Self::MarketData(_)
            | Self::OrderEntry(_)
            | Self::DropCopy(_)
            | Self::OwnedMboBinding(_)
            | Self::Control(_)
            | Self::Timer(_) => MAX_REACTOR_COMMANDS_PER_INPUT,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReactorInputKind {
    Clock,
    Snapshot,
    MarketData,
    OrderEntry,
    DropCopy,
    OwnedMboBinding,
    Control,
    Transmission,
    Timer,
    SafetyKill,
}

/// One command prepared by the engine and published into caller-owned storage.
/// `InputOrdinal(0)` is reserved for a reactor-generated mandatory safety kill.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReactorEgress {
    pub input_ordinal: InputOrdinal,
    pub command_index: u8,
    pub command: OrderCommand,
}

/// Scheduler work limits. Command capacity is intentionally not a scheduler budget;
/// it is the actual length of the caller's egress slice and is safety-critical.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReactorBudget {
    pub max_events: usize,
    pub max_transmissions: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReactorStop {
    InputDrained,
    EventBudgetExhausted,
    TransmissionBudgetExhausted,
    AwaitingTransmission {
        outstanding: usize,
    },
    TransmissionBoundary {
        published: usize,
        outstanding: usize,
    },
    MandatoryKillRequired {
        required_egress: usize,
        available_egress: usize,
    },
    MandatoryKillApplied,
    EmergencyEgressRequired {
        required_egress: usize,
        available_egress: usize,
    },
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReactorRunReport {
    pub run_ordinal: Option<RunOrdinal>,
    pub events_processed: usize,
    pub transmissions_processed: usize,
    pub commands_published: usize,
    pub last_input_ordinal: Option<InputOrdinal>,
    pub outstanding_transmissions: usize,
    pub event_retained: bool,
    pub mandatory_kill_pending: bool,
    pub stop: ReactorStop,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReactorCounters {
    pub runs: u64,
    pub events_dequeued: u64,
    pub events_processed: u64,
    pub transmissions_dequeued: u64,
    pub transmissions_processed: u64,
    pub clock_inputs: u64,
    pub snapshot_inputs: u64,
    pub market_data_inputs: u64,
    pub order_entry_inputs: u64,
    pub drop_copy_inputs: u64,
    pub owned_mbo_binding_inputs: u64,
    pub control_inputs: u64,
    pub timer_inputs: u64,
    pub commands_published: u64,
    pub transmissions_sent: u64,
    pub transmissions_proven_unsent: u64,
    pub transmission_wait_stops: u64,
    pub mandatory_kill_requests: u64,
    pub mandatory_kills_applied: u64,
    pub engine_errors: u64,
    pub input_contract_errors: u64,
    /// Diagnostic counters saturate rather than wrapping; routing never depends on them.
    pub saturated: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReactorError {
    DirtyEgressSlot {
        index: usize,
    },
    InputOrdinalExhausted,
    RunOrdinalExhausted,
    InvalidTimer(TimerInput),
    TransmissionMismatch {
        expected: OrderCommand,
        received: OrderCommand,
    },
    UnexpectedTransmission(OrderCommand),
    EngineOutputContract {
        declared: usize,
        populated: usize,
    },
    InternalInvariant,
    Engine {
        input: ReactorInputKind,
        source: EngineError,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReactorFailure {
    pub error: ReactorError,
    /// Partial progress makes every command published before a fault visible.
    pub report: ReactorRunReport,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MandatoryKill {
    _private: (),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ControlDispatchOrigin {
    LiveAuthenticated,
    JournalReplay,
}

/// Fixed-state owner of the single-writer execution engine.
#[derive(Debug)]
pub struct HotPathReactor<
    const MAX_BOOK_ORDERS: usize,
    const MAX_BOOK_LEVELS: usize,
    const MAX_ORDERS: usize,
    const MAX_RECENT_TRADES: usize,
    const MAX_FILLS: usize,
> {
    engine:
        ExecutionEngine<MAX_BOOK_ORDERS, MAX_BOOK_LEVELS, MAX_ORDERS, MAX_RECENT_TRADES, MAX_FILLS>,
    retained_event: Option<ReactorInput>,
    mandatory_kill: Option<MandatoryKill>,
    outstanding: [Option<OrderCommand>; MAX_REACTOR_COMMANDS_PER_INPUT],
    outstanding_next: usize,
    outstanding_len: usize,
    next_run_ordinal: RunOrdinal,
    next_input_ordinal: InputOrdinal,
    counters: ReactorCounters,
}

impl<
    const MAX_BOOK_ORDERS: usize,
    const MAX_BOOK_LEVELS: usize,
    const MAX_ORDERS: usize,
    const MAX_RECENT_TRADES: usize,
    const MAX_FILLS: usize,
> HotPathReactor<MAX_BOOK_ORDERS, MAX_BOOK_LEVELS, MAX_ORDERS, MAX_RECENT_TRADES, MAX_FILLS>
{
    #[must_use]
    pub const fn new(
        engine: ExecutionEngine<
            MAX_BOOK_ORDERS,
            MAX_BOOK_LEVELS,
            MAX_ORDERS,
            MAX_RECENT_TRADES,
            MAX_FILLS,
        >,
    ) -> Self {
        Self {
            engine,
            retained_event: None,
            mandatory_kill: None,
            outstanding: [None; MAX_REACTOR_COMMANDS_PER_INPUT],
            outstanding_next: 0,
            outstanding_len: 0,
            next_run_ordinal: RunOrdinal(1),
            next_input_ordinal: InputOrdinal(1),
            counters: ReactorCounters::new(),
        }
    }

    #[must_use]
    pub const fn engine(
        &self,
    ) -> &ExecutionEngine<MAX_BOOK_ORDERS, MAX_BOOK_LEVELS, MAX_ORDERS, MAX_RECENT_TRADES, MAX_FILLS>
    {
        &self.engine
    }

    #[must_use]
    pub const fn counters(&self) -> ReactorCounters {
        self.counters
    }

    #[must_use]
    pub const fn has_retained_event(&self) -> bool {
        self.retained_event.is_some()
    }

    #[must_use]
    pub const fn retained_event(&self) -> Option<ReactorInput> {
        self.retained_event
    }

    #[must_use]
    pub const fn mandatory_kill_pending(&self) -> bool {
        self.mandatory_kill.is_some()
    }

    /// Schedule a source-less internal safety kill without fabricating or retaining
    /// a reactor input.
    ///
    /// The request is idempotent while safety work is pending. The next reactor run
    /// drains any already-published transmission feedback first, then applies an
    /// [`KillCode::InternalInvariant`] kill before normal input processing.
    ///
    /// Returns `true` only when this call acquires the pending safety request.
    #[must_use]
    pub fn trip_internal_safety(&mut self) -> bool {
        if self.mandatory_kill.is_some() {
            return false;
        }
        self.mandatory_kill = Some(MandatoryKill { _private: () });
        bump(
            &mut self.counters.mandatory_kill_requests,
            &mut self.counters.saturated,
        );
        true
    }

    #[must_use]
    pub const fn outstanding_transmissions(&self) -> usize {
        self.outstanding_len.saturating_sub(self.outstanding_next)
    }

    /// Exact equality of execution and scheduler state at an observation boundary.
    /// Diagnostic counters are included because they expose divergent routing, run,
    /// saturation, and fault histories.
    #[must_use]
    pub fn deterministic_state_eq(&self, other: &Self) -> bool {
        self.engine.deterministic_state_eq(&other.engine)
            && self.retained_event == other.retained_event
            && self.mandatory_kill.is_some() == other.mandatory_kill.is_some()
            && self.outstanding == other.outstanding
            && self.outstanding_next == other.outstanding_next
            && self.outstanding_len == other.outstanding_len
            && self.next_run_ordinal == other.next_run_ordinal
            && self.next_input_ordinal == other.next_input_ordinal
            && self.counters == other.counters
    }

    /// Drain priority transmission feedback, then consume a bounded normal FIFO prefix.
    ///
    /// Both egress slots and both ingress lanes are caller-owned fixed storage. Egress
    /// must contain only `None`; this prevents reuse from overwriting unresolved
    /// commands. An event capable of producing commands is never sent to the engine
    /// unless two clean egress slots are available.
    ///
    /// # Errors
    ///
    /// Returns a failure with partial progress for dirty egress, invalid timer or
    /// transmission contracts, engine errors, or internal output-contract faults.
    #[allow(
        clippy::result_large_err,
        reason = "boxing the detailed failure would allocate on the hot-path fault path"
    )]
    pub fn run<const EVENT_SLOTS: usize, const TRANSMISSION_SLOTS: usize>(
        &mut self,
        events: &mut Consumer<'_, ReactorInput, EVENT_SLOTS>,
        transmissions: &mut Consumer<'_, TransmissionInput, TRANSMISSION_SLOTS>,
        budget: ReactorBudget,
        egress: &mut [Option<ReactorEgress>],
    ) -> Result<ReactorRunReport, ReactorFailure> {
        self.run_with_control_origin(
            events,
            transmissions,
            budget,
            egress,
            ControlDispatchOrigin::LiveAuthenticated,
        )
    }

    #[allow(
        clippy::result_large_err,
        reason = "replay retains the exact fixed hot-path failure without allocation"
    )]
    pub(crate) fn run_replay<const EVENT_SLOTS: usize, const TRANSMISSION_SLOTS: usize>(
        &mut self,
        events: &mut Consumer<'_, ReactorInput, EVENT_SLOTS>,
        transmissions: &mut Consumer<'_, TransmissionInput, TRANSMISSION_SLOTS>,
        budget: ReactorBudget,
        egress: &mut [Option<ReactorEgress>],
    ) -> Result<ReactorRunReport, ReactorFailure> {
        self.run_with_control_origin(
            events,
            transmissions,
            budget,
            egress,
            ControlDispatchOrigin::JournalReplay,
        )
    }

    #[allow(
        clippy::result_large_err,
        reason = "the shared dispatcher retains the exact fixed hot-path failure"
    )]
    fn run_with_control_origin<const EVENT_SLOTS: usize, const TRANSMISSION_SLOTS: usize>(
        &mut self,
        events: &mut Consumer<'_, ReactorInput, EVENT_SLOTS>,
        transmissions: &mut Consumer<'_, TransmissionInput, TRANSMISSION_SLOTS>,
        budget: ReactorBudget,
        egress: &mut [Option<ReactorEgress>],
        control_origin: ControlDispatchOrigin,
    ) -> Result<ReactorRunReport, ReactorFailure> {
        let mut report = self.empty_report();
        if let Some(index) = egress.iter().position(Option::is_some) {
            return Err(self.failure(ReactorError::DirtyEgressSlot { index }, report));
        }
        let run_ordinal = self
            .allocate_run_ordinal()
            .map_err(|error| self.failure(error, report))?;
        report.run_ordinal = Some(run_ordinal);
        bump(&mut self.counters.runs, &mut self.counters.saturated);

        if let Some(stop) = self.drain_transmissions(transmissions, budget, &mut report)? {
            report.stop = stop;
            return Ok(self.finish_report(report));
        }
        if let Some(stop) = self.apply_mandatory_kill(egress, &mut report)? {
            report.stop = stop;
            return Ok(self.finish_report(report));
        }
        self.process_events(events, budget, egress, report, control_origin)
    }

    #[allow(
        clippy::result_large_err,
        reason = "the public fault retains exact fixed-size engine diagnostics without allocation"
    )]
    fn drain_transmissions<const N: usize>(
        &mut self,
        transmissions: &mut Consumer<'_, TransmissionInput, N>,
        budget: ReactorBudget,
        report: &mut ReactorRunReport,
    ) -> Result<Option<ReactorStop>, ReactorFailure> {
        while report.transmissions_processed < budget.max_transmissions {
            let Some(input) = transmissions.try_pop() else {
                if self.outstanding_transmissions() != 0 {
                    bump(
                        &mut self.counters.transmission_wait_stops,
                        &mut self.counters.saturated,
                    );
                    return Ok(Some(ReactorStop::AwaitingTransmission {
                        outstanding: self.outstanding_transmissions(),
                    }));
                }
                return Ok(None);
            };
            bump(
                &mut self.counters.transmissions_dequeued,
                &mut self.counters.saturated,
            );
            match self.expected_transmission() {
                Some(expected) if input.command != expected => {
                    bump(
                        &mut self.counters.input_contract_errors,
                        &mut self.counters.saturated,
                    );
                    let _new_request = self.trip_internal_safety();
                    return Err(self.failure(
                        ReactorError::TransmissionMismatch {
                            expected,
                            received: input.command,
                        },
                        *report,
                    ));
                }
                None => {
                    bump(
                        &mut self.counters.input_contract_errors,
                        &mut self.counters.saturated,
                    );
                    let _new_request = self.trip_internal_safety();
                    return Err(
                        self.failure(ReactorError::UnexpectedTransmission(input.command), *report)
                    );
                }
                Some(_) => {}
            }
            let ordinal = match self.allocate_ordinal() {
                Ok(ordinal) => ordinal,
                Err(error) => {
                    let _new_request = self.trip_internal_safety();
                    return Err(self.failure(error, *report));
                }
            };
            report.transmissions_processed += 1;
            report.last_input_ordinal = Some(ordinal);
            bump(
                &mut self.counters.transmissions_processed,
                &mut self.counters.saturated,
            );
            if let Err(source) =
                self.engine
                    .on_transmission(input.command, input.status, input.monotonic_now)
            {
                bump(
                    &mut self.counters.engine_errors,
                    &mut self.counters.saturated,
                );
                let _new_request = self.trip_internal_safety();
                return Err(self.failure(
                    ReactorError::Engine {
                        input: ReactorInputKind::Transmission,
                        source,
                    },
                    *report,
                ));
            }
            self.acknowledge_transmission(input);
        }
        if self.outstanding_transmissions() != 0 || transmissions.available() != 0 {
            return Ok(Some(ReactorStop::TransmissionBudgetExhausted));
        }
        Ok(None)
    }

    #[allow(
        clippy::result_large_err,
        reason = "the public fault retains exact fixed-size engine diagnostics without allocation"
    )]
    fn apply_mandatory_kill(
        &mut self,
        egress: &mut [Option<ReactorEgress>],
        report: &mut ReactorRunReport,
    ) -> Result<Option<ReactorStop>, ReactorFailure> {
        let Some(_pending) = self.mandatory_kill else {
            return Ok(None);
        };
        if egress.len() < MAX_REACTOR_COMMANDS_PER_INPUT {
            return Ok(Some(ReactorStop::MandatoryKillRequired {
                required_egress: MAX_REACTOR_COMMANDS_PER_INPUT,
                available_egress: egress.len(),
            }));
        }

        let mut commands = [None; MAX_REACTOR_COMMANDS_PER_INPUT];
        let declared = match self
            .engine
            .fail_closed(KillCode::InternalInvariant, &mut commands)
        {
            Ok(batch) => batch.commands,
            Err(_source) if self.engine.kill_snapshot().is_some() => {
                bump(
                    &mut self.counters.engine_errors,
                    &mut self.counters.saturated,
                );
                match self.engine.prepare_kill_cancels(&mut commands) {
                    Ok(batch) => batch.commands,
                    Err(cancel_source) => {
                        return Err(self.failure(
                            ReactorError::Engine {
                                input: ReactorInputKind::SafetyKill,
                                source: cancel_source,
                            },
                            *report,
                        ));
                    }
                }
            }
            Err(source) => {
                bump(
                    &mut self.counters.engine_errors,
                    &mut self.counters.saturated,
                );
                return Err(self.failure(
                    ReactorError::Engine {
                        input: ReactorInputKind::SafetyKill,
                        source,
                    },
                    *report,
                ));
            }
        };
        let populated = self.validate_engine_output(declared, &commands, *report)?;
        self.mandatory_kill = None;
        bump(
            &mut self.counters.mandatory_kills_applied,
            &mut self.counters.saturated,
        );
        if populated == 0 {
            return Ok(Some(ReactorStop::MandatoryKillApplied));
        }
        self.publish_commands(InputOrdinal(0), &commands, populated, egress, report)?;
        Ok(Some(ReactorStop::TransmissionBoundary {
            published: populated,
            outstanding: self.outstanding_transmissions(),
        }))
    }

    #[allow(
        clippy::result_large_err,
        reason = "the public fault retains exact fixed-size engine diagnostics without allocation"
    )]
    fn process_events<const N: usize>(
        &mut self,
        events: &mut Consumer<'_, ReactorInput, N>,
        budget: ReactorBudget,
        egress: &mut [Option<ReactorEgress>],
        mut report: ReactorRunReport,
        control_origin: ControlDispatchOrigin,
    ) -> Result<ReactorRunReport, ReactorFailure> {
        while report.events_processed < budget.max_events {
            let input = if let Some(retained) = self.retained_event.take() {
                retained
            } else if let Some(input) = events.try_pop() {
                bump(
                    &mut self.counters.events_dequeued,
                    &mut self.counters.saturated,
                );
                input
            } else {
                report.stop = ReactorStop::InputDrained;
                return Ok(self.finish_report(report));
            };

            let required = input.maximum_commands();
            if required > egress.len() {
                self.retained_event = Some(input);
                report.stop = self.enter_egress_fail_closed(egress.len());
                return Ok(self.finish_report(report));
            }
            let ordinal = self
                .allocate_ordinal()
                .map_err(|error| self.failure(error, report))?;
            report.events_processed += 1;
            report.last_input_ordinal = Some(ordinal);
            bump(
                &mut self.counters.events_processed,
                &mut self.counters.saturated,
            );
            self.bump_event_kind(input.kind());
            if let ReactorInput::Timer(timer) = input
                && !valid_timer(timer)
            {
                bump(
                    &mut self.counters.input_contract_errors,
                    &mut self.counters.saturated,
                );
                return Err(self.failure(ReactorError::InvalidTimer(timer), report));
            }

            let mut commands = [None; MAX_REACTOR_COMMANDS_PER_INPUT];
            let declared = match self.dispatch_event(input, &mut commands, control_origin) {
                Ok(declared) => declared,
                Err(source) => {
                    bump(
                        &mut self.counters.engine_errors,
                        &mut self.counters.saturated,
                    );
                    let mut populated = populated_prefix(&commands).unwrap_or_default();
                    if populated == 0 && self.engine.kill_snapshot().is_some() {
                        // Some source types do not ordinarily own output, but any of
                        // them can uncover a fatal invariant. Use the already-reserved
                        // fixed batch to publish emergency cancels while retaining the
                        // initiating typed engine error as the primary failure.
                        match self.engine.prepare_kill_cancels(&mut commands) {
                            Ok(batch) => match populated_prefix(&commands) {
                                Ok(count) if count == batch.commands => populated = count,
                                Ok(_) | Err(_) => commands.fill(None),
                            },
                            Err(_) => commands.fill(None),
                        }
                    }
                    if populated != 0 {
                        self.publish_commands(ordinal, &commands, populated, egress, &mut report)?;
                    }
                    return Err(self.failure(
                        ReactorError::Engine {
                            input: input.kind(),
                            source,
                        },
                        report,
                    ));
                }
            };
            let populated = self.validate_engine_output(declared, &commands, report)?;
            if populated != 0 {
                self.publish_commands(ordinal, &commands, populated, egress, &mut report)?;
                report.stop = ReactorStop::TransmissionBoundary {
                    published: populated,
                    outstanding: self.outstanding_transmissions(),
                };
                return Ok(self.finish_report(report));
            }
        }
        report.stop = ReactorStop::EventBudgetExhausted;
        Ok(self.finish_report(report))
    }

    fn enter_egress_fail_closed(&mut self, available: usize) -> ReactorStop {
        if self.engine.kill_snapshot().is_some() {
            ReactorStop::EmergencyEgressRequired {
                required_egress: MAX_REACTOR_COMMANDS_PER_INPUT,
                available_egress: available,
            }
        } else {
            let _new_request = self.trip_internal_safety();
            ReactorStop::MandatoryKillRequired {
                required_egress: MAX_REACTOR_COMMANDS_PER_INPUT,
                available_egress: available,
            }
        }
    }

    fn dispatch_event(
        &mut self,
        input: ReactorInput,
        commands: &mut [Option<OrderCommand>; MAX_REACTOR_COMMANDS_PER_INPUT],
        control_origin: ControlDispatchOrigin,
    ) -> Result<usize, EngineError> {
        match input {
            ReactorInput::Clock(clock) => {
                self.engine.observe_clock(clock.sample)?;
                Ok(0)
            }
            ReactorInput::Snapshot(snapshot) => self
                .engine
                .on_snapshot(snapshot.message, snapshot.monotonic_now, commands)
                .map(|outcome| outcome.output.commands),
            ReactorInput::MarketData(market) => self
                .engine
                .on_market_data(market.message, market.monotonic_now, commands)
                .map(|outcome| outcome.output.commands),
            ReactorInput::OrderEntry(order_entry) => self
                .engine
                .on_order_entry(order_entry.message, order_entry.monotonic_now, commands)
                .map(|outcome| outcome.output.commands),
            ReactorInput::DropCopy(drop_copy) => self
                .engine
                .on_drop_copy(drop_copy.message, drop_copy.monotonic_now, commands)
                .map(|outcome| outcome.commands),
            ReactorInput::OwnedMboBinding(binding) => self
                .engine
                .on_owned_mbo_binding(binding.binding, binding.monotonic_now)
                .map(|_| 0),
            ReactorInput::Control(control) => match control_origin {
                ControlDispatchOrigin::LiveAuthenticated => self
                    .engine
                    .apply_control_decision(control.decision(), commands)
                    .map(|outcome| outcome.commands),
                ControlDispatchOrigin::JournalReplay => self
                    .engine
                    .apply_replayed_control_decision(control.decision(), commands)
                    .map(|outcome| outcome.commands),
            },
            ReactorInput::Timer(timer) => match timer.action {
                TimerAction::KillCancelSweep if self.engine.kill_snapshot().is_some() => self
                    .engine
                    .prepare_kill_cancels(commands)
                    .map(|outcome| outcome.commands),
                TimerAction::KillCancelSweep => Ok(0),
                TimerAction::ControlLivenessCheck => self
                    .engine
                    .check_control_liveness(timer.fired_at, commands)
                    .map(|outcome| outcome.commands),
                TimerAction::DropCopyLivenessCheck => self
                    .engine
                    .check_drop_copy_liveness(timer.fired_at, commands)
                    .map(|outcome| outcome.commands),
            },
        }
    }

    #[allow(
        clippy::result_large_err,
        reason = "the public fault retains exact fixed-size engine diagnostics without allocation"
    )]
    fn validate_engine_output(
        &self,
        declared: usize,
        commands: &[Option<OrderCommand>; MAX_REACTOR_COMMANDS_PER_INPUT],
        report: ReactorRunReport,
    ) -> Result<usize, ReactorFailure> {
        let populated = populated_prefix(commands).map_err(|populated| {
            self.failure(
                ReactorError::EngineOutputContract {
                    declared,
                    populated,
                },
                report,
            )
        })?;
        if declared != populated || declared > MAX_REACTOR_COMMANDS_PER_INPUT {
            return Err(self.failure(
                ReactorError::EngineOutputContract {
                    declared,
                    populated,
                },
                report,
            ));
        }
        Ok(populated)
    }

    #[allow(
        clippy::result_large_err,
        reason = "the public fault retains exact fixed-size engine diagnostics without allocation"
    )]
    fn publish_commands(
        &mut self,
        ordinal: InputOrdinal,
        commands: &[Option<OrderCommand>; MAX_REACTOR_COMMANDS_PER_INPUT],
        count: usize,
        egress: &mut [Option<ReactorEgress>],
        report: &mut ReactorRunReport,
    ) -> Result<(), ReactorFailure> {
        if self.outstanding_transmissions() != 0 {
            return Err(self.failure(ReactorError::InternalInvariant, *report));
        }
        self.outstanding = [None; MAX_REACTOR_COMMANDS_PER_INPUT];
        self.outstanding_next = 0;
        self.outstanding_len = count;
        for index in 0..count {
            let Some(command) = commands.get(index).copied().flatten() else {
                return Err(self.failure(ReactorError::InternalInvariant, *report));
            };
            let Some(slot) = egress.get_mut(report.commands_published + index) else {
                return Err(self.failure(ReactorError::InternalInvariant, *report));
            };
            let command_index = u8::try_from(index)
                .map_err(|_| self.failure(ReactorError::InternalInvariant, *report))?;
            *slot = Some(ReactorEgress {
                input_ordinal: ordinal,
                command_index,
                command,
            });
            self.outstanding[index] = Some(command);
        }
        report.commands_published += count;
        add(
            &mut self.counters.commands_published,
            count,
            &mut self.counters.saturated,
        );
        Ok(())
    }

    fn expected_transmission(&self) -> Option<OrderCommand> {
        self.outstanding
            .get(self.outstanding_next)
            .copied()
            .flatten()
    }

    fn acknowledge_transmission(&mut self, input: TransmissionInput) {
        if self.outstanding_transmissions() != 0 {
            self.outstanding[self.outstanding_next] = None;
            self.outstanding_next += 1;
            if self.outstanding_next == self.outstanding_len {
                self.outstanding_next = 0;
                self.outstanding_len = 0;
            }
        }
        match input.status {
            TransmissionStatus::Sent => bump(
                &mut self.counters.transmissions_sent,
                &mut self.counters.saturated,
            ),
            TransmissionStatus::ProvenUnsent => bump(
                &mut self.counters.transmissions_proven_unsent,
                &mut self.counters.saturated,
            ),
        }
    }

    fn allocate_ordinal(&mut self) -> Result<InputOrdinal, ReactorError> {
        let ordinal = self.next_input_ordinal;
        self.next_input_ordinal = InputOrdinal(
            ordinal
                .0
                .checked_add(1)
                .ok_or(ReactorError::InputOrdinalExhausted)?,
        );
        Ok(ordinal)
    }

    fn allocate_run_ordinal(&mut self) -> Result<RunOrdinal, ReactorError> {
        let ordinal = self.next_run_ordinal;
        self.next_run_ordinal = RunOrdinal(
            ordinal
                .0
                .checked_add(1)
                .ok_or(ReactorError::RunOrdinalExhausted)?,
        );
        Ok(ordinal)
    }

    fn bump_event_kind(&mut self, kind: ReactorInputKind) {
        let (counter, saturated) = match kind {
            ReactorInputKind::Clock => (
                &mut self.counters.clock_inputs,
                &mut self.counters.saturated,
            ),
            ReactorInputKind::Snapshot => (
                &mut self.counters.snapshot_inputs,
                &mut self.counters.saturated,
            ),
            ReactorInputKind::MarketData => (
                &mut self.counters.market_data_inputs,
                &mut self.counters.saturated,
            ),
            ReactorInputKind::OrderEntry => (
                &mut self.counters.order_entry_inputs,
                &mut self.counters.saturated,
            ),
            ReactorInputKind::DropCopy => (
                &mut self.counters.drop_copy_inputs,
                &mut self.counters.saturated,
            ),
            ReactorInputKind::OwnedMboBinding => (
                &mut self.counters.owned_mbo_binding_inputs,
                &mut self.counters.saturated,
            ),
            ReactorInputKind::Control => (
                &mut self.counters.control_inputs,
                &mut self.counters.saturated,
            ),
            ReactorInputKind::Timer => (
                &mut self.counters.timer_inputs,
                &mut self.counters.saturated,
            ),
            ReactorInputKind::Transmission | ReactorInputKind::SafetyKill => return,
        };
        bump(counter, saturated);
    }

    fn empty_report(&self) -> ReactorRunReport {
        ReactorRunReport {
            run_ordinal: None,
            events_processed: 0,
            transmissions_processed: 0,
            commands_published: 0,
            last_input_ordinal: None,
            outstanding_transmissions: self.outstanding_transmissions(),
            event_retained: self.retained_event.is_some(),
            mandatory_kill_pending: self.mandatory_kill.is_some(),
            stop: ReactorStop::Failed,
        }
    }

    fn finish_report(&self, mut report: ReactorRunReport) -> ReactorRunReport {
        report.outstanding_transmissions = self.outstanding_transmissions();
        report.event_retained = self.retained_event.is_some();
        report.mandatory_kill_pending = self.mandatory_kill.is_some();
        report
    }

    fn failure(&self, error: ReactorError, report: ReactorRunReport) -> ReactorFailure {
        ReactorFailure {
            error,
            report: self.finish_report(report),
        }
    }
}

impl ReactorCounters {
    const fn new() -> Self {
        Self {
            runs: 0,
            events_dequeued: 0,
            events_processed: 0,
            transmissions_dequeued: 0,
            transmissions_processed: 0,
            clock_inputs: 0,
            snapshot_inputs: 0,
            market_data_inputs: 0,
            order_entry_inputs: 0,
            drop_copy_inputs: 0,
            owned_mbo_binding_inputs: 0,
            control_inputs: 0,
            timer_inputs: 0,
            commands_published: 0,
            transmissions_sent: 0,
            transmissions_proven_unsent: 0,
            transmission_wait_stops: 0,
            mandatory_kill_requests: 0,
            mandatory_kills_applied: 0,
            engine_errors: 0,
            input_contract_errors: 0,
            saturated: false,
        }
    }
}

fn valid_timer(timer: TimerInput) -> bool {
    timer.timer_id.0 != 0
        && timer.scheduled_at != MonotonicTimestampNs::ZERO
        && timer.fired_at >= timer.scheduled_at
}

fn populated_prefix(
    commands: &[Option<OrderCommand>; MAX_REACTOR_COMMANDS_PER_INPUT],
) -> Result<usize, usize> {
    let populated = commands.iter().filter(|slot| slot.is_some()).count();
    if commands.iter().take(populated).all(Option::is_some)
        && commands.iter().skip(populated).all(Option::is_none)
    {
        Ok(populated)
    } else {
        Err(populated)
    }
}

fn bump(counter: &mut u64, saturated: &mut bool) {
    add(counter, 1, saturated);
}

fn add(counter: &mut u64, amount: usize, saturated: &mut bool) {
    let converted = u64::try_from(amount).unwrap_or(u64::MAX);
    if let Some(value) = counter.checked_add(converted) {
        *counter = value;
    } else {
        *counter = u64::MAX;
        *saturated = true;
    }
}
