//! Allocation-free dispatch of normalized journal events into the real execution engine.

use crate::engine::{EngineError, ExecutionEngine};
use crate::event_codec::{EventCodecError, ReplayInput, decode_replay_input};
use crate::events::NormalizedEvent;
use crate::reactor::{MAX_REACTOR_COMMANDS_PER_INPUT, ReactorInput, TimerAction};
use crate::venue::OrderCommand;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EngineReplayError {
    Codec(EventCodecError),
    Engine(EngineError),
    OutputContract { declared: usize, populated: usize },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EngineReplayRoute {
    Normal,
    PriorityTransmission,
    NoEngineInput,
    RetainedNormal,
    SafetyKill,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EngineReplayOutcome {
    pub route: EngineReplayRoute,
    pub commands: usize,
}

/// Decode and apply one journal event to the same engine APIs used by the hot reactor.
/// Caller-owned output is cleared before dispatch and remains inspectable on failure.
///
/// # Errors
///
/// Returns a codec, engine, or output-contract error. All underlying engine fail-closed
/// behavior is preserved.
#[allow(
    clippy::result_large_err,
    reason = "replay certification retains exact fixed-size engine diagnostics"
)]
pub fn dispatch_engine_replay_event<
    const MAX_BOOK_ORDERS: usize,
    const MAX_BOOK_LEVELS: usize,
    const MAX_ORDERS: usize,
    const MAX_RECENT_TRADES: usize,
    const MAX_FILLS: usize,
>(
    engine: &mut ExecutionEngine<
        MAX_BOOK_ORDERS,
        MAX_BOOK_LEVELS,
        MAX_ORDERS,
        MAX_RECENT_TRADES,
        MAX_FILLS,
    >,
    event: NormalizedEvent,
    output: &mut [Option<OrderCommand>; MAX_REACTOR_COMMANDS_PER_INPUT],
) -> Result<EngineReplayOutcome, EngineReplayError> {
    output.fill(None);
    let replay_input = decode_replay_input(event).map_err(EngineReplayError::Codec)?;
    let (route, declared) = match replay_input {
        ReplayInput::Reactor(input) => (
            EngineReplayRoute::Normal,
            dispatch_normal_input(engine, input, output).map_err(EngineReplayError::Engine)?,
        ),
        ReplayInput::Transmission(input) => {
            engine
                .on_transmission(input.command, input.status, input.monotonic_now)
                .map_err(EngineReplayError::Engine)?;
            (EngineReplayRoute::PriorityTransmission, 0)
        }
        ReplayInput::NoEngineInput => (EngineReplayRoute::NoEngineInput, 0),
    };
    let populated =
        populated_prefix(output).map_err(|populated| EngineReplayError::OutputContract {
            declared,
            populated,
        })?;
    if populated != declared {
        return Err(EngineReplayError::OutputContract {
            declared,
            populated,
        });
    }
    Ok(EngineReplayOutcome {
        route,
        commands: declared,
    })
}

fn dispatch_normal_input<
    const MAX_BOOK_ORDERS: usize,
    const MAX_BOOK_LEVELS: usize,
    const MAX_ORDERS: usize,
    const MAX_RECENT_TRADES: usize,
    const MAX_FILLS: usize,
>(
    engine: &mut ExecutionEngine<
        MAX_BOOK_ORDERS,
        MAX_BOOK_LEVELS,
        MAX_ORDERS,
        MAX_RECENT_TRADES,
        MAX_FILLS,
    >,
    input: ReactorInput,
    output: &mut [Option<OrderCommand>; MAX_REACTOR_COMMANDS_PER_INPUT],
) -> Result<usize, EngineError> {
    match input {
        ReactorInput::Clock(clock) => {
            engine.observe_clock(clock.sample)?;
            Ok(0)
        }
        ReactorInput::Snapshot(snapshot) => engine
            .on_snapshot(snapshot.message, snapshot.monotonic_now, output)
            .map(|outcome| outcome.output.commands),
        ReactorInput::MarketData(market) => engine
            .on_market_data(market.message, market.monotonic_now, output)
            .map(|outcome| outcome.output.commands),
        ReactorInput::OrderEntry(order_entry) => engine
            .on_order_entry(order_entry.message, order_entry.monotonic_now, output)
            .map(|outcome| outcome.output.commands),
        ReactorInput::DropCopy(drop_copy) => engine
            .on_drop_copy(drop_copy.message, drop_copy.monotonic_now, output)
            .map(|outcome| outcome.commands),
        ReactorInput::OwnedMboBinding(binding) => engine
            .on_owned_mbo_binding(binding.binding, binding.monotonic_now)
            .map(|_| 0),
        ReactorInput::Control(control) => engine
            .apply_replayed_control_decision(control.decision(), output)
            .map(|outcome| outcome.commands),
        ReactorInput::Timer(timer) => match timer.action {
            TimerAction::KillCancelSweep if engine.kill_snapshot().is_some() => engine
                .prepare_kill_cancels(output)
                .map(|outcome| outcome.commands),
            TimerAction::KillCancelSweep => Ok(0),
            TimerAction::ControlLivenessCheck => engine
                .check_control_liveness(timer.fired_at, output)
                .map(|outcome| outcome.commands),
            TimerAction::DropCopyLivenessCheck => engine
                .check_drop_copy_liveness(timer.fired_at, output)
                .map(|outcome| outcome.commands),
        },
    }
}

fn populated_prefix(
    output: &[Option<OrderCommand>; MAX_REACTOR_COMMANDS_PER_INPUT],
) -> Result<usize, usize> {
    let populated = output.iter().filter(|slot| slot.is_some()).count();
    if output[..populated].iter().all(Option::is_some)
        && output[populated..].iter().all(Option::is_none)
    {
        Ok(populated)
    } else {
        Err(populated)
    }
}
