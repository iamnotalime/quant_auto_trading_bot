//! Allocation-free conversion between typed hot-path inputs and journal events.
//!
//! The journal persists the exact inputs presented to the single-writer reactor. A
//! replay consumer can therefore reconstruct normal-lane and priority-lane inputs
//! without venue-specific guessing or heap allocation.

use crate::clock::ClockSample;
use crate::control::{
    ConfigDigest, ControlDecision, ControlDecisionOrigin, ControlKillReason, ControlKillRequest,
    EngineControlAction,
};
use crate::engine::TransmissionStatus;
use crate::events::{
    CaptureOrdinal, ControlEventOrigin, EVENT_FLAG_RECOVERY, EVENT_FLAG_SNAPSHOT, EventError,
    EventKind, EventSide, EventSource, NormalizedEvent, SequenceDomain,
};
use crate::reactor::{
    ClockInput, ControlInput, DropCopyInput, MarketDataInput, OrderEntryInput,
    OwnedMboBindingInput, ReactorInput, SnapshotInput, TimerAction, TimerId, TimerInput,
    TransmissionInput,
};
use crate::types::{
    EventHeader, InstrumentId, MonotonicTimestampNs, OrderId, PriceTicks, Quantity, Sequence,
    TimestampNs, VenueId,
};
use crate::venue::{
    Accepted, BookDelta, CancelAll, CancelOrder, CancelScope, Canceled, ClientOrderId, Fill,
    InboundMessage, InboundPayload, LifecycleCorrectionDigest, LifecycleCorrectionId,
    LifecycleCorrectionKind, LifecycleCorrectionObserved, LiquidityFlag, MarketByOrderId,
    MarketDataMessage, MarketDataPayload, NewOrder, OrderCommand, OrderEvent, OwnedMboBinding,
    OwnedMboBindingMethod, RejectCode, Rejected, ReplaceOrder, SessionEvent, SnapshotMessage,
    SnapshotOrder, SnapshotPayload, TimeInForce, TradeId, VenueOrderId,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VenueCaptureMetadata {
    pub venue: VenueId,
    pub source: EventSource,
    pub capture_ordinal: CaptureOrdinal,
    pub monotonic_timestamp: MonotonicTimestampNs,
    /// True only for events inside an explicitly journaled recovery boundary.
    pub recovery: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SnapshotCaptureMetadata {
    pub venue: VenueCaptureMetadata,
    pub snapshot_id: u64,
    pub last_incremental_sequence: Sequence,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayInput {
    Reactor(ReactorInput),
    Transmission(TransmissionInput),
    /// A recovery/snapshot boundary or protocol heartbeat with no engine mutation.
    NoEngineInput,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventCodecError {
    InvalidEvent(EventError),
    UnexpectedKind(EventKind),
    InvalidSnapshotContext,
    InvalidCode { kind: EventKind, code: u64 },
    IntegerOutOfRange { kind: EventKind, value: u64 },
    InvalidControlDecision,
    InvalidOrderCommand,
}

impl From<EventError> for EventCodecError {
    fn from(error: EventError) -> Self {
        Self::InvalidEvent(error)
    }
}

/// Normalize one decoded direct-feed message.
///
/// # Errors
///
/// Returns an error when metadata, timestamps, source domain, or payload fields are
/// not canonical.
pub fn normalize_market_data(
    metadata: VenueCaptureMetadata,
    message: MarketDataMessage,
) -> Result<NormalizedEvent, EventCodecError> {
    let fields = market_fields(message.payload);
    checked(NormalizedEvent::new_full(
        venue_header(
            metadata,
            message.instrument,
            message.sequence,
            message.exchange_timestamp,
            message.hardware_receive_timestamp,
        ),
        metadata.source,
        metadata.capture_ordinal,
        metadata.monotonic_timestamp,
        fields.kind,
        fields.side,
        recovery_flag(metadata.recovery),
        fields.order_id,
        0,
        0,
        fields.price,
        fields.quantity,
        Quantity::ZERO,
        fields.reference,
        fields.auxiliary,
        [0; 32],
    ))
}

/// Normalize one decoded native order-entry input.
///
/// # Errors
///
/// Returns an error when metadata, timestamps, source domain, or payload fields are
/// not canonical.
pub fn normalize_order_entry(
    metadata: VenueCaptureMetadata,
    message: InboundMessage,
) -> Result<NormalizedEvent, EventCodecError> {
    if metadata.source.sequence_domain != SequenceDomain::OrderEntry {
        return Err(EventCodecError::UnexpectedKind(
            order_entry_fields(message.payload).kind,
        ));
    }
    normalize_execution_report(metadata, message)
}

/// Normalize one decoded independent drop-copy input.
///
/// # Errors
///
/// Returns an error unless metadata binds the dedicated drop-copy sequence domain
/// and every timestamp and payload field is canonical.
pub fn normalize_drop_copy(
    metadata: VenueCaptureMetadata,
    message: InboundMessage,
) -> Result<NormalizedEvent, EventCodecError> {
    if metadata.source.sequence_domain != SequenceDomain::DropCopy {
        return Err(EventCodecError::UnexpectedKind(
            order_entry_fields(message.payload).kind,
        ));
    }
    normalize_execution_report(metadata, message)
}

fn normalize_execution_report(
    metadata: VenueCaptureMetadata,
    message: InboundMessage,
) -> Result<NormalizedEvent, EventCodecError> {
    let fields = order_entry_fields(message.payload);
    checked(NormalizedEvent::new_full(
        venue_header(
            metadata,
            InstrumentId(0),
            message.sequence,
            message.exchange_timestamp,
            message.hardware_receive_timestamp,
        ),
        metadata.source,
        metadata.capture_ordinal,
        metadata.monotonic_timestamp,
        fields.kind,
        EventSide::None,
        recovery_flag(metadata.recovery),
        fields.order_id,
        fields.secondary_id,
        fields.tertiary_id,
        fields.price,
        fields.quantity,
        fields.leaves,
        fields.reference,
        fields.auxiliary,
        fields.blob,
    ))
}

/// Normalize one snapshot begin/order/end message. Snapshot orders do not carry the
/// snapshot identifier or anchor themselves, so the active transaction metadata is
/// mandatory and is checked against begin/end messages.
///
/// # Errors
///
/// Returns an error for a mismatched transaction or non-canonical event.
pub fn normalize_snapshot(
    metadata: SnapshotCaptureMetadata,
    message: SnapshotMessage,
) -> Result<NormalizedEvent, EventCodecError> {
    let (kind, instrument, side, order_id, price, quantity) = match message.payload {
        SnapshotPayload::Begin {
            snapshot_id,
            last_incremental_sequence,
        } => {
            ensure_snapshot_context(metadata, snapshot_id, last_incremental_sequence)?;
            (
                EventKind::SnapshotStart,
                InstrumentId(0),
                EventSide::None,
                OrderId(0),
                PriceTicks::ZERO,
                Quantity::ZERO,
            )
        }
        SnapshotPayload::Order(order) => (
            EventKind::BookAdd,
            order.instrument,
            order.side.into(),
            OrderId(order.order_id.0),
            order.price,
            order.quantity,
        ),
        SnapshotPayload::End {
            snapshot_id,
            last_incremental_sequence,
        } => {
            ensure_snapshot_context(metadata, snapshot_id, last_incremental_sequence)?;
            (
                EventKind::SnapshotEnd,
                InstrumentId(0),
                EventSide::None,
                OrderId(0),
                PriceTicks::ZERO,
                Quantity::ZERO,
            )
        }
    };
    checked(NormalizedEvent::new_full(
        venue_header(
            metadata.venue,
            instrument,
            metadata.last_incremental_sequence,
            message.exchange_timestamp,
            message.hardware_receive_timestamp,
        ),
        metadata.venue.source,
        metadata.venue.capture_ordinal,
        metadata.venue.monotonic_timestamp,
        kind,
        side,
        EVENT_FLAG_SNAPSHOT | recovery_flag(metadata.venue.recovery),
        order_id,
        0,
        0,
        price,
        quantity,
        Quantity::ZERO,
        metadata.snapshot_id,
        0,
        [0; 32],
    ))
}

/// Normalize one accepted clock-discipline sample.
///
/// # Errors
///
/// Returns an error for zero clocks or a zero capture ordinal.
pub fn normalize_clock(
    capture_ordinal: CaptureOrdinal,
    sample: ClockSample,
) -> Result<NormalizedEvent, EventCodecError> {
    checked(local_event(
        capture_ordinal,
        sample.monotonic,
        EventKind::ClockSample,
        EventSide::None,
        OrderId(0),
        0,
        0,
        PriceTicks::ZERO,
        Quantity::ZERO,
        Quantity::ZERO,
        sample.utc.0,
        sample.uncertainty_ns,
        [0; 32],
    ))
}

/// Normalize one decision emitted by the authenticated control gate.
///
/// # Errors
///
/// Returns an error for a non-canonical decision. A kill decision must include the
/// first-fault result returned by the kill latch.
pub fn normalize_control_decision(
    capture_ordinal: CaptureOrdinal,
    decision: ControlDecision,
) -> Result<NormalizedEvent, EventCodecError> {
    if decision.origin() != ControlDecisionOrigin::AuthenticatedGate {
        return Err(EventCodecError::InvalidControlDecision);
    }
    let (kind, tertiary_id, auxiliary, blob) = match decision.action() {
        EngineControlAction::Arm {
            config_epoch,
            config_digest,
            lease_deadline,
        } => {
            if decision.kill_first_fault_acquired().is_some() {
                return Err(EventCodecError::InvalidControlDecision);
            }
            (
                EventKind::ControlArm,
                lease_deadline.0,
                config_epoch,
                config_digest.0,
            )
        }
        EngineControlAction::Disarm => {
            if decision.kill_first_fault_acquired().is_some() {
                return Err(EventCodecError::InvalidControlDecision);
            }
            (EventKind::ControlDisarm, 0, 0, [0; 32])
        }
        EngineControlAction::Heartbeat { lease_deadline } => {
            if decision.kill_first_fault_acquired().is_some() {
                return Err(EventCodecError::InvalidControlDecision);
            }
            (EventKind::ControlHeartbeat, lease_deadline.0, 0, [0; 32])
        }
        EngineControlAction::Kill(request) => {
            let first_fault = match decision.kill_first_fault_acquired() {
                Some(false) => 1,
                Some(true) => 2,
                None => return Err(EventCodecError::InvalidControlDecision),
            };
            (
                EventKind::ControlKill,
                request.requested_at.0,
                kill_reason_code(request.reason) | (first_fault << 8),
                [0; 32],
            )
        }
    };
    checked(
        local_event(
            capture_ordinal,
            MonotonicTimestampNs::ZERO,
            kind,
            EventSide::None,
            OrderId(decision.accepted_sequence().0),
            decision.next_sequence().0,
            tertiary_id,
            PriceTicks::ZERO,
            Quantity::ZERO,
            Quantity::ZERO,
            decision.accepted_at().0,
            auxiliary,
            blob,
        )
        .with_control_origin(ControlEventOrigin::AuthenticatedGate),
    )
}

/// Normalize priority-lane transport feedback.
///
/// # Errors
///
/// Returns an error for a non-canonical command, timestamp, or status.
pub fn normalize_transmission(
    capture_ordinal: CaptureOrdinal,
    input: TransmissionInput,
) -> Result<NormalizedEvent, EventCodecError> {
    input
        .command
        .validate()
        .map_err(|_| EventCodecError::InvalidOrderCommand)?;
    let status = transmission_status_code(input.status);
    let (kind, side, order_id, secondary_id, tertiary_id, price, quantity, reference, auxiliary) =
        match input.command {
            OrderCommand::New(order) => (
                EventKind::TransmissionNew,
                order.side.into(),
                OrderId(order.client_order_id.0),
                u64::from(order.instrument.0),
                0,
                order.price,
                order.quantity,
                order.created_at.0,
                status | (time_in_force_code(order.time_in_force) << 8),
            ),
            OrderCommand::Cancel(order) => (
                EventKind::TransmissionCancel,
                EventSide::None,
                OrderId(order.client_order_id.0),
                order.venue_order_id.0,
                0,
                PriceTicks::ZERO,
                Quantity::ZERO,
                order.created_at.0,
                status,
            ),
            OrderCommand::Replace(order) => (
                EventKind::TransmissionReplace,
                EventSide::None,
                OrderId(order.current_client_order_id.0),
                order.replacement_client_order_id.0,
                order.venue_order_id.0,
                order.new_price,
                order.new_quantity,
                order.created_at.0,
                status,
            ),
            OrderCommand::CancelAll(command) => {
                let (instrument, scope) = match command.scope {
                    CancelScope::Session => (0, 1),
                    CancelScope::Instrument(instrument) => (u64::from(instrument.0), 2),
                };
                (
                    EventKind::TransmissionCancelAll,
                    EventSide::None,
                    OrderId(instrument),
                    0,
                    0,
                    PriceTicks::ZERO,
                    Quantity::ZERO,
                    command.created_at.0,
                    status | (scope << 8),
                )
            }
        };
    checked(local_event(
        capture_ordinal,
        input.monotonic_now,
        kind,
        side,
        order_id,
        secondary_id,
        tertiary_id,
        price,
        quantity,
        Quantity::ZERO,
        reference,
        auxiliary,
        [0; 32],
    ))
}

/// Normalize one monotonic scheduler notification.
///
/// # Errors
///
/// Returns an error for zero IDs/timestamps or a fire time before its schedule.
pub fn normalize_timer(
    capture_ordinal: CaptureOrdinal,
    input: TimerInput,
) -> Result<NormalizedEvent, EventCodecError> {
    let action = match input.action {
        TimerAction::KillCancelSweep => 1,
        TimerAction::ControlLivenessCheck => 2,
        TimerAction::DropCopyLivenessCheck => 3,
    };
    checked(local_event(
        capture_ordinal,
        input.fired_at,
        EventKind::Timer,
        EventSide::None,
        OrderId(input.timer_id.0),
        input.scheduled_at.0,
        0,
        PriceTicks::ZERO,
        Quantity::ZERO,
        Quantity::ZERO,
        0,
        action,
        [0; 32],
    ))
}

/// Normalize one explicit private/public owned-order correlation.
///
/// # Errors
///
/// Returns an error for an invalid adapter method, identifier, sequence, venue, or
/// monotonic timestamp.
pub fn normalize_owned_mbo_binding(
    capture_ordinal: CaptureOrdinal,
    input: OwnedMboBindingInput,
) -> Result<NormalizedEvent, EventCodecError> {
    let (method, rule_id) = match input.binding.method {
        OwnedMboBindingMethod::ExplicitNativeIdentifier => (1, 0),
        OwnedMboBindingMethod::CertifiedDeterministicRule { rule_id } => (2, u64::from(rule_id)),
    };
    let auxiliary = method | (rule_id << 8) | (u64::from(input.binding.venue.0) << 40);
    checked(local_event(
        capture_ordinal,
        input.monotonic_now,
        EventKind::OwnedMboBinding,
        EventSide::None,
        OrderId(input.binding.client_order_id.0),
        input.binding.venue_order_id.0,
        input.binding.market_by_order_id.0,
        PriceTicks::ZERO,
        Quantity::ZERO,
        Quantity::ZERO,
        input.binding.order_entry_sequence.0,
        auxiliary,
        [0; 32],
    ))
}

/// Route one validated journal event back to the reactor's normal lane, its priority
/// transmission lane, or a no-engine boundary event.
///
/// # Errors
///
/// Returns an error when the event cannot be represented by the typed hot-path API.
pub fn decode_replay_input(event: NormalizedEvent) -> Result<ReplayInput, EventCodecError> {
    event.validate()?;
    match event.kind {
        EventKind::ClockSample => Ok(ReplayInput::Reactor(ReactorInput::Clock(ClockInput {
            sample: decode_clock(event)?,
        }))),
        EventKind::ControlArm
        | EventKind::ControlDisarm
        | EventKind::ControlHeartbeat
        | EventKind::ControlKill => {
            let decision = decode_control_decision(event)?;
            Ok(ReplayInput::Reactor(ReactorInput::Control(
                ControlInput::new(decision),
            )))
        }
        EventKind::TransmissionNew
        | EventKind::TransmissionCancel
        | EventKind::TransmissionReplace
        | EventKind::TransmissionCancelAll => {
            Ok(ReplayInput::Transmission(decode_transmission(event)?))
        }
        EventKind::Timer => Ok(ReplayInput::Reactor(ReactorInput::Timer(decode_timer(
            event,
        )?))),
        EventKind::OwnedMboBinding => Ok(ReplayInput::Reactor(ReactorInput::OwnedMboBinding(
            decode_owned_mbo_binding(event)?,
        ))),
        EventKind::SnapshotStart | EventKind::SnapshotEnd => Ok(ReplayInput::Reactor(
            ReactorInput::Snapshot(SnapshotInput {
                message: decode_snapshot(event)?,
                monotonic_now: event.monotonic_timestamp,
            }),
        )),
        EventKind::BookAdd if event.is_snapshot() => Ok(ReplayInput::Reactor(
            ReactorInput::Snapshot(SnapshotInput {
                message: decode_snapshot(event)?,
                monotonic_now: event.monotonic_timestamp,
            }),
        )),
        EventKind::BookAdd
        | EventKind::BookModify
        | EventKind::BookCancel
        | EventKind::BookExecute
        | EventKind::BookClear
        | EventKind::Trade
        | EventKind::TradingStatus => Ok(ReplayInput::Reactor(ReactorInput::MarketData(
            MarketDataInput {
                message: decode_market_data(event)?,
                monotonic_now: event.monotonic_timestamp,
            },
        ))),
        EventKind::OrderAccepted
        | EventKind::OrderRejected
        | EventKind::OrderFill
        | EventKind::OrderCancelled
        | EventKind::LifecycleCorrectionObserved
        | EventKind::SessionLogonAccepted
        | EventKind::SessionLogonRejected
        | EventKind::SessionReplayComplete
        | EventKind::SessionSnapshotRequired
        | EventKind::SessionLogout => decode_execution_replay_input(event),
        EventKind::Heartbeat if event.source.sequence_domain == SequenceDomain::OrderEntry => Ok(
            ReplayInput::Reactor(ReactorInput::OrderEntry(OrderEntryInput {
                message: decode_order_entry(event)?,
                monotonic_now: event.monotonic_timestamp,
            })),
        ),
        EventKind::Heartbeat if event.source.sequence_domain == SequenceDomain::DropCopy => Ok(
            ReplayInput::Reactor(ReactorInput::DropCopy(DropCopyInput {
                message: decode_drop_copy(event)?,
                monotonic_now: event.monotonic_timestamp,
            })),
        ),
        EventKind::Heartbeat | EventKind::RecoveryStart | EventKind::RecoveryEnd => {
            Ok(ReplayInput::NoEngineInput)
        }
    }
}

/// Decode a journaled market-data event.
///
/// # Errors
///
/// Returns an error if `event` is not a non-snapshot market-data input.
pub fn decode_market_data(event: NormalizedEvent) -> Result<MarketDataMessage, EventCodecError> {
    event.validate()?;
    if event.source.sequence_domain != SequenceDomain::MarketData || event.is_snapshot() {
        return Err(EventCodecError::UnexpectedKind(event.kind));
    }
    let payload = match event.kind {
        EventKind::BookAdd => MarketDataPayload::Book(BookDelta::Add {
            order_id: MarketByOrderId(event.order_id.0),
            side: event
                .side
                .as_side()
                .ok_or(EventCodecError::UnexpectedKind(event.kind))?,
            price: event.price,
            quantity: event.quantity,
        }),
        EventKind::BookModify => MarketDataPayload::Book(BookDelta::Modify {
            order_id: MarketByOrderId(event.order_id.0),
            price: event.price,
            quantity: event.quantity,
        }),
        EventKind::BookCancel => MarketDataPayload::Book(BookDelta::Cancel {
            order_id: MarketByOrderId(event.order_id.0),
        }),
        EventKind::BookExecute => MarketDataPayload::Book(BookDelta::Execute {
            order_id: MarketByOrderId(event.order_id.0),
            price: event.price,
            quantity: event.quantity,
        }),
        EventKind::BookClear => MarketDataPayload::Book(BookDelta::Clear),
        EventKind::Trade => MarketDataPayload::Trade {
            trade_id: TradeId(event.reference),
            side: event
                .side
                .as_side()
                .ok_or(EventCodecError::UnexpectedKind(event.kind))?,
            price: event.price,
            quantity: event.quantity,
        },
        EventKind::TradingStatus => MarketDataPayload::TradingStatus {
            status_code: u16::try_from(event.auxiliary).map_err(|_| {
                EventCodecError::IntegerOutOfRange {
                    kind: event.kind,
                    value: event.auxiliary,
                }
            })?,
        },
        _ => return Err(EventCodecError::UnexpectedKind(event.kind)),
    };
    Ok(MarketDataMessage {
        instrument: event.header.instrument,
        sequence: event.header.sequence,
        exchange_timestamp: event.header.exchange_timestamp,
        hardware_receive_timestamp: event.header.hardware_receive_timestamp,
        payload,
    })
}

/// Decode a journaled order-entry input.
///
/// # Errors
///
/// Returns an error if `event` is not an order-entry session or lifecycle event.
pub fn decode_order_entry(event: NormalizedEvent) -> Result<InboundMessage, EventCodecError> {
    event.validate()?;
    if event.source.sequence_domain != SequenceDomain::OrderEntry {
        return Err(EventCodecError::UnexpectedKind(event.kind));
    }
    decode_execution_report(event)
}

/// Decode a journaled independent drop-copy input.
///
/// # Errors
///
/// Returns an error if `event` is not a drop-copy session or lifecycle event.
pub fn decode_drop_copy(event: NormalizedEvent) -> Result<InboundMessage, EventCodecError> {
    event.validate()?;
    if event.source.sequence_domain != SequenceDomain::DropCopy {
        return Err(EventCodecError::UnexpectedKind(event.kind));
    }
    decode_execution_report(event)
}

fn decode_execution_report(event: NormalizedEvent) -> Result<InboundMessage, EventCodecError> {
    let payload = match event.kind {
        EventKind::OrderAccepted => InboundPayload::Order(OrderEvent::Accepted(Accepted {
            client_order_id: ClientOrderId(event.order_id.0),
            venue_order_id: VenueOrderId(event.secondary_id),
            price: event.price,
            quantity: event.quantity,
        })),
        EventKind::OrderRejected => InboundPayload::Order(OrderEvent::Rejected(Rejected {
            client_order_id: ClientOrderId(event.order_id.0),
            code: RejectCode(u32_from_auxiliary(event)?),
        })),
        EventKind::OrderCancelled => InboundPayload::Order(OrderEvent::Canceled(Canceled {
            client_order_id: ClientOrderId(event.order_id.0),
            venue_order_id: VenueOrderId(event.secondary_id),
            canceled_quantity: event.quantity,
            leaves_quantity: event.leaves_quantity,
        })),
        EventKind::OrderFill => InboundPayload::Order(OrderEvent::Fill(Fill {
            client_order_id: ClientOrderId(event.order_id.0),
            venue_order_id: VenueOrderId(event.secondary_id),
            trade_id: TradeId(event.tertiary_id),
            price: event.price,
            quantity: event.quantity,
            leaves_quantity: event.leaves_quantity,
            liquidity: decode_liquidity(event)?,
        })),
        EventKind::LifecycleCorrectionObserved => {
            let kind = LifecycleCorrectionKind::from_wire(event.auxiliary).ok_or(
                EventCodecError::InvalidCode {
                    kind: event.kind,
                    code: event.auxiliary,
                },
            )?;
            InboundPayload::Order(OrderEvent::LifecycleCorrectionObserved(
                LifecycleCorrectionObserved {
                    correction_id: LifecycleCorrectionId(event.reference),
                    target_trade_id: TradeId(event.tertiary_id),
                    kind,
                    canonical_payload_digest: LifecycleCorrectionDigest(event.blob),
                },
            ))
        }
        EventKind::SessionLogonAccepted => InboundPayload::Session(SessionEvent::LogonAccepted),
        EventKind::SessionLogonRejected => InboundPayload::Session(SessionEvent::LogonRejected {
            code: RejectCode(u32_from_auxiliary(event)?),
        }),
        EventKind::Heartbeat => InboundPayload::Session(SessionEvent::Heartbeat),
        EventKind::SessionReplayComplete => InboundPayload::Session(SessionEvent::ReplayComplete {
            through: Sequence(event.reference),
        }),
        EventKind::SessionSnapshotRequired => {
            InboundPayload::Session(SessionEvent::SnapshotRequired)
        }
        EventKind::SessionLogout => InboundPayload::Session(SessionEvent::Logout {
            code: RejectCode(u32_from_auxiliary(event)?),
        }),
        _ => return Err(EventCodecError::UnexpectedKind(event.kind)),
    };
    Ok(InboundMessage {
        sequence: event.header.sequence,
        exchange_timestamp: event.header.exchange_timestamp,
        hardware_receive_timestamp: event.header.hardware_receive_timestamp,
        payload,
    })
}

fn decode_execution_replay_input(event: NormalizedEvent) -> Result<ReplayInput, EventCodecError> {
    match event.source.sequence_domain {
        SequenceDomain::OrderEntry => Ok(ReplayInput::Reactor(ReactorInput::OrderEntry(
            OrderEntryInput {
                message: decode_order_entry(event)?,
                monotonic_now: event.monotonic_timestamp,
            },
        ))),
        SequenceDomain::DropCopy => Ok(ReplayInput::Reactor(ReactorInput::DropCopy(
            DropCopyInput {
                message: decode_drop_copy(event)?,
                monotonic_now: event.monotonic_timestamp,
            },
        ))),
        SequenceDomain::Local | SequenceDomain::MarketData => {
            Err(EventCodecError::UnexpectedKind(event.kind))
        }
    }
}

/// Decode a snapshot begin/order/end event.
///
/// # Errors
///
/// Returns an error if the event is not flagged as a canonical snapshot item.
pub fn decode_snapshot(event: NormalizedEvent) -> Result<SnapshotMessage, EventCodecError> {
    event.validate()?;
    if !event.is_snapshot() || event.source.sequence_domain != SequenceDomain::MarketData {
        return Err(EventCodecError::UnexpectedKind(event.kind));
    }
    let payload = match event.kind {
        EventKind::SnapshotStart => SnapshotPayload::Begin {
            snapshot_id: event.reference,
            last_incremental_sequence: event.header.sequence,
        },
        EventKind::BookAdd => SnapshotPayload::Order(SnapshotOrder {
            instrument: event.header.instrument,
            order_id: MarketByOrderId(event.order_id.0),
            side: event
                .side
                .as_side()
                .ok_or(EventCodecError::UnexpectedKind(event.kind))?,
            price: event.price,
            quantity: event.quantity,
        }),
        EventKind::SnapshotEnd => SnapshotPayload::End {
            snapshot_id: event.reference,
            last_incremental_sequence: event.header.sequence,
        },
        _ => return Err(EventCodecError::UnexpectedKind(event.kind)),
    };
    Ok(SnapshotMessage {
        exchange_timestamp: event.header.exchange_timestamp,
        hardware_receive_timestamp: event.header.hardware_receive_timestamp,
        payload,
    })
}

/// Decode a clock sample.
///
/// # Errors
///
/// Returns an error if the event is not a canonical clock sample.
pub fn decode_clock(event: NormalizedEvent) -> Result<ClockSample, EventCodecError> {
    event.validate()?;
    if event.kind != EventKind::ClockSample {
        return Err(EventCodecError::UnexpectedKind(event.kind));
    }
    Ok(ClockSample {
        utc: TimestampNs(event.reference),
        monotonic: event.monotonic_timestamp,
        uncertainty_ns: event.auxiliary,
    })
}

/// Decode the full accepted control decision retained for audit/replay.
///
/// # Errors
///
/// Returns an error for an invalid action, reason, or first-fault code.
pub fn decode_control_decision(event: NormalizedEvent) -> Result<ControlDecision, EventCodecError> {
    event.validate()?;
    let (action, first_fault) = match event.kind {
        EventKind::ControlArm => (
            EngineControlAction::Arm {
                config_epoch: event.auxiliary,
                config_digest: ConfigDigest(event.blob),
                lease_deadline: TimestampNs(event.tertiary_id),
            },
            None,
        ),
        EventKind::ControlDisarm => (EngineControlAction::Disarm, None),
        EventKind::ControlHeartbeat => (
            EngineControlAction::Heartbeat {
                lease_deadline: TimestampNs(event.tertiary_id),
            },
            None,
        ),
        EventKind::ControlKill => {
            let reason = decode_kill_reason(event.auxiliary & 0xff, event.kind)?;
            let first_fault = match (event.auxiliary >> 8) & 0xff {
                1 => false,
                2 => true,
                code => {
                    return Err(EventCodecError::InvalidCode {
                        kind: event.kind,
                        code,
                    });
                }
            };
            (
                EngineControlAction::Kill(ControlKillRequest {
                    reason,
                    requested_at: TimestampNs(event.tertiary_id),
                }),
                Some(first_fault),
            )
        }
        _ => return Err(EventCodecError::UnexpectedKind(event.kind)),
    };
    let accepted_sequence = Sequence(event.order_id.0);
    let next_sequence = Sequence(event.secondary_id);
    let accepted_at = TimestampNs(event.reference);
    match event.control_origin() {
        ControlEventOrigin::AuthenticatedGate => Ok(ControlDecision::from_authenticated_event(
            action,
            accepted_sequence,
            next_sequence,
            accepted_at,
            first_fault,
        )),
        ControlEventOrigin::JournalReplay => Ok(ControlDecision::from_journal_replay(
            action,
            accepted_sequence,
            next_sequence,
            accepted_at,
            first_fault,
        )),
        ControlEventOrigin::Untrusted => Err(EventCodecError::InvalidControlDecision),
    }
}

/// Decode priority-lane transmission feedback.
///
/// # Errors
///
/// Returns an error for an invalid status, command code, or instrument width.
pub fn decode_transmission(event: NormalizedEvent) -> Result<TransmissionInput, EventCodecError> {
    event.validate()?;
    let status = decode_transmission_status(event.auxiliary & 0xff, event.kind)?;
    let command = match event.kind {
        EventKind::TransmissionNew => OrderCommand::New(NewOrder {
            client_order_id: ClientOrderId(event.order_id.0),
            instrument: InstrumentId(u32_from_value(event.secondary_id, event.kind)?),
            side: event
                .side
                .as_side()
                .ok_or(EventCodecError::UnexpectedKind(event.kind))?,
            price: event.price,
            quantity: event.quantity,
            time_in_force: decode_time_in_force((event.auxiliary >> 8) & 0xff, event.kind)?,
            created_at: TimestampNs(event.reference),
        }),
        EventKind::TransmissionCancel => OrderCommand::Cancel(CancelOrder {
            client_order_id: ClientOrderId(event.order_id.0),
            venue_order_id: VenueOrderId(event.secondary_id),
            created_at: TimestampNs(event.reference),
        }),
        EventKind::TransmissionReplace => OrderCommand::Replace(ReplaceOrder {
            current_client_order_id: ClientOrderId(event.order_id.0),
            replacement_client_order_id: ClientOrderId(event.secondary_id),
            venue_order_id: VenueOrderId(event.tertiary_id),
            new_price: event.price,
            new_quantity: event.quantity,
            created_at: TimestampNs(event.reference),
        }),
        EventKind::TransmissionCancelAll => {
            let scope = match (event.auxiliary >> 8) & 0xff {
                1 => CancelScope::Session,
                2 => CancelScope::Instrument(InstrumentId(u32_from_value(
                    event.order_id.0,
                    event.kind,
                )?)),
                code => {
                    return Err(EventCodecError::InvalidCode {
                        kind: event.kind,
                        code,
                    });
                }
            };
            OrderCommand::CancelAll(CancelAll {
                scope,
                created_at: TimestampNs(event.reference),
            })
        }
        _ => return Err(EventCodecError::UnexpectedKind(event.kind)),
    };
    command
        .validate()
        .map_err(|_| EventCodecError::InvalidOrderCommand)?;
    Ok(TransmissionInput {
        command,
        status,
        monotonic_now: event.monotonic_timestamp,
    })
}

/// Decode a scheduler notification.
///
/// # Errors
///
/// Returns an error if the action code is unknown.
pub fn decode_timer(event: NormalizedEvent) -> Result<TimerInput, EventCodecError> {
    event.validate()?;
    if event.kind != EventKind::Timer {
        return Err(EventCodecError::UnexpectedKind(event.kind));
    }
    let action = match event.auxiliary {
        1 => TimerAction::KillCancelSweep,
        2 => TimerAction::ControlLivenessCheck,
        3 => TimerAction::DropCopyLivenessCheck,
        code => {
            return Err(EventCodecError::InvalidCode {
                kind: event.kind,
                code,
            });
        }
    };
    Ok(TimerInput {
        timer_id: TimerId(event.order_id.0),
        action,
        scheduled_at: MonotonicTimestampNs(event.secondary_id),
        fired_at: event.monotonic_timestamp,
    })
}

/// Decode an adapter-authenticated owned-order/MBO correlation.
///
/// # Errors
///
/// Returns an error for an unknown method or out-of-range rule/venue code.
pub fn decode_owned_mbo_binding(
    event: NormalizedEvent,
) -> Result<OwnedMboBindingInput, EventCodecError> {
    event.validate()?;
    if event.kind != EventKind::OwnedMboBinding {
        return Err(EventCodecError::UnexpectedKind(event.kind));
    }
    let method = match event.auxiliary & 0xff {
        1 => OwnedMboBindingMethod::ExplicitNativeIdentifier,
        2 => OwnedMboBindingMethod::CertifiedDeterministicRule {
            rule_id: u32_from_value((event.auxiliary >> 8) & u64::from(u32::MAX), event.kind)?,
        },
        code => {
            return Err(EventCodecError::InvalidCode {
                kind: event.kind,
                code,
            });
        }
    };
    let venue_bits = (event.auxiliary >> 40) & u64::from(u16::MAX);
    let venue = u16::try_from(venue_bits).map_err(|_| EventCodecError::IntegerOutOfRange {
        kind: event.kind,
        value: venue_bits,
    })?;
    Ok(OwnedMboBindingInput {
        binding: OwnedMboBinding {
            venue: VenueId(venue),
            client_order_id: ClientOrderId(event.order_id.0),
            venue_order_id: VenueOrderId(event.secondary_id),
            market_by_order_id: MarketByOrderId(event.tertiary_id),
            order_entry_sequence: Sequence(event.reference),
            method,
        },
        monotonic_now: event.monotonic_timestamp,
    })
}

fn checked(event: NormalizedEvent) -> Result<NormalizedEvent, EventCodecError> {
    event.validate()?;
    Ok(event)
}

#[derive(Clone, Copy, Debug)]
struct MarketFields {
    kind: EventKind,
    side: EventSide,
    order_id: OrderId,
    price: PriceTicks,
    quantity: Quantity,
    reference: u64,
    auxiliary: u64,
}

fn market_fields(payload: MarketDataPayload) -> MarketFields {
    match payload {
        MarketDataPayload::Book(delta) => book_fields(delta),
        MarketDataPayload::Trade {
            trade_id,
            side,
            price,
            quantity,
        } => MarketFields {
            kind: EventKind::Trade,
            side: side.into(),
            order_id: OrderId(0),
            price,
            quantity,
            reference: trade_id.0,
            auxiliary: 0,
        },
        MarketDataPayload::TradingStatus { status_code } => MarketFields {
            kind: EventKind::TradingStatus,
            side: EventSide::None,
            order_id: OrderId(0),
            price: PriceTicks::ZERO,
            quantity: Quantity::ZERO,
            reference: 0,
            auxiliary: u64::from(status_code),
        },
    }
}

fn book_fields(delta: BookDelta) -> MarketFields {
    match delta {
        BookDelta::Add {
            order_id,
            side,
            price,
            quantity,
        } => MarketFields {
            kind: EventKind::BookAdd,
            side: side.into(),
            order_id: OrderId(order_id.0),
            price,
            quantity,
            reference: 0,
            auxiliary: 0,
        },
        BookDelta::Modify {
            order_id,
            price,
            quantity,
        } => MarketFields {
            kind: EventKind::BookModify,
            side: EventSide::None,
            order_id: OrderId(order_id.0),
            price,
            quantity,
            reference: 0,
            auxiliary: 0,
        },
        BookDelta::Cancel { order_id } => {
            empty_market_fields(EventKind::BookCancel, OrderId(order_id.0))
        }
        BookDelta::Execute {
            order_id,
            price,
            quantity,
        } => MarketFields {
            kind: EventKind::BookExecute,
            side: EventSide::None,
            order_id: OrderId(order_id.0),
            price,
            quantity,
            reference: 0,
            auxiliary: 0,
        },
        BookDelta::Clear => empty_market_fields(EventKind::BookClear, OrderId(0)),
    }
}

const fn empty_market_fields(kind: EventKind, order_id: OrderId) -> MarketFields {
    MarketFields {
        kind,
        side: EventSide::None,
        order_id,
        price: PriceTicks::ZERO,
        quantity: Quantity::ZERO,
        reference: 0,
        auxiliary: 0,
    }
}

#[derive(Clone, Copy, Debug)]
struct OrderFields {
    kind: EventKind,
    order_id: OrderId,
    secondary_id: u64,
    tertiary_id: u64,
    price: PriceTicks,
    quantity: Quantity,
    leaves: Quantity,
    reference: u64,
    auxiliary: u64,
    blob: [u8; 32],
}

fn order_entry_fields(payload: InboundPayload) -> OrderFields {
    match payload {
        InboundPayload::Order(event) => order_fields(event),
        InboundPayload::Session(event) => session_fields(event),
    }
}

fn order_fields(event: OrderEvent) -> OrderFields {
    match event {
        OrderEvent::Accepted(value) => OrderFields {
            kind: EventKind::OrderAccepted,
            order_id: OrderId(value.client_order_id.0),
            secondary_id: value.venue_order_id.0,
            price: value.price,
            quantity: value.quantity,
            ..empty_order_fields(EventKind::OrderAccepted)
        },
        OrderEvent::Rejected(value) => OrderFields {
            order_id: OrderId(value.client_order_id.0),
            auxiliary: u64::from(value.code.0),
            ..empty_order_fields(EventKind::OrderRejected)
        },
        OrderEvent::Canceled(value) => OrderFields {
            order_id: OrderId(value.client_order_id.0),
            secondary_id: value.venue_order_id.0,
            quantity: value.canceled_quantity,
            leaves: value.leaves_quantity,
            ..empty_order_fields(EventKind::OrderCancelled)
        },
        OrderEvent::Fill(value) => OrderFields {
            order_id: OrderId(value.client_order_id.0),
            secondary_id: value.venue_order_id.0,
            tertiary_id: value.trade_id.0,
            price: value.price,
            quantity: value.quantity,
            leaves: value.leaves_quantity,
            auxiliary: liquidity_code(value.liquidity),
            ..empty_order_fields(EventKind::OrderFill)
        },
        OrderEvent::LifecycleCorrectionObserved(value) => OrderFields {
            tertiary_id: value.target_trade_id.0,
            reference: value.correction_id.0,
            auxiliary: value.kind as u64,
            blob: value.canonical_payload_digest.0,
            ..empty_order_fields(EventKind::LifecycleCorrectionObserved)
        },
    }
}

fn session_fields(event: SessionEvent) -> OrderFields {
    match event {
        SessionEvent::LogonAccepted => empty_order_fields(EventKind::SessionLogonAccepted),
        SessionEvent::LogonRejected { code } => OrderFields {
            auxiliary: u64::from(code.0),
            ..empty_order_fields(EventKind::SessionLogonRejected)
        },
        SessionEvent::Heartbeat => empty_order_fields(EventKind::Heartbeat),
        SessionEvent::ReplayComplete { through } => OrderFields {
            reference: through.0,
            ..empty_order_fields(EventKind::SessionReplayComplete)
        },
        SessionEvent::SnapshotRequired => empty_order_fields(EventKind::SessionSnapshotRequired),
        SessionEvent::Logout { code } => OrderFields {
            auxiliary: u64::from(code.0),
            ..empty_order_fields(EventKind::SessionLogout)
        },
    }
}

const fn empty_order_fields(kind: EventKind) -> OrderFields {
    OrderFields {
        kind,
        order_id: OrderId(0),
        secondary_id: 0,
        tertiary_id: 0,
        price: PriceTicks::ZERO,
        quantity: Quantity::ZERO,
        leaves: Quantity::ZERO,
        reference: 0,
        auxiliary: 0,
        blob: [0; 32],
    }
}

const fn recovery_flag(recovery: bool) -> u16 {
    if recovery { EVENT_FLAG_RECOVERY } else { 0 }
}

const fn venue_header(
    metadata: VenueCaptureMetadata,
    instrument: InstrumentId,
    sequence: Sequence,
    exchange_timestamp: TimestampNs,
    hardware_receive_timestamp: TimestampNs,
) -> EventHeader {
    EventHeader {
        venue: metadata.venue,
        instrument,
        sequence,
        exchange_timestamp,
        hardware_receive_timestamp,
    }
}

#[allow(clippy::too_many_arguments)]
const fn local_event(
    capture_ordinal: CaptureOrdinal,
    monotonic_timestamp: MonotonicTimestampNs,
    kind: EventKind,
    side: EventSide,
    order_id: OrderId,
    secondary_id: u64,
    tertiary_id: u64,
    price: PriceTicks,
    quantity: Quantity,
    leaves_quantity: Quantity,
    reference: u64,
    auxiliary: u64,
    blob: [u8; 32],
) -> NormalizedEvent {
    NormalizedEvent::new_full(
        EventHeader {
            venue: VenueId(0),
            instrument: InstrumentId(0),
            sequence: Sequence(0),
            exchange_timestamp: TimestampNs::ZERO,
            hardware_receive_timestamp: TimestampNs::ZERO,
        },
        EventSource::LOCAL,
        capture_ordinal,
        monotonic_timestamp,
        kind,
        side,
        0,
        order_id,
        secondary_id,
        tertiary_id,
        price,
        quantity,
        leaves_quantity,
        reference,
        auxiliary,
        blob,
    )
}

fn ensure_snapshot_context(
    metadata: SnapshotCaptureMetadata,
    snapshot_id: u64,
    last_incremental_sequence: Sequence,
) -> Result<(), EventCodecError> {
    if snapshot_id == metadata.snapshot_id
        && last_incremental_sequence == metadata.last_incremental_sequence
    {
        Ok(())
    } else {
        Err(EventCodecError::InvalidSnapshotContext)
    }
}

const fn liquidity_code(value: LiquidityFlag) -> u64 {
    match value {
        LiquidityFlag::Added => 1,
        LiquidityFlag::Removed => 2,
        LiquidityFlag::Unknown => 3,
    }
}

fn decode_liquidity(event: NormalizedEvent) -> Result<LiquidityFlag, EventCodecError> {
    match event.auxiliary {
        1 => Ok(LiquidityFlag::Added),
        2 => Ok(LiquidityFlag::Removed),
        3 => Ok(LiquidityFlag::Unknown),
        code => Err(EventCodecError::InvalidCode {
            kind: event.kind,
            code,
        }),
    }
}

const fn transmission_status_code(value: TransmissionStatus) -> u64 {
    match value {
        TransmissionStatus::Sent => 1,
        TransmissionStatus::ProvenUnsent => 2,
    }
}

fn decode_transmission_status(
    code: u64,
    kind: EventKind,
) -> Result<TransmissionStatus, EventCodecError> {
    match code {
        1 => Ok(TransmissionStatus::Sent),
        2 => Ok(TransmissionStatus::ProvenUnsent),
        _ => Err(EventCodecError::InvalidCode { kind, code }),
    }
}

const fn time_in_force_code(value: TimeInForce) -> u64 {
    match value {
        TimeInForce::Day => 1,
        TimeInForce::ImmediateOrCancel => 2,
        TimeInForce::FillOrKill => 3,
        TimeInForce::GoodTillCancel => 4,
        TimeInForce::PostOnly => 5,
    }
}

fn decode_time_in_force(code: u64, kind: EventKind) -> Result<TimeInForce, EventCodecError> {
    match code {
        1 => Ok(TimeInForce::Day),
        2 => Ok(TimeInForce::ImmediateOrCancel),
        3 => Ok(TimeInForce::FillOrKill),
        4 => Ok(TimeInForce::GoodTillCancel),
        5 => Ok(TimeInForce::PostOnly),
        _ => Err(EventCodecError::InvalidCode { kind, code }),
    }
}

const fn kill_reason_code(value: ControlKillReason) -> u64 {
    match value {
        ControlKillReason::AuthenticationFailure => 1,
        ControlKillReason::ProtocolViolation => 2,
        ControlKillReason::SequenceViolation => 3,
        ControlKillReason::TimeViolation => 4,
        ControlKillReason::ConfigurationViolation => 5,
        ControlKillReason::InvalidState => 6,
        ControlKillReason::LivenessExpired => 7,
        ControlKillReason::Manual => 8,
    }
}

fn decode_kill_reason(code: u64, kind: EventKind) -> Result<ControlKillReason, EventCodecError> {
    match code {
        1 => Ok(ControlKillReason::AuthenticationFailure),
        2 => Ok(ControlKillReason::ProtocolViolation),
        3 => Ok(ControlKillReason::SequenceViolation),
        4 => Ok(ControlKillReason::TimeViolation),
        5 => Ok(ControlKillReason::ConfigurationViolation),
        6 => Ok(ControlKillReason::InvalidState),
        7 => Ok(ControlKillReason::LivenessExpired),
        8 => Ok(ControlKillReason::Manual),
        _ => Err(EventCodecError::InvalidCode { kind, code }),
    }
}

fn u32_from_auxiliary(event: NormalizedEvent) -> Result<u32, EventCodecError> {
    u32_from_value(event.auxiliary, event.kind)
}

fn u32_from_value(value: u64, kind: EventKind) -> Result<u32, EventCodecError> {
    u32::try_from(value).map_err(|_| EventCodecError::IntegerOutOfRange { kind, value })
}
