mod support;

use quant_hft_core::adverse::AdverseConfig;
use quant_hft_core::clock::ClockSample;
use quant_hft_core::control::ConfigDigest;
use quant_hft_core::engine::{EngineConfig, ExecutionEngine, TransmissionStatus};
use quant_hft_core::native_replay::{
    NativeIngressCapture, NativeIngressLane, NativeOwnedMboIngressCapture,
    NativeOwnedMboReplayResult, NativePacketMetadata, NativeReplayError, NativeReplayVerifier,
};
use quant_hft_core::reactor::{HotPathReactor, OwnedMboBindingInput};
use quant_hft_core::reactor_replay::dispatch_reactor_replay_event;
use quant_hft_core::risk::{
    CurrencyId, InstrumentRiskDefinition, InstrumentValuation, RiskLimits, RiskSessionId,
};
use quant_hft_core::strategy::QuotePolicyConfig;
use quant_hft_core::types::{
    InstrumentId, MonotonicTimestampNs, OrderId, PriceTicks, Quantity, Sequence, Side, TimestampNs,
    VenueId,
};
use quant_hft_core::venue::{
    Accepted, BookDelta, ClientOrderId, CorrelationResult, DecodeResult, DirectMarketDataDecoder,
    InboundMessage, InboundPayload, MarketByOrderId, MarketDataFeed, MarketDataMessage,
    MarketDataPayload, NativeOrderEntryDecoder, NativeOrderEntryEncoder, NativeOwnedMboCorrelator,
    NewOrder, OrderCommand, OrderEvent, OwnedMboBinding, OwnedMboBindingMethod, ProtocolId,
    SessionCommand, SessionEvent, SessionId, SnapshotMessage, SnapshotPayload, TradeId,
    TransactionalCodec, VenueCapabilities, VenueDescriptor, VenueIdentity, VenueOrderId,
    VenueSession, WireError,
};
use quant_hft_core::{
    CaptureOrdinal, EventSource, SequenceDomain, SessionEpoch, SourceId, VenueCaptureMetadata,
    normalize_market_data, normalize_order_entry, normalize_owned_mbo_binding,
};

const IDENTITY: VenueIdentity = VenueIdentity {
    venue: VenueId(7),
    market_data_protocol: ProtocolId(701),
    order_entry_protocol: ProtocolId(702),
    session: SessionId(703),
};

const CAPABILITIES: VenueCapabilities = VenueCapabilities::MARKET_DATA_L3
    .union(VenueCapabilities::NEW_ORDER)
    .union(VenueCapabilities::SNAPSHOT_RECOVERY)
    .union(VenueCapabilities::OWNED_MBO_CORRELATION);

const MARKET_PACKET: [u8; 1] = [0xA0];
const SNAPSHOT_BEGIN_PACKET: [u8; 1] = [0xB0];
const SNAPSHOT_END_PACKET: [u8; 1] = [0xB1];
const LOGON_PACKET: [u8; 1] = [0xC0];
const ACCEPTED_PACKET: [u8; 1] = [0xC1];
const INSTRUMENT: InstrumentId = InstrumentId(9);
const ENGINE_OFFSET: u64 = 1_000_000_000;

type TestEngine = ExecutionEngine<64, 16, 8, 16, 16>;
type TestReactor = HotPathReactor<64, 16, 8, 16, 16>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CorrelationMode {
    MarketTwo,
    OrderExplicit,
    ExcessiveCount,
    DirtyTail,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FixedExactAdapter {
    mode: CorrelationMode,
    codec_state: u64,
    market_correlation_calls: u8,
    order_correlation_calls: u8,
}

impl FixedExactAdapter {
    const fn new(mode: CorrelationMode) -> Self {
        Self {
            mode,
            codec_state: 0,
            market_correlation_calls: 0,
            order_correlation_calls: 0,
        }
    }

    fn mutate(&mut self) {
        self.codec_state = self.codec_state.wrapping_add(1);
    }
}

impl VenueDescriptor for FixedExactAdapter {
    const IDENTITY: VenueIdentity = IDENTITY;
    const CAPABILITIES: VenueCapabilities = CAPABILITIES;
}

impl TransactionalCodec for FixedExactAdapter {
    type Checkpoint = Self;

    fn checkpoint(&self) -> Self::Checkpoint {
        *self
    }

    fn restore(&mut self, checkpoint: Self::Checkpoint) {
        *self = checkpoint;
    }
}

impl DirectMarketDataDecoder for FixedExactAdapter {
    fn decode_market_data(
        &mut self,
        packet: &[u8],
        hardware_receive_timestamp: TimestampNs,
        output: &mut [Option<MarketDataMessage>],
    ) -> Result<DecodeResult, WireError> {
        self.mutate();
        if packet != MARKET_PACKET {
            return Err(WireError::MalformedPacket);
        }
        require_slots(output.len(), 2)?;
        let messages = market_messages(hardware_receive_timestamp);
        output[0] = Some(messages[0]);
        output[1] = Some(messages[1]);
        Ok(DecodeResult {
            messages: 2,
            consumed_bytes: MARKET_PACKET.len(),
        })
    }

    fn decode_snapshot(
        &mut self,
        packet: &[u8],
        hardware_receive_timestamp: TimestampNs,
        output: &mut [Option<SnapshotMessage>],
    ) -> Result<DecodeResult, WireError> {
        self.mutate();
        require_slots(output.len(), 1)?;
        let payload = if packet == SNAPSHOT_BEGIN_PACKET {
            SnapshotPayload::Begin {
                snapshot_id: 11,
                last_incremental_sequence: Sequence(99),
            }
        } else if packet == SNAPSHOT_END_PACKET {
            SnapshotPayload::End {
                snapshot_id: 11,
                last_incremental_sequence: Sequence(99),
            }
        } else {
            return Err(WireError::MalformedPacket);
        };
        output[0] = Some(SnapshotMessage {
            exchange_timestamp: TimestampNs(hardware_receive_timestamp.0 - 1),
            hardware_receive_timestamp,
            payload,
        });
        Ok(DecodeResult {
            messages: 1,
            consumed_bytes: 1,
        })
    }
}

impl NativeOrderEntryDecoder for FixedExactAdapter {
    fn decode_order_entry(
        &mut self,
        packet: &[u8],
        hardware_receive_timestamp: TimestampNs,
        output: &mut [Option<InboundMessage>],
    ) -> Result<DecodeResult, WireError> {
        self.mutate();
        require_slots(output.len(), 1)?;
        let (sequence, payload) = if packet == LOGON_PACKET {
            (
                Sequence(1),
                InboundPayload::Session(SessionEvent::LogonAccepted),
            )
        } else if packet == ACCEPTED_PACKET {
            (
                Sequence(2),
                InboundPayload::Order(OrderEvent::Accepted(Accepted {
                    client_order_id: ClientOrderId(1_000),
                    venue_order_id: VenueOrderId(7_000),
                    price: PriceTicks(99),
                    quantity: Quantity(10),
                })),
            )
        } else {
            return Err(WireError::MalformedPacket);
        };
        output[0] = Some(InboundMessage {
            sequence,
            exchange_timestamp: TimestampNs(hardware_receive_timestamp.0 - 1),
            hardware_receive_timestamp,
            payload,
        });
        Ok(DecodeResult {
            messages: 1,
            consumed_bytes: 1,
        })
    }
}

impl NativeOrderEntryEncoder for FixedExactAdapter {
    fn encode_session(
        &mut self,
        _sequence: Sequence,
        _command: SessionCommand,
        _output: &mut [u8],
    ) -> Result<usize, WireError> {
        Err(WireError::UnsupportedMessage { message_type: 0 })
    }

    fn encode_order(
        &mut self,
        _sequence: Sequence,
        _command: OrderCommand,
        _instrument: quant_hft_core::InstrumentDefinition,
        _output: &mut [u8],
    ) -> Result<usize, WireError> {
        Err(WireError::UnsupportedMessage { message_type: 0 })
    }
}

impl NativeOwnedMboCorrelator for FixedExactAdapter {
    fn correlate_order_entry(
        &mut self,
        message: InboundMessage,
        output: &mut [Option<OwnedMboBinding>],
    ) -> Result<CorrelationResult, WireError> {
        self.mutate();
        self.order_correlation_calls = self.order_correlation_calls.wrapping_add(1);
        if self.mode == CorrelationMode::OrderExplicit
            && matches!(
                message.payload,
                InboundPayload::Order(OrderEvent::Accepted(_))
            )
        {
            require_slots(output.len(), 1)?;
            output[0] = Some(order_binding());
            return Ok(CorrelationResult { bindings: 1 });
        }
        Ok(CorrelationResult { bindings: 0 })
    }

    fn correlate_market_data(
        &mut self,
        _message: MarketDataMessage,
        output: &mut [Option<OwnedMboBinding>],
    ) -> Result<CorrelationResult, WireError> {
        self.mutate();
        let call = self.market_correlation_calls;
        self.market_correlation_calls = self.market_correlation_calls.wrapping_add(1);
        if call != 0 {
            return Ok(CorrelationResult { bindings: 0 });
        }
        match self.mode {
            CorrelationMode::MarketTwo => {
                require_slots(output.len(), 2)?;
                let expected = market_bindings();
                output[0] = Some(expected[0]);
                output[1] = Some(expected[1]);
                Ok(CorrelationResult { bindings: 2 })
            }
            CorrelationMode::ExcessiveCount => Ok(CorrelationResult {
                bindings: output.len().saturating_add(1),
            }),
            CorrelationMode::DirtyTail => {
                require_slots(output.len(), 2)?;
                let expected = market_bindings();
                output[0] = Some(expected[0]);
                output[1] = Some(expected[1]);
                Ok(CorrelationResult { bindings: 1 })
            }
            CorrelationMode::OrderExplicit => Ok(CorrelationResult { bindings: 0 }),
        }
    }

    fn correlate_snapshot(
        &mut self,
        _message: SnapshotMessage,
        _output: &mut [Option<OwnedMboBinding>],
    ) -> Result<CorrelationResult, WireError> {
        self.mutate();
        Ok(CorrelationResult { bindings: 0 })
    }
}

#[test]
fn market_frame_binds_two_outputs_to_only_the_first_message() {
    let mut adapter = FixedExactAdapter::new(CorrelationMode::MarketTwo);
    let mut feed = live_feed(&mut adapter);
    let metadata = market_metadata(1);
    let venue_events = normalized_market_events(metadata, [1, 4]);
    let expected_bindings = normalized_binding_events(&market_bindings(), &[2, 3], 1_010);
    let capture = owned_capture(
        metadata,
        NativeIngressLane::MarketData,
        &MARKET_PACKET,
        &venue_events,
        &expected_bindings,
    );
    let mut decoded = [None; 2];
    let mut bindings = [None; 3];
    let mut verifier = NativeReplayVerifier::new(1).unwrap();

    assert_eq!(
        verifier.verify_market_data_with_owned_mbo(
            &mut feed,
            &mut adapter,
            capture,
            &mut decoded,
            &mut bindings,
        ),
        Ok(NativeOwnedMboReplayResult {
            messages: 2,
            bindings: 2,
        })
    );
    assert_eq!(
        decoded,
        market_messages(metadata.hardware_receive_timestamp).map(Some)
    );
    assert_eq!(
        bindings,
        [Some(market_bindings()[0]), Some(market_bindings()[1]), None]
    );
    assert_eq!(adapter.market_correlation_calls, 2);
    assert_eq!(feed.expected_sequence(), Sequence(102));
    assert_eq!(verifier.last_capture_ordinal(), Some(CaptureOrdinal(4)));
    assert_eq!(verifier.next_frame_ordinal(), 2);
}

#[test]
fn accepted_order_emits_one_explicit_native_binding() {
    let mut adapter = FixedExactAdapter::new(CorrelationMode::OrderExplicit);
    let mut session = live_session(&mut adapter);
    let metadata = order_metadata(1);
    let message = accepted_message(metadata.hardware_receive_timestamp);
    let venue_event =
        normalize_order_entry(venue_metadata(metadata, CaptureOrdinal(1)), message).unwrap();
    let binding_event = normalize_owned_mbo_binding(
        CaptureOrdinal(2),
        OwnedMboBindingInput {
            binding: order_binding(),
            monotonic_now: metadata.monotonic_timestamp,
        },
    )
    .unwrap();
    let venue_events = [venue_event];
    let binding_events = [binding_event];
    let capture = owned_capture(
        metadata,
        NativeIngressLane::OrderEntry,
        &ACCEPTED_PACKET,
        &venue_events,
        &binding_events,
    );
    let mut decoded = [None; 1];
    let mut bindings = [None; 2];
    let mut verifier = NativeReplayVerifier::new(1).unwrap();

    assert_eq!(
        verifier.verify_order_entry_with_owned_mbo(
            &mut session,
            &mut adapter,
            capture,
            &mut decoded,
            &mut bindings,
        ),
        Ok(NativeOwnedMboReplayResult {
            messages: 1,
            bindings: 1,
        })
    );
    assert_eq!(decoded, [Some(message)]);
    assert_eq!(bindings, [Some(order_binding()), None]);
    assert_eq!(session.expected_inbound(), Sequence(3));
    assert_eq!(verifier.last_capture_ordinal(), Some(CaptureOrdinal(2)));
}

#[test]
fn wrong_binding_association_restores_feed_adapter_and_latches_cleanly() {
    let mut adapter = FixedExactAdapter::new(CorrelationMode::MarketTwo);
    let mut feed = live_feed(&mut adapter);
    let feed_before = feed;
    let adapter_before = adapter;
    let metadata = market_metadata(1);
    let venue_events = normalized_market_events(metadata, [1, 2]);
    let expected_bindings = normalized_binding_events(&market_bindings(), &[3, 4], 1_010);
    let capture = owned_capture(
        metadata,
        NativeIngressLane::MarketData,
        &MARKET_PACKET,
        &venue_events,
        &expected_bindings,
    );
    let mut decoded = market_messages(metadata.hardware_receive_timestamp).map(Some);
    let mut bindings = market_bindings().map(Some);
    let mut verifier = NativeReplayVerifier::new(1).unwrap();

    assert_eq!(
        verifier.verify_market_data_with_owned_mbo(
            &mut feed,
            &mut adapter,
            capture,
            &mut decoded,
            &mut bindings,
        ),
        Err(NativeReplayError::CorrelatedCaptureOrdinalMismatch {
            expected: CaptureOrdinal(2),
            received: CaptureOrdinal(3),
        })
    );
    assert_eq!(feed, feed_before);
    assert_eq!(adapter, adapter_before);
    assert!(decoded.iter().all(Option::is_none));
    assert!(bindings.iter().all(Option::is_none));
    assert!(verifier.failed());
    assert_eq!(verifier.next_frame_ordinal(), 1);
    assert_eq!(verifier.last_capture_ordinal(), None);

    decoded = market_messages(metadata.hardware_receive_timestamp).map(Some);
    bindings = market_bindings().map(Some);
    assert_eq!(
        verifier.verify_market_data_with_owned_mbo(
            &mut feed,
            &mut adapter,
            capture,
            &mut decoded,
            &mut bindings,
        ),
        Err(NativeReplayError::Failed)
    );
    assert_eq!(feed, feed_before);
    assert_eq!(adapter, adapter_before);
    assert!(decoded.iter().all(Option::is_none));
    assert!(bindings.iter().all(Option::is_none));
}

#[test]
fn binding_value_mismatch_restores_session_and_adapter() {
    let mut adapter = FixedExactAdapter::new(CorrelationMode::OrderExplicit);
    let mut session = live_session(&mut adapter);
    let session_before = session;
    let adapter_before = adapter;
    let metadata = order_metadata(1);
    let message = accepted_message(metadata.hardware_receive_timestamp);
    let venue_event =
        normalize_order_entry(venue_metadata(metadata, CaptureOrdinal(1)), message).unwrap();
    let mut wrong = order_binding();
    wrong.market_by_order_id = MarketByOrderId(70_001);
    let binding_event = normalize_owned_mbo_binding(
        CaptureOrdinal(2),
        OwnedMboBindingInput {
            binding: wrong,
            monotonic_now: metadata.monotonic_timestamp,
        },
    )
    .unwrap();
    let venue_events = [venue_event];
    let binding_events = [binding_event];
    let capture = owned_capture(
        metadata,
        NativeIngressLane::OrderEntry,
        &ACCEPTED_PACKET,
        &venue_events,
        &binding_events,
    );
    let mut decoded = [Some(message)];
    let mut bindings = [Some(order_binding())];
    let mut verifier = NativeReplayVerifier::new(1).unwrap();

    assert_eq!(
        verifier.verify_order_entry_with_owned_mbo(
            &mut session,
            &mut adapter,
            capture,
            &mut decoded,
            &mut bindings,
        ),
        Err(NativeReplayError::OwnedMboBindingEventMismatch { index: 0 })
    );
    assert_eq!(session, session_before);
    assert_eq!(adapter, adapter_before);
    assert!(decoded.iter().all(Option::is_none));
    assert!(bindings.iter().all(Option::is_none));
    assert_eq!(verifier.next_frame_ordinal(), 1);
    assert_eq!(verifier.last_capture_ordinal(), None);
}

#[test]
fn excessive_count_and_dirty_tail_are_rejected_without_state_commit() {
    {
        let mut adapter = FixedExactAdapter::new(CorrelationMode::ExcessiveCount);
        let mut feed = live_feed(&mut adapter);
        let before = (feed, adapter);
        let metadata = market_metadata(1);
        let venue_events = normalized_market_events(metadata, [1, 2]);
        let capture = owned_capture(
            metadata,
            NativeIngressLane::MarketData,
            &MARKET_PACKET,
            &venue_events,
            &[],
        );
        let mut verifier = NativeReplayVerifier::new(1).unwrap();
        let mut decoded = [None; 2];
        let mut bindings = [None; 1];
        assert_eq!(
            verifier.verify_market_data_with_owned_mbo(
                &mut feed,
                &mut adapter,
                capture,
                &mut decoded,
                &mut bindings,
            ),
            Err(NativeReplayError::OwnedMboCorrelationCountOutOfRange {
                reported: 2,
                available: 1,
            })
        );
        assert_eq!((feed, adapter), before);
        assert!(decoded.iter().all(Option::is_none));
        assert!(bindings.iter().all(Option::is_none));
    }

    {
        let mut adapter = FixedExactAdapter::new(CorrelationMode::DirtyTail);
        let mut feed = live_feed(&mut adapter);
        let before = (feed, adapter);
        let metadata = market_metadata(1);
        let venue_events = normalized_market_events(metadata, [1, 3]);
        let expected = normalized_binding_events(&market_bindings()[..1], &[2], 1_010);
        let capture = owned_capture(
            metadata,
            NativeIngressLane::MarketData,
            &MARKET_PACKET,
            &venue_events,
            &expected,
        );
        let mut verifier = NativeReplayVerifier::new(1).unwrap();
        let mut decoded = [None; 2];
        let mut bindings = [None; 2];
        assert_eq!(
            verifier.verify_market_data_with_owned_mbo(
                &mut feed,
                &mut adapter,
                capture,
                &mut decoded,
                &mut bindings,
            ),
            Err(NativeReplayError::DirtyOwnedMboBindingTail { index: 1 })
        );
        assert_eq!((feed, adapter), before);
        assert!(decoded.iter().all(Option::is_none));
        assert!(bindings.iter().all(Option::is_none));
    }
}

#[test]
fn actual_reactor_adds_ownership_only_for_explicit_binding_event() {
    let (engine, bid) = engine_with_accepted_quotes();
    let public_id = MarketByOrderId(7_000);
    assert_eq!(
        engine
            .owned_mbo_registry()
            .by_venue_order(VenueOrderId(public_id.0)),
        None
    );
    assert_eq!(engine.owned_mbo_registry().by_market_order(public_id), None);

    let binding = OwnedMboBinding {
        venue: IDENTITY.venue,
        client_order_id: bid.client_order_id,
        venue_order_id: VenueOrderId(public_id.0),
        market_by_order_id: public_id,
        order_entry_sequence: Sequence(2),
        method: OwnedMboBindingMethod::ExplicitNativeIdentifier,
    };
    let event = normalize_owned_mbo_binding(
        CaptureOrdinal(1),
        OwnedMboBindingInput {
            binding,
            monotonic_now: MonotonicTimestampNs(1_550),
        },
    )
    .unwrap();
    let mut reactor = TestReactor::new(engine);
    let mut output = [None; 2];
    let outcome = dispatch_reactor_replay_event(&mut reactor, event, &mut output).unwrap();

    assert_eq!(outcome.commands, 0);
    assert!(output.iter().all(Option::is_none));
    assert_eq!(
        reactor
            .engine()
            .owned_mbo_registry()
            .by_market_order(public_id),
        Some(binding)
    );
}

fn require_slots(provided: usize, required: usize) -> Result<(), WireError> {
    if provided < required {
        Err(WireError::BufferTooSmall { required, provided })
    } else {
        Ok(())
    }
}

fn market_messages(hardware_receive_timestamp: TimestampNs) -> [MarketDataMessage; 2] {
    [
        MarketDataMessage {
            instrument: INSTRUMENT,
            sequence: Sequence(100),
            exchange_timestamp: TimestampNs(hardware_receive_timestamp.0 - 10),
            hardware_receive_timestamp,
            payload: MarketDataPayload::Book(BookDelta::Add {
                order_id: MarketByOrderId(70_000),
                side: Side::Buy,
                price: PriceTicks(99),
                quantity: Quantity(20),
            }),
        },
        MarketDataMessage {
            instrument: INSTRUMENT,
            sequence: Sequence(101),
            exchange_timestamp: TimestampNs(hardware_receive_timestamp.0 - 9),
            hardware_receive_timestamp,
            payload: MarketDataPayload::Book(BookDelta::Add {
                order_id: MarketByOrderId(70_001),
                side: Side::Sell,
                price: PriceTicks(101),
                quantity: Quantity(20),
            }),
        },
    ]
}

fn accepted_message(hardware_receive_timestamp: TimestampNs) -> InboundMessage {
    InboundMessage {
        sequence: Sequence(2),
        exchange_timestamp: TimestampNs(hardware_receive_timestamp.0 - 1),
        hardware_receive_timestamp,
        payload: InboundPayload::Order(OrderEvent::Accepted(Accepted {
            client_order_id: ClientOrderId(1_000),
            venue_order_id: VenueOrderId(7_000),
            price: PriceTicks(99),
            quantity: Quantity(10),
        })),
    }
}

fn market_bindings() -> [OwnedMboBinding; 2] {
    [
        OwnedMboBinding {
            venue: IDENTITY.venue,
            client_order_id: ClientOrderId(1_000),
            venue_order_id: VenueOrderId(7_000),
            market_by_order_id: MarketByOrderId(70_000),
            order_entry_sequence: Sequence(10),
            method: OwnedMboBindingMethod::CertifiedDeterministicRule { rule_id: 19 },
        },
        OwnedMboBinding {
            venue: IDENTITY.venue,
            client_order_id: ClientOrderId(1_001),
            venue_order_id: VenueOrderId(7_001),
            market_by_order_id: MarketByOrderId(70_001),
            order_entry_sequence: Sequence(11),
            method: OwnedMboBindingMethod::CertifiedDeterministicRule { rule_id: 19 },
        },
    ]
}

fn order_binding() -> OwnedMboBinding {
    OwnedMboBinding {
        venue: IDENTITY.venue,
        client_order_id: ClientOrderId(1_000),
        venue_order_id: VenueOrderId(7_000),
        market_by_order_id: MarketByOrderId(7_000),
        order_entry_sequence: Sequence(2),
        method: OwnedMboBindingMethod::ExplicitNativeIdentifier,
    }
}

fn live_feed(adapter: &mut FixedExactAdapter) -> MarketDataFeed {
    let mut feed = MarketDataFeed::new::<FixedExactAdapter>(Sequence(100)).unwrap();
    feed.connect().unwrap();
    feed.begin_snapshot().unwrap();
    let mut output = [None; 1];
    feed.decode_snapshot(
        adapter,
        &SNAPSHOT_BEGIN_PACKET,
        TimestampNs(100),
        &mut output,
    )
    .unwrap();
    feed.decode_snapshot(adapter, &SNAPSHOT_END_PACKET, TimestampNs(110), &mut output)
        .unwrap();
    let token = feed.snapshot_apply_token().unwrap();
    feed.complete_snapshot(token, TimestampNs(120)).unwrap();
    feed
}

fn live_session(adapter: &mut FixedExactAdapter) -> VenueSession {
    let mut session = VenueSession::new::<FixedExactAdapter>(
        Sequence(500),
        Sequence(1),
        10_000,
        support::instrument_definition(IDENTITY.venue, INSTRUMENT),
    )
    .unwrap();
    session.connect(TimestampNs(10)).unwrap();
    let mut output = [None; 1];
    session
        .decode_inbound(adapter, &LOGON_PACKET, TimestampNs(30), &mut output)
        .unwrap();
    session
}

fn market_source() -> EventSource {
    EventSource::new(
        SourceId::new(IDENTITY.market_data_protocol.0, 1),
        SequenceDomain::MarketData,
        SessionEpoch(1),
    )
}

fn order_source() -> EventSource {
    EventSource::new(
        SourceId::new(IDENTITY.order_entry_protocol.0, 1),
        SequenceDomain::OrderEntry,
        SessionEpoch(1),
    )
}

fn market_metadata(frame_ordinal: u64) -> NativePacketMetadata {
    NativePacketMetadata {
        frame_ordinal,
        adapter_identity: IDENTITY,
        source: market_source(),
        hardware_receive_timestamp: TimestampNs(1_000),
        monotonic_timestamp: MonotonicTimestampNs(1_010),
        recovery: false,
    }
}

fn order_metadata(frame_ordinal: u64) -> NativePacketMetadata {
    NativePacketMetadata {
        frame_ordinal,
        adapter_identity: IDENTITY,
        source: order_source(),
        hardware_receive_timestamp: TimestampNs(2_000),
        monotonic_timestamp: MonotonicTimestampNs(2_010),
        recovery: false,
    }
}

fn venue_metadata(
    metadata: NativePacketMetadata,
    capture_ordinal: CaptureOrdinal,
) -> VenueCaptureMetadata {
    VenueCaptureMetadata {
        venue: metadata.adapter_identity.venue,
        source: metadata.source,
        capture_ordinal,
        monotonic_timestamp: metadata.monotonic_timestamp,
        recovery: metadata.recovery,
    }
}

fn normalized_market_events(
    metadata: NativePacketMetadata,
    ordinals: [u64; 2],
) -> [quant_hft_core::NormalizedEvent; 2] {
    let messages = market_messages(metadata.hardware_receive_timestamp);
    [
        normalize_market_data(
            venue_metadata(metadata, CaptureOrdinal(ordinals[0])),
            messages[0],
        )
        .unwrap(),
        normalize_market_data(
            venue_metadata(metadata, CaptureOrdinal(ordinals[1])),
            messages[1],
        )
        .unwrap(),
    ]
}

fn normalized_binding_events(
    bindings: &[OwnedMboBinding],
    ordinals: &[u64],
    monotonic_now: u64,
) -> Vec<quant_hft_core::NormalizedEvent> {
    bindings
        .iter()
        .zip(ordinals)
        .map(|(binding, ordinal)| {
            normalize_owned_mbo_binding(
                CaptureOrdinal(*ordinal),
                OwnedMboBindingInput {
                    binding: *binding,
                    monotonic_now: MonotonicTimestampNs(monotonic_now),
                },
            )
            .unwrap()
        })
        .collect()
}

fn owned_capture<'a>(
    metadata: NativePacketMetadata,
    lane: NativeIngressLane,
    packet: &'a [u8],
    expected_events: &'a [quant_hft_core::NormalizedEvent],
    expected_bindings: &'a [quant_hft_core::NormalizedEvent],
) -> NativeOwnedMboIngressCapture<'a> {
    NativeOwnedMboIngressCapture {
        ingress: NativeIngressCapture {
            metadata,
            lane,
            packet,
            expected_events,
        },
        expected_bindings,
    }
}

fn engine_config() -> EngineConfig {
    EngineConfig {
        venue: IDENTITY.venue,
        instrument: INSTRUMENT,
        first_market_sequence: Sequence(1),
        first_order_sequence: Sequence(1),
        first_client_order_id: ClientOrderId(1_000),
        first_risk_order_id: OrderId(5_000),
        instrument_definition: support::instrument_definition(IDENTITY.venue, INSTRUMENT),
        max_clock_uncertainty_ns: 1_000,
        max_clock_offset_step_ns: 100,
        max_clock_holdover_ns: 100_000,
        clock_drift_parts_per_billion: 10,
        risk_session: RiskSessionId(1),
        risk_definition: InstrumentRiskDefinition {
            instrument: INSTRUMENT,
            base_currency: CurrencyId(840),
            valuation: InstrumentValuation::Fixed {
                base_units_per_price_tick: 1,
                contract_multiplier: 1,
            },
            position_limit: Quantity(1_000),
        },
        risk: RiskLimits {
            max_order_quantity: Quantity(100),
            max_order_notional: 1_000_000,
            max_gross_notional: 10_000_000,
            max_net_notional: 10_000_000,
            max_daily_loss: 1_000_000,
            max_market_age_ns: 10_000,
        },
        adverse: AdverseConfig {
            markout_horizon_ns: 100,
            rolling_window_ns: 10_000,
            breach_markout_ticks: 1,
            halt_after_consecutive: 2,
            halt_aggregate_loss: 10_000,
            kill_after_consecutive: 3,
            kill_aggregate_loss: 20_000,
        },
        quote: QuotePolicyConfig {
            base_quantity: Quantity(10),
            base_half_spread_ticks: 1,
            max_volatility_spread_ticks: 10,
            max_abs_alpha_ticks: 1,
            inventory_skew_numerator: 0,
            inventory_skew_denominator: 1,
            max_abs_inventory: Quantity(1_000),
        },
    }
}

fn engine_market(sequence: u64, monotonic: u64, payload: MarketDataPayload) -> MarketDataMessage {
    MarketDataMessage {
        instrument: INSTRUMENT,
        sequence: Sequence(sequence),
        exchange_timestamp: TimestampNs(ENGINE_OFFSET + monotonic - 10),
        hardware_receive_timestamp: TimestampNs(ENGINE_OFFSET + monotonic),
        payload,
    }
}

fn engine_inbound(sequence: u64, monotonic: u64, payload: InboundPayload) -> InboundMessage {
    InboundMessage {
        sequence: Sequence(sequence),
        exchange_timestamp: TimestampNs(ENGINE_OFFSET + monotonic - 10),
        hardware_receive_timestamp: TimestampNs(ENGINE_OFFSET + monotonic),
        payload,
    }
}

fn engine_with_accepted_quotes() -> (TestEngine, NewOrder) {
    let mut engine = TestEngine::new(engine_config()).unwrap();
    engine
        .observe_clock(ClockSample {
            utc: TimestampNs(ENGINE_OFFSET + 1_000),
            monotonic: MonotonicTimestampNs(1_000),
            uncertainty_ns: 10,
        })
        .unwrap();
    let mut output = [None; 2];
    for (monotonic, payload) in [
        (
            1_010,
            SnapshotPayload::Begin {
                snapshot_id: 1,
                last_incremental_sequence: Sequence(0),
            },
        ),
        (
            1_020,
            SnapshotPayload::End {
                snapshot_id: 1,
                last_incremental_sequence: Sequence(0),
            },
        ),
    ] {
        engine
            .on_snapshot(
                SnapshotMessage {
                    exchange_timestamp: TimestampNs(ENGINE_OFFSET + monotonic - 10),
                    hardware_receive_timestamp: TimestampNs(ENGINE_OFFSET + monotonic),
                    payload,
                },
                MonotonicTimestampNs(monotonic),
                &mut output,
            )
            .unwrap();
    }
    engine
        .on_order_entry(
            engine_inbound(
                1,
                1_030,
                InboundPayload::Session(SessionEvent::LogonAccepted),
            ),
            MonotonicTimestampNs(1_030),
            &mut output,
        )
        .unwrap();
    engine
        .apply_control_decision(
            support::authenticated_arm(
                1,
                ConfigDigest([0xA5; 32]),
                Sequence(1),
                TimestampNs(ENGINE_OFFSET + 1_030),
                TimestampNs(u64::MAX),
            ),
            &mut output,
        )
        .unwrap();
    engine
        .on_market_data(
            engine_market(
                1,
                1_050,
                MarketDataPayload::TradingStatus { status_code: 1 },
            ),
            MonotonicTimestampNs(1_050),
            &mut output,
        )
        .unwrap();
    engine
        .on_market_data(
            engine_market(
                2,
                1_100,
                MarketDataPayload::Book(BookDelta::Add {
                    order_id: MarketByOrderId(11),
                    side: Side::Buy,
                    price: PriceTicks(99),
                    quantity: Quantity(100),
                }),
            ),
            MonotonicTimestampNs(1_100),
            &mut output,
        )
        .unwrap();
    engine
        .on_market_data(
            engine_market(
                3,
                1_200,
                MarketDataPayload::Trade {
                    trade_id: TradeId(90),
                    side: Side::Buy,
                    price: PriceTicks(100),
                    quantity: Quantity(1),
                },
            ),
            MonotonicTimestampNs(1_200),
            &mut output,
        )
        .unwrap();
    engine
        .on_market_data(
            engine_market(
                4,
                1_300,
                MarketDataPayload::Book(BookDelta::Add {
                    order_id: MarketByOrderId(12),
                    side: Side::Sell,
                    price: PriceTicks(101),
                    quantity: Quantity(100),
                }),
            ),
            MonotonicTimestampNs(1_300),
            &mut output,
        )
        .unwrap();
    let commands = [output[0].unwrap(), output[1].unwrap()];
    let mut bid = None;
    let mut ask = None;
    for command in commands {
        match command {
            OrderCommand::New(order) if order.side == Side::Buy => bid = Some(order),
            OrderCommand::New(order) if order.side == Side::Sell => ask = Some(order),
            _ => panic!("expected two new quote commands"),
        }
        engine
            .on_transmission(
                command,
                TransmissionStatus::Sent,
                MonotonicTimestampNs(1_400),
            )
            .unwrap();
    }
    let bid = bid.unwrap();
    let ask = ask.unwrap();
    for (sequence, monotonic, order, venue_order_id) in [
        (2, 1_500, bid, VenueOrderId(7_000)),
        (3, 1_501, ask, VenueOrderId(7_001)),
    ] {
        engine
            .on_order_entry(
                engine_inbound(
                    sequence,
                    monotonic,
                    InboundPayload::Order(OrderEvent::Accepted(Accepted {
                        client_order_id: order.client_order_id,
                        venue_order_id,
                        price: order.price,
                        quantity: order.quantity,
                    })),
                ),
                MonotonicTimestampNs(monotonic),
                &mut [None; 2],
            )
            .unwrap();
    }
    (engine, bid)
}
