mod support;

use quant_hft_core::adverse::{AdverseConfig, AdverseMonitor};
use quant_hft_core::control::ConfigDigest;
use quant_hft_core::kill::KillLatch;
use quant_hft_core::reactor::{
    InputOrdinal, ReactorEgress, ReactorInputKind, ReactorStop, RunOrdinal, TransmissionInput,
};
use quant_hft_core::reactor_audit::{
    SCHEDULER_COMMIT_RECORD_LEN, SchedulerCommit, SchedulerRoute, decode_scheduler_commit,
    encode_scheduler_commit,
};
use quant_hft_core::risk::{
    CurrencyId, InstrumentRiskDefinition, InstrumentValuation, PreTradeRequest, RiskEngine,
    RiskLimits, RiskSessionId,
};
use quant_hft_core::venue::{
    DecodeResult, DirectMarketDataDecoder, InboundMessage, InboundPayload, MarketDataFeed,
    MarketDataMessage, MarketDataPayload, NativeOrderEntryDecoder, NativeOrderEntryEncoder,
    NewOrder, OrderCommand, ProtocolId, SessionCommand, SessionEvent, SessionId, SnapshotMessage,
    SnapshotPayload, TimeInForce, TransactionalCodec, VenueCapabilities, VenueDescriptor,
    VenueIdentity, VenueSession, WireError,
};
use quant_hft_core::{
    AUDIT_PREFIX_AUTHENTICATED_LEN, AUDIT_PREFIX_RECORD_LEN, AuditContainerHeader,
    AuditContainerId, AuditPrefixAnchor, AuditPrefixFlags, AuditPrefixRecordVariant,
    AuditPrefixTicketState, AuditRecordKind, AuditTag, BookEvent, CancelConfirmed, CancelReason,
    CaptureOrdinal, ClientOrderId, ClockDiscipline, ClockSample, EventSource, ExactQueuePosition,
    InstrumentDefinitionBinding, InstrumentId, L3Book, LatencyHistogram, MonotonicTimestampNs,
    NATIVE_LIVE_CHECKPOINT_RECORD_LEN, NativeIngressCapture, NativeIngressLane,
    NativeLiveCheckpoint, NativeLivePhase, NativeOrderEgressCapture, NativePacketMetadata,
    NativeProductId, NativeReplayVerifier, NativeTransmissionContext,
    NativeTransmissionDisposition, NativeTransmissionProofError, NativeTransmissionProofVerifier,
    NewAccepted, NewOrderRequest, OrderEconomics, OrderId, OrderManager, PriceTicks, Quantity,
    QueuePolicy, QueuePosition, ReferenceDataAuthorityId, ReferenceDataDigest, Sequence,
    SequenceDomain, SessionEpoch, Side, SourceId, SpscRing, TimestampNs, VenueCaptureMetadata,
    VenueId, VenueOrderId, VenueOrderIdentity, decode_audit_prefix_anchor,
    decode_native_live_checkpoint_record, encode_audit_prefix_anchor,
    encode_audit_prefix_authenticated, encode_native_live_checkpoint_record, encode_record,
    normalize_market_data, normalize_transmission,
};
use quant_hft_core::{engine::TransmissionStatus, journal::RECORD_LEN};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::Mutex;

#[derive(Debug)]
struct CountingAllocator;

static TEST_LOCK: Mutex<()> = Mutex::new(());

thread_local! {
    static TRACK_ALLOCATIONS: Cell<bool> = const { Cell::new(false) };
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

fn count_allocation() {
    let _ = TRACK_ALLOCATIONS.try_with(|tracking| {
        if tracking.get() {
            let _ = ALLOCATIONS.try_with(|allocations| {
                allocations.set(allocations.get().saturating_add(1));
            });
        }
    });
}

// SAFETY: every operation is forwarded unchanged to `System`; the counter is
// observational and does not alter pointer, layout, or lifetime semantics.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        count_allocation();
        // SAFETY: the caller provides the `GlobalAlloc` contract and `layout` is
        // forwarded unchanged to the system allocator.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: `pointer` and `layout` came from the forwarded system allocation.
        unsafe { System.dealloc(pointer, layout) };
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        count_allocation();
        // SAFETY: the caller provides the `GlobalAlloc` contract and `layout` is
        // forwarded unchanged to the system allocator.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        count_allocation();
        // SAFETY: all arguments are forwarded unchanged to the system allocator.
        unsafe { System.realloc(pointer, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

const NATIVE_IDENTITY: VenueIdentity = VenueIdentity {
    venue: VenueId(7),
    market_data_protocol: ProtocolId(101),
    order_entry_protocol: ProtocolId(202),
    session: SessionId(303),
};

const NATIVE_CAPABILITIES: VenueCapabilities = VenueCapabilities::MARKET_DATA_L3
    .union(VenueCapabilities::SNAPSHOT_RECOVERY)
    .union(VenueCapabilities::NEW_ORDER);

const MARKET_PACKET_TAG: u8 = 0x40;
const SNAPSHOT_BEGIN_TAG: u8 = 0x50;
const SNAPSHOT_END_TAG: u8 = 0x52;
const LOGON_PACKET_TAG: u8 = 0x60;
const MARKET_PACKET_LEN: usize = 9;
const SNAPSHOT_PACKET_LEN: usize = 17;
const NEW_ORDER_WIRE_LEN: usize = 47;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct FixedNativeAdapter {
    codec_state: u64,
}

impl VenueDescriptor for FixedNativeAdapter {
    const IDENTITY: VenueIdentity = NATIVE_IDENTITY;
    const CAPABILITIES: VenueCapabilities = NATIVE_CAPABILITIES;
}

impl TransactionalCodec for FixedNativeAdapter {
    type Checkpoint = u64;

    fn checkpoint(&self) -> Self::Checkpoint {
        self.codec_state
    }

    fn restore(&mut self, checkpoint: Self::Checkpoint) {
        self.codec_state = checkpoint;
    }
}

impl DirectMarketDataDecoder for FixedNativeAdapter {
    fn decode_market_data(
        &mut self,
        packet: &[u8],
        hardware_receive_timestamp: TimestampNs,
        output: &mut [Option<MarketDataMessage>],
    ) -> Result<DecodeResult, WireError> {
        require_native_slot(output.len())?;
        if packet.len() != MARKET_PACKET_LEN || packet[0] != MARKET_PACKET_TAG {
            return Err(WireError::MalformedPacket);
        }
        let sequence = Sequence(read_native_u64(packet, 1)?);
        self.codec_state = self.codec_state.wrapping_add(1);
        output[0] = Some(fixed_market_message(sequence, hardware_receive_timestamp));
        Ok(DecodeResult {
            messages: 1,
            consumed_bytes: MARKET_PACKET_LEN,
        })
    }

    fn decode_snapshot(
        &mut self,
        packet: &[u8],
        hardware_receive_timestamp: TimestampNs,
        output: &mut [Option<SnapshotMessage>],
    ) -> Result<DecodeResult, WireError> {
        require_native_slot(output.len())?;
        if packet.len() != SNAPSHOT_PACKET_LEN {
            return Err(WireError::MalformedPacket);
        }
        let snapshot_id = read_native_u64(packet, 1)?;
        let last_incremental_sequence = Sequence(read_native_u64(packet, 9)?);
        let payload = match packet[0] {
            SNAPSHOT_BEGIN_TAG => SnapshotPayload::Begin {
                snapshot_id,
                last_incremental_sequence,
            },
            SNAPSHOT_END_TAG => SnapshotPayload::End {
                snapshot_id,
                last_incremental_sequence,
            },
            _ => return Err(WireError::MalformedPacket),
        };
        self.codec_state = self.codec_state.wrapping_add(1);
        output[0] = Some(SnapshotMessage {
            exchange_timestamp: TimestampNs(hardware_receive_timestamp.0 - 1),
            hardware_receive_timestamp,
            payload,
        });
        Ok(DecodeResult {
            messages: 1,
            consumed_bytes: SNAPSHOT_PACKET_LEN,
        })
    }
}

impl NativeOrderEntryDecoder for FixedNativeAdapter {
    fn decode_order_entry(
        &mut self,
        packet: &[u8],
        hardware_receive_timestamp: TimestampNs,
        output: &mut [Option<InboundMessage>],
    ) -> Result<DecodeResult, WireError> {
        require_native_slot(output.len())?;
        if packet != [LOGON_PACKET_TAG] {
            return Err(WireError::MalformedPacket);
        }
        self.codec_state = self.codec_state.wrapping_add(1);
        output[0] = Some(InboundMessage {
            sequence: Sequence(1),
            exchange_timestamp: TimestampNs(20),
            hardware_receive_timestamp,
            payload: InboundPayload::Session(SessionEvent::LogonAccepted),
        });
        Ok(DecodeResult {
            messages: 1,
            consumed_bytes: 1,
        })
    }
}

impl NativeOrderEntryEncoder for FixedNativeAdapter {
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
        sequence: Sequence,
        command: OrderCommand,
        _instrument: quant_hft_core::InstrumentDefinition,
        output: &mut [u8],
    ) -> Result<usize, WireError> {
        let OrderCommand::New(order) = command else {
            return Err(WireError::UnsupportedMessage { message_type: 0 });
        };
        if output.len() < NEW_ORDER_WIRE_LEN {
            return Err(WireError::BufferTooSmall {
                required: NEW_ORDER_WIRE_LEN,
                provided: output.len(),
            });
        }
        self.codec_state = self.codec_state.wrapping_add(1);
        write_new_order_wire(output, sequence, order);
        Ok(NEW_ORDER_WIRE_LEN)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FixedTransportProof {
    frame_ordinal: u64,
    venue_sequence: Sequence,
    scheduler_commit_ordinal: u64,
    scheduler_capture_ordinal: CaptureOrdinal,
    scheduler_source_event_crc32c: u32,
    egress: ReactorEgress,
    encoded_bytes: [u8; NEW_ORDER_WIRE_LEN],
    disposition: NativeTransmissionDisposition,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct FixedTransportVerifier {
    verified: u64,
}

impl NativeTransmissionProofVerifier for FixedTransportVerifier {
    type Proof = FixedTransportProof;
    type Checkpoint = u64;

    fn checkpoint(&self) -> Self::Checkpoint {
        self.verified
    }

    fn restore(&mut self, checkpoint: Self::Checkpoint) {
        self.verified = checkpoint;
    }

    fn verify(
        &mut self,
        context: NativeTransmissionContext<'_>,
        proof: &Self::Proof,
    ) -> Result<NativeTransmissionDisposition, NativeTransmissionProofError> {
        self.verified = self.verified.wrapping_add(1);
        if context.frame_ordinal != proof.frame_ordinal
            || context.adapter_identity != NATIVE_IDENTITY
            || context.venue_sequence != proof.venue_sequence
            || context.scheduler_commit_ordinal != proof.scheduler_commit_ordinal
            || context.scheduler_capture_ordinal != proof.scheduler_capture_ordinal
            || context.scheduler_source_event_crc32c != proof.scheduler_source_event_crc32c
            || context.egress != proof.egress
            || context.encoded_bytes != proof.encoded_bytes
        {
            return Err(NativeTransmissionProofError::Rejected);
        }
        Ok(proof.disposition)
    }
}

fn require_native_slot(provided: usize) -> Result<(), WireError> {
    if provided == 0 {
        Err(WireError::BufferTooSmall {
            required: 1,
            provided,
        })
    } else {
        Ok(())
    }
}

fn fixed_market_message(
    sequence: Sequence,
    hardware_receive_timestamp: TimestampNs,
) -> MarketDataMessage {
    MarketDataMessage {
        sequence,
        exchange_timestamp: TimestampNs(hardware_receive_timestamp.0 - 100),
        hardware_receive_timestamp,
        instrument: InstrumentId(9),
        payload: MarketDataPayload::TradingStatus { status_code: 1 },
    }
}

fn fixed_market_packet(sequence: Sequence) -> [u8; MARKET_PACKET_LEN] {
    let mut packet = [0_u8; MARKET_PACKET_LEN];
    packet[0] = MARKET_PACKET_TAG;
    write_native_u64(&mut packet, 1, sequence.0);
    packet
}

fn fixed_snapshot_packet(kind: u8) -> [u8; SNAPSHOT_PACKET_LEN] {
    let mut packet = [0_u8; SNAPSHOT_PACKET_LEN];
    packet[0] = kind;
    write_native_u64(&mut packet, 1, 77);
    write_native_u64(&mut packet, 9, 99);
    packet
}

fn live_native_feed(adapter: &mut FixedNativeAdapter) -> MarketDataFeed {
    let mut feed = MarketDataFeed::new::<FixedNativeAdapter>(Sequence(100)).expect("native feed");
    feed.connect().expect("native feed connect");
    feed.begin_snapshot().expect("native feed snapshot");
    let mut output = [None; 1];
    feed.decode_snapshot(
        adapter,
        &fixed_snapshot_packet(SNAPSHOT_BEGIN_TAG),
        TimestampNs(101),
        &mut output,
    )
    .expect("snapshot begin");
    feed.decode_snapshot(
        adapter,
        &fixed_snapshot_packet(SNAPSHOT_END_TAG),
        TimestampNs(111),
        &mut output,
    )
    .expect("snapshot end");
    let token = feed.snapshot_apply_token().expect("snapshot token");
    feed.complete_snapshot(token, TimestampNs(120))
        .expect("snapshot apply");
    feed
}

fn live_native_session(adapter: &mut FixedNativeAdapter) -> VenueSession {
    let mut session = VenueSession::new::<FixedNativeAdapter>(
        Sequence(700),
        Sequence(1),
        10_000,
        support::instrument_definition(NATIVE_IDENTITY.venue, InstrumentId(9)),
    )
    .expect("native session");
    session.connect(TimestampNs(10)).expect("session connect");
    session
        .decode_inbound(
            adapter,
            &[LOGON_PACKET_TAG],
            TimestampNs(30),
            &mut [None; 1],
        )
        .expect("session logon");
    session
}

fn native_market_source() -> EventSource {
    EventSource::new(
        SourceId::new(NATIVE_IDENTITY.market_data_protocol.0, 1),
        SequenceDomain::MarketData,
        SessionEpoch(1),
    )
}

fn fixed_new_order(iteration: u64) -> OrderCommand {
    OrderCommand::New(NewOrder {
        client_order_id: ClientOrderId(10_000 + iteration),
        instrument: InstrumentId(9),
        side: Side::Buy,
        price: PriceTicks(100),
        quantity: Quantity(5),
        time_in_force: TimeInForce::PostOnly,
        created_at: TimestampNs(2_000 + iteration),
    })
}

fn expected_new_order_wire(sequence: Sequence, command: OrderCommand) -> [u8; NEW_ORDER_WIRE_LEN] {
    let OrderCommand::New(order) = command else {
        return [0_u8; NEW_ORDER_WIRE_LEN];
    };
    let mut wire = [0_u8; NEW_ORDER_WIRE_LEN];
    write_new_order_wire(&mut wire, sequence, order);
    wire
}

fn write_new_order_wire(output: &mut [u8], sequence: Sequence, order: NewOrder) {
    output[0] = 0x20;
    write_native_u64(output, 1, sequence.0);
    write_native_u64(output, 9, order.client_order_id.0);
    output[17..21].copy_from_slice(&order.instrument.0.to_le_bytes());
    output[21] = order.side as u8;
    output[22..30].copy_from_slice(&order.price.0.to_le_bytes());
    output[30..38].copy_from_slice(&order.quantity.0.to_le_bytes());
    output[38] = order.time_in_force as u8;
    write_native_u64(output, 39, order.created_at.0);
}

fn canonical_event_crc32c(event: quant_hft_core::NormalizedEvent) -> Option<u32> {
    let mut record = [0_u8; RECORD_LEN];
    if encode_record(event, &mut record) != Ok(RECORD_LEN) {
        return None;
    }
    Some(u32::from_le_bytes([
        record[RECORD_LEN - 4],
        record[RECORD_LEN - 3],
        record[RECORD_LEN - 2],
        record[RECORD_LEN - 1],
    ]))
}

fn write_native_u64(output: &mut [u8], offset: usize, value: u64) {
    output[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn read_native_u64(input: &[u8], offset: usize) -> Result<u64, WireError> {
    let bytes = input
        .get(offset..offset + 8)
        .ok_or(WireError::MalformedPacket)?;
    Ok(u64::from_le_bytes(
        bytes.try_into().map_err(|_| WireError::MalformedPacket)?,
    ))
}

#[test]
fn representative_hot_path_performs_no_heap_allocations() {
    let _guard = TEST_LOCK.lock().expect("allocation test lock");
    let mut book = L3Book::<16, 8>::new(Sequence(1));
    book.apply(
        Sequence(1),
        BookEvent::Add {
            order_id: OrderId(1),
            side: Side::Buy,
            price: PriceTicks(100),
            quantity: Quantity(10),
        },
    )
    .expect("seed bid");
    book.apply(
        Sequence(2),
        BookEvent::Add {
            order_id: OrderId(2),
            side: Side::Sell,
            price: PriceTicks(102),
            quantity: Quantity(10),
        },
    )
    .expect("seed ask");

    let mut queue = QueuePosition::new(
        OrderId(99),
        Side::Buy,
        PriceTicks(100),
        Quantity(5),
        Quantity(20),
        QueuePolicy::Conservative,
    )
    .expect("queue");
    let mut exact_queue = ExactQueuePosition::<16>::join_behind_book(
        &book,
        OrderId(100),
        Side::Buy,
        PriceTicks(100),
        Quantity(5),
    )
    .expect("exact MBO queue");
    let mut clock = ClockDiscipline::new(1_000, 100, 10_000_000, 10);
    clock
        .observe(ClockSample {
            utc: TimestampNs(1_000_000),
            monotonic: MonotonicTimestampNs(500_000),
            uncertainty_ns: 20,
        })
        .expect("clock sample");
    let mut histogram = LatencyHistogram::<32>::new();
    let mut ring = SpscRing::<u64, 64>::new();
    let (mut producer, mut consumer) = ring.split();
    let kill = KillLatch::new();
    let mut risk = RiskEngine::<4, 64>::new(
        RiskLimits {
            max_order_quantity: Quantity(100),
            max_order_notional: 1_000_000,
            max_gross_notional: 10_000_000,
            max_net_notional: 10_000_000,
            max_daily_loss: 1_000_000,
            max_market_age_ns: 20_000_000,
        },
        RiskSessionId(1),
    )
    .expect("risk");
    risk.register_instrument(InstrumentRiskDefinition {
        instrument: quant_hft_core::InstrumentId(1),
        base_currency: CurrencyId(840),
        valuation: InstrumentValuation::Fixed {
            base_units_per_price_tick: 1,
            contract_multiplier: 1,
        },
        position_limit: Quantity(1_000),
    })
    .expect("instrument risk definition");
    risk.on_mark(
        quant_hft_core::InstrumentId(1),
        PriceTicks(100),
        TimestampNs(500_000),
        TimestampNs(500_000),
        true,
        &kill,
    )
    .expect("initial risk mark");
    let adverse = AdverseMonitor::<4, 64>::new(AdverseConfig {
        markout_horizon_ns: 1_000,
        rolling_window_ns: 10_000,
        breach_markout_ticks: 2,
        halt_after_consecutive: 3,
        halt_aggregate_loss: 1_000,
        kill_after_consecutive: 5,
        kill_aggregate_loss: 2_000,
    })
    .expect("adverse monitor");
    let mut orders = OrderManager::<64, 64>::new().expect("orders");

    ALLOCATIONS.set(0);
    TRACK_ALLOCATIONS.set(true);
    for (sequence, iteration) in (3_u64..).zip(0..10_000_u64) {
        let quantity = Quantity(i64::try_from(iteration % 9 + 1).expect("bounded quantity"));
        let book_outcome = book
            .apply(
                Sequence(sequence),
                BookEvent::Modify {
                    order_id: OrderId(1),
                    price: PriceTicks(100),
                    quantity,
                },
            )
            .expect("bounded replace");
        exact_queue
            .on_book_outcome(&book, book_outcome)
            .expect("exact MBO queue update");
        queue
            .replace(PriceTicks(100), Quantity(5), Quantity(20))
            .expect("queue replace");
        let timestamp = clock
            .timestamp(MonotonicTimestampNs(500_000 + iteration))
            .expect("disciplined time");
        histogram.record(timestamp.uncertainty_ns);
        producer.try_push(iteration).expect("ring has one item");
        assert_eq!(consumer.try_pop(), Some(iteration));

        let id = iteration + 1;
        let client_order_id = ClientOrderId(id);
        let economics = OrderEconomics {
            client_order_id,
            instrument: quant_hft_core::InstrumentId(1),
            side: Side::Buy,
            limit_price: PriceTicks(100),
            original_quantity: Quantity(5),
        };
        orders
            .prepare_new(
                NewOrderRequest {
                    client_order_id,
                    risk_order_id: OrderId(id),
                    instrument: economics.instrument,
                    side: economics.side,
                    limit_price: economics.limit_price,
                    quantity: economics.original_quantity,
                    now: TimestampNs(501_000 + iteration),
                    clock_healthy: true,
                },
                &mut risk,
                &adverse,
                &kill,
            )
            .expect("reserve order");
        orders
            .mark_new_transmitted(client_order_id, TimestampNs(501_000 + iteration), &kill)
            .expect("new transmitted");
        let venue_order_id = VenueOrderId(id);
        orders
            .on_new_accepted(
                NewAccepted {
                    order: VenueOrderIdentity {
                        economics,
                        venue_order_id,
                    },
                    sequence: Sequence(id * 2 + 1),
                    leaves_quantity: Quantity(5),
                    received_at: TimestampNs(501_000 + iteration),
                },
                &risk,
                &kill,
            )
            .expect("new accepted");
        orders
            .prepare_cancel(client_order_id, TimestampNs(501_000 + iteration), &kill)
            .expect("prepare cancel");
        orders
            .mark_cancel_transmitted(client_order_id, TimestampNs(501_000 + iteration), &kill)
            .expect("cancel transmitted");
        orders
            .on_cancel_confirmed(
                CancelConfirmed {
                    order: VenueOrderIdentity {
                        economics,
                        venue_order_id,
                    },
                    sequence: Sequence(id * 2 + 2),
                    canceled_quantity: Quantity(5),
                    leaves_quantity: Quantity::ZERO,
                    reason: CancelReason::Requested,
                    received_at: TimestampNs(501_000 + iteration),
                },
                &mut risk,
                &kill,
            )
            .expect("cancel confirmed");
    }
    TRACK_ALLOCATIONS.set(false);
    let allocations = ALLOCATIONS.get();

    assert_eq!(allocations, 0, "hot-path loop allocated on the heap");
    assert_eq!(histogram.count(), 10_000);
    assert_eq!(orders.order_count(), 0);
    assert_eq!(risk.order_count(), 0);
}

#[test]
fn per_order_mark_revaluation_performs_no_heap_allocations() {
    let _guard = TEST_LOCK.lock().expect("allocation test lock");
    let kill = KillLatch::new();
    let mut risk = RiskEngine::<1, 8>::new(
        RiskLimits {
            max_order_quantity: Quantity(100),
            max_order_notional: 1_000_000,
            max_gross_notional: 10_000_000,
            max_net_notional: 10_000_000,
            max_daily_loss: 1_000_000,
            max_market_age_ns: 1_000_000,
        },
        RiskSessionId(1),
    )
    .expect("risk");
    risk.register_instrument(InstrumentRiskDefinition {
        instrument: InstrumentId(1),
        base_currency: CurrencyId(840),
        valuation: InstrumentValuation::Fixed {
            base_units_per_price_tick: 1,
            contract_multiplier: 1,
        },
        position_limit: Quantity(1_000),
    })
    .expect("instrument");
    risk.on_mark(
        InstrumentId(1),
        PriceTicks(100),
        TimestampNs(100),
        TimestampNs(100),
        true,
        &kill,
    )
    .expect("initial mark");
    for (order_id, side, price) in [
        (1, Side::Buy, 50),
        (2, Side::Buy, 150),
        (3, Side::Sell, 80),
        (4, Side::Sell, 200),
    ] {
        risk.authorize_order(
            PreTradeRequest {
                order_id: OrderId(order_id),
                instrument: InstrumentId(1),
                side,
                price: PriceTicks(price),
                quantity: Quantity(1),
                now: TimestampNs(101),
                clock_healthy: true,
                instrument_halted: false,
            },
            &kill,
        )
        .expect("reservation");
    }

    ALLOCATIONS.set(0);
    TRACK_ALLOCATIONS.set(true);
    for iteration in 0_u64..10_000 {
        let price = if iteration % 2 == 0 { 120 } else { 60 };
        let timestamp = TimestampNs(102 + iteration);
        risk.on_mark(
            InstrumentId(1),
            PriceTicks(price),
            timestamp,
            timestamp,
            true,
            &kill,
        )
        .expect("bounded revaluation");
    }
    TRACK_ALLOCATIONS.set(false);

    assert_eq!(ALLOCATIONS.get(), 0, "risk revaluation allocated");
    let state = risk.instrument(InstrumentId(1)).expect("instrument state");
    assert_eq!(state.open_buy_notional, 210);
    assert_eq!(state.open_sell_notional, 280);
    assert!(!kill.is_triggered());
}

#[test]
fn scheduler_commit_codec_performs_no_heap_allocations() {
    let _guard = TEST_LOCK.lock().expect("allocation test lock");
    let command = OrderCommand::New(NewOrder {
        client_order_id: ClientOrderId(90),
        instrument: quant_hft_core::InstrumentId(1),
        side: Side::Buy,
        price: PriceTicks(100),
        quantity: Quantity(5),
        time_in_force: TimeInForce::PostOnly,
        created_at: TimestampNs(1_000),
    });
    let commit = SchedulerCommit {
        commit_ordinal: 1,
        route: SchedulerRoute::Normal,
        input_kind: Some(ReactorInputKind::MarketData),
        run_ordinal: Some(RunOrdinal(1)),
        input_ordinal: Some(InputOrdinal(1)),
        egress_input_ordinal: Some(InputOrdinal(1)),
        capture_ordinal: quant_hft_core::CaptureOrdinal(1),
        source_event_crc32c: 0x1234_5678,
        commands: [Some(command), None],
        outstanding_transmissions: 1,
        event_retained: false,
        mandatory_kill_pending: false,
        stop: Some(ReactorStop::TransmissionBoundary {
            published: 1,
            outstanding: 1,
        }),
    };
    let mut record = [0_u8; SCHEDULER_COMMIT_RECORD_LEN];
    encode_scheduler_commit(commit, &mut record).expect("warm scheduler encode");
    decode_scheduler_commit(&record).expect("warm scheduler decode");

    ALLOCATIONS.set(0);
    TRACK_ALLOCATIONS.set(true);
    for _ in 0..10_000 {
        assert_eq!(
            encode_scheduler_commit(commit, &mut record),
            Ok(SCHEDULER_COMMIT_RECORD_LEN)
        );
        assert_eq!(decode_scheduler_commit(&record).unwrap().0, commit);
    }
    TRACK_ALLOCATIONS.set(false);
    let allocations = ALLOCATIONS.get();
    assert_eq!(allocations, 0, "scheduler commit codec allocated");
}

#[test]
fn native_checkpoint_codec_performs_no_heap_allocations() {
    let _guard = TEST_LOCK.lock().expect("allocation test lock");
    let checkpoint = NativeLiveCheckpoint {
        expected_identity: NATIVE_IDENTITY,
        expected_instrument_binding: InstrumentDefinitionBinding {
            venue: NATIVE_IDENTITY.venue,
            instrument: InstrumentId(1),
            native_product: NativeProductId(2),
            authority: ReferenceDataAuthorityId(3),
            reference_data_version: 4,
            reference_data_digest: ReferenceDataDigest([0x5a; 32]),
        },
        expected_market_data_source: native_market_source(),
        expected_order_entry_source: EventSource::new(
            SourceId::new(NATIVE_IDENTITY.order_entry_protocol.0, 8),
            SequenceDomain::OrderEntry,
            SessionEpoch(1),
        ),
        expected_drop_copy_source: Some(EventSource::new(
            SourceId::new(303, 9),
            SequenceDomain::DropCopy,
            SessionEpoch(2),
        )),
        monotonic_clock_epoch: 11,
        expected_first_source_capture: CaptureOrdinal(12),
        last_source_capture: Some(CaptureOrdinal(13)),
        last_feedback_capture: Some(CaptureOrdinal(14)),
        last_outbound_frame: Some(15),
        next_commit_ordinal: 16,
        phase: NativeLivePhase::Ambiguous,
    };
    let scope_ticket = 17;
    let mut record = [0_u8; NATIVE_LIVE_CHECKPOINT_RECORD_LEN];
    encode_native_live_checkpoint_record(scope_ticket, checkpoint, &mut record)
        .expect("warm checkpoint encode");
    decode_native_live_checkpoint_record(&record).expect("warm checkpoint decode");

    let mut succeeded = true;
    ALLOCATIONS.set(0);
    TRACK_ALLOCATIONS.set(true);
    for _ in 0..10_000 {
        if encode_native_live_checkpoint_record(scope_ticket, checkpoint, &mut record)
            != Ok(NATIVE_LIVE_CHECKPOINT_RECORD_LEN)
            || decode_native_live_checkpoint_record(&record) != Ok((scope_ticket, checkpoint))
        {
            succeeded = false;
            break;
        }
    }
    TRACK_ALLOCATIONS.set(false);

    assert!(succeeded, "native checkpoint codec failed");
    assert_eq!(ALLOCATIONS.get(), 0, "native checkpoint codec allocated");
}

#[test]
fn audit_prefix_codec_performs_no_heap_allocations() {
    let _guard = TEST_LOCK.lock().expect("allocation test lock");
    let header_tag = AuditTag([0xA3; 32]);
    let deployment_tag = AuditTag([0xD6; 32]);
    let header = AuditContainerHeader {
        algorithm_id: 0x5148_5041,
        key_id: 0x1122_3344_5566_7788,
        container_id: AuditContainerId([0x42; 16]),
        generation: 1,
        first_record_ordinal: 41,
        monotonic_clock_epoch: 11,
        config_digest: ConfigDigest([0xC3; 32]),
        software_digest: [0x5A; 32],
        venue_identity: NATIVE_IDENTITY,
        market_data_source: native_market_source(),
        order_entry_source: EventSource::new(
            SourceId::new(NATIVE_IDENTITY.order_entry_protocol.0, 8),
            SequenceDomain::OrderEntry,
            SessionEpoch(1),
        ),
        drop_copy_source: None,
        instrument_definition_binding: InstrumentDefinitionBinding {
            venue: NATIVE_IDENTITY.venue,
            instrument: InstrumentId(1),
            native_product: NativeProductId(2),
            authority: ReferenceDataAuthorityId(3),
            reference_data_version: 4,
            reference_data_digest: ReferenceDataDigest([0x5A; 32]),
        },
        predecessor: None,
    };
    let mut anchor = AuditPrefixAnchor {
        flags: AuditPrefixFlags::NONE,
        algorithm_id: header.algorithm_id,
        key_id: header.key_id,
        anchor_sequence: 2,
        previous_anchor_sequence: 1,
        container_id: header.container_id,
        container_generation: header.generation,
        committed_file_length: 700,
        record_count: 1,
        first_record_ordinal: header.first_record_ordinal,
        last_record_ordinal: header.first_record_ordinal,
        header_tag,
        current_record_chain_tag: AuditTag([0xB4; 32]),
        scope_ticket: 0,
        ticket_state: AuditPrefixTicketState::TicketClosed,
        last_record_kind: AuditRecordKind::LIVE_CHECKPOINT,
        last_record_variant: AuditPrefixRecordVariant::CHECKPOINT,
        unresolved_intent_count: 0,
        next_record_ordinal: header.first_record_ordinal + 1,
        next_frame_ordinal: 2,
        next_capture_ordinal: 3,
        next_commit_ordinal: 4,
        next_ticket_id: 0,
        monotonic_clock_epoch: header.monotonic_clock_epoch,
        previous_anchor_tag: AuditTag([0xC5; 32]),
    };
    let mut authenticated = [0_u8; AUDIT_PREFIX_AUTHENTICATED_LEN];
    let mut record = [0_u8; AUDIT_PREFIX_RECORD_LEN];
    encode_audit_prefix_authenticated(&anchor, &header, header_tag, &mut authenticated)
        .expect("warm prefix encode");
    encode_audit_prefix_anchor(&anchor, &header, header_tag, deployment_tag, &mut record)
        .expect("warm tagged prefix encode");
    decode_audit_prefix_anchor(&record, &header, header_tag).expect("warm prefix decode");

    let mut succeeded = true;
    ALLOCATIONS.set(0);
    TRACK_ALLOCATIONS.set(true);
    for sequence in 2..10_002 {
        anchor.anchor_sequence = sequence;
        anchor.previous_anchor_sequence = sequence - 1;
        if encode_audit_prefix_authenticated(&anchor, &header, header_tag, &mut authenticated)
            != Ok(AUDIT_PREFIX_AUTHENTICATED_LEN)
            || encode_audit_prefix_anchor(&anchor, &header, header_tag, deployment_tag, &mut record)
                != Ok(AUDIT_PREFIX_RECORD_LEN)
            || decode_audit_prefix_anchor(&record, &header, header_tag).is_err()
        {
            succeeded = false;
            break;
        }
    }
    TRACK_ALLOCATIONS.set(false);

    assert!(succeeded, "audit prefix codec failed");
    assert_eq!(ALLOCATIONS.get(), 0, "audit prefix codec allocated");
}

#[test]
fn native_replay_ingress_and_proven_send_perform_no_heap_allocations() {
    const MEASURED_RUNS: u64 = 10_000;

    let _guard = TEST_LOCK.lock().expect("allocation test lock");
    TRACK_ALLOCATIONS.set(false);
    ALLOCATIONS.set(0);

    let mut adapter = FixedNativeAdapter::default();
    let mut feed = live_native_feed(&mut adapter);
    let mut session = live_native_session(&mut adapter);
    let mut transport = FixedTransportVerifier::default();
    let mut verifier = NativeReplayVerifier::new(1).expect("native replay verifier");
    let source = native_market_source();
    let mut completed = 0_u64;
    let mut succeeded = true;

    // Iteration zero warms the exact generic decoder, journal, scheduler, encoder,
    // proof-verifier, and comparison path. Only the following iterations are counted.
    for iteration in 0..=MEASURED_RUNS {
        if iteration == 1 {
            ALLOCATIONS.set(0);
            TRACK_ALLOCATIONS.set(true);
        }

        let market_sequence = Sequence(100 + iteration);
        let market_packet = fixed_market_packet(market_sequence);
        let hardware_receive_timestamp = TimestampNs(1_000 + iteration);
        let monotonic_timestamp = MonotonicTimestampNs(1_100 + iteration);
        let source_capture_ordinal = CaptureOrdinal(iteration * 2 + 1);
        let market_metadata = NativePacketMetadata {
            frame_ordinal: verifier.next_frame_ordinal(),
            adapter_identity: NATIVE_IDENTITY,
            source,
            hardware_receive_timestamp,
            monotonic_timestamp,
            recovery: false,
        };
        let source_event = match normalize_market_data(
            VenueCaptureMetadata {
                venue: NATIVE_IDENTITY.venue,
                source,
                capture_ordinal: source_capture_ordinal,
                monotonic_timestamp,
                recovery: false,
            },
            fixed_market_message(market_sequence, hardware_receive_timestamp),
        ) {
            Ok(event) => event,
            Err(_) => {
                succeeded = false;
                break;
            }
        };
        let expected_events = [source_event];
        let market_capture = NativeIngressCapture {
            metadata: market_metadata,
            lane: NativeIngressLane::MarketData,
            packet: &market_packet,
            expected_events: &expected_events,
        };
        let mut decoded = [None; 1];
        if verifier.verify_market_data(&mut feed, &mut adapter, market_capture, &mut decoded)
            != Ok(1)
        {
            succeeded = false;
            break;
        }

        let Some(source_event_crc32c) = canonical_event_crc32c(source_event) else {
            succeeded = false;
            break;
        };
        let command = fixed_new_order(iteration);
        let commit_ordinal = iteration + 1;
        let input_ordinal = InputOrdinal(commit_ordinal);
        let egress = ReactorEgress {
            input_ordinal,
            command_index: 0,
            command,
        };
        let scheduler_commit = SchedulerCommit {
            commit_ordinal,
            route: SchedulerRoute::Normal,
            input_kind: Some(ReactorInputKind::MarketData),
            run_ordinal: Some(RunOrdinal(commit_ordinal)),
            input_ordinal: Some(input_ordinal),
            egress_input_ordinal: Some(input_ordinal),
            capture_ordinal: source_capture_ordinal,
            source_event_crc32c,
            commands: [Some(command), None],
            outstanding_transmissions: 1,
            event_retained: false,
            mandatory_kill_pending: false,
            stop: Some(ReactorStop::TransmissionBoundary {
                published: 1,
                outstanding: 1,
            }),
        };
        let venue_sequence = session.next_outbound();
        let expected_wire = expected_new_order_wire(venue_sequence, command);
        let disposition = NativeTransmissionDisposition {
            status: TransmissionStatus::Sent,
            monotonic_now: MonotonicTimestampNs(3_000 + iteration),
        };
        let transmission = TransmissionInput {
            command,
            status: disposition.status,
            monotonic_now: disposition.monotonic_now,
        };
        let transmission_event = match normalize_transmission(
            CaptureOrdinal(source_capture_ordinal.0 + 1),
            transmission,
        ) {
            Ok(event) => event,
            Err(_) => {
                succeeded = false;
                break;
            }
        };
        let frame_ordinal = verifier.next_frame_ordinal();
        let proof = FixedTransportProof {
            frame_ordinal,
            venue_sequence,
            scheduler_commit_ordinal: commit_ordinal,
            scheduler_capture_ordinal: source_capture_ordinal,
            scheduler_source_event_crc32c: source_event_crc32c,
            egress,
            encoded_bytes: expected_wire,
            disposition,
        };
        let egress_capture = NativeOrderEgressCapture {
            frame_ordinal,
            scheduler_commit_ordinal: commit_ordinal,
            scheduler_source_event: Some(source_event),
            egress,
            adapter_identity: NATIVE_IDENTITY,
            venue_sequence,
            encoded_bytes: &expected_wire,
            transmission_minimum_monotonic: transmission.monotonic_now,
            transmission_event,
        };
        let mut encoded = [0xA5_u8; 64];
        if verifier.verify_encoded_order(
            &mut session,
            &mut adapter,
            &mut transport,
            scheduler_commit,
            egress,
            &proof,
            egress_capture,
            &mut encoded,
        ) != Ok(transmission)
            || encoded[..NEW_ORDER_WIRE_LEN] != expected_wire
            || !encoded[NEW_ORDER_WIRE_LEN..].iter().all(|byte| *byte == 0)
        {
            succeeded = false;
            break;
        }
        completed += 1;
    }

    TRACK_ALLOCATIONS.set(false);
    let allocations = ALLOCATIONS.get();
    let total_runs = MEASURED_RUNS + 1;

    assert!(succeeded, "warmed native replay path failed");
    assert_eq!(allocations, 0, "native replay path allocated");
    assert_eq!(completed, total_runs);
    assert_eq!(feed.expected_sequence(), Sequence(100 + total_runs));
    assert_eq!(session.next_outbound(), Sequence(700 + total_runs));
    assert_eq!(transport.verified, total_runs);
    assert_eq!(verifier.next_frame_ordinal(), 1 + total_runs * 2);
    assert_eq!(
        verifier.last_capture_ordinal(),
        Some(CaptureOrdinal(total_runs * 2))
    );
    assert!(!verifier.failed());
}
