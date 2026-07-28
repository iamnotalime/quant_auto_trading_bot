mod support;

use quant_hft_core::adverse::AdverseConfig;
use quant_hft_core::clock::ClockSample;
use quant_hft_core::control::ConfigDigest;
use quant_hft_core::engine::TransmissionStatus;
use quant_hft_core::engine::{EngineConfig, ExecutionEngine};
use quant_hft_core::native_replay::{
    NativeIngressCapture, NativeIngressLane, NativeOrderEgressCapture, NativePacketMetadata,
    NativeReplayError, NativeReplayVerifier, NativeSnapshotContext, NativeTransmissionContext,
    NativeTransmissionDisposition, NativeTransmissionProofError, NativeTransmissionProofVerifier,
};
use quant_hft_core::reactor::{HotPathReactor, InputOrdinal, ReactorEgress, TransmissionInput};
use quant_hft_core::reactor_audit::SchedulerCommit;
use quant_hft_core::reactor_replay::dispatch_reactor_replay_event;
use quant_hft_core::risk::{
    CurrencyId, InstrumentRiskDefinition, InstrumentValuation, RiskLimits, RiskSessionId,
};
use quant_hft_core::strategy::QuotePolicyConfig;
use quant_hft_core::venue::{
    Accepted, BookDelta, ClientOrderId, DecodeResult, DirectMarketDataDecoder, InboundMessage,
    InboundPayload, MarketDataFeed, MarketDataMessage, MarketDataPayload, NativeOrderEntryDecoder,
    NativeOrderEntryEncoder, NewOrder, OrderCommand, OrderEvent, ProtocolId, SessionCommand,
    SessionEvent, SessionId, SnapshotMessage, SnapshotOrder, SnapshotPayload, TransactionalCodec,
    VenueCapabilities, VenueDescriptor, VenueIdentity, VenueOrderId, VenueSession, WireError,
};
use quant_hft_core::{
    CaptureOrdinal, EventSource, InstrumentId, MonotonicTimestampNs, NormalizedEvent, OrderId,
    PriceTicks, Quantity, Sequence, SequenceDomain, SessionEpoch, Side, SnapshotCaptureMetadata,
    SourceId, TimestampNs, VenueCaptureMetadata, VenueId, normalize_market_data,
    normalize_order_entry, normalize_snapshot, normalize_transmission,
};

const IDENTITY: VenueIdentity = VenueIdentity {
    venue: VenueId(7),
    market_data_protocol: ProtocolId(101),
    order_entry_protocol: ProtocolId(202),
    session: SessionId(303),
};

const CAPABILITIES: VenueCapabilities = VenueCapabilities::MARKET_DATA_L3
    .union(VenueCapabilities::NEW_ORDER)
    .union(VenueCapabilities::SNAPSHOT_RECOVERY);

const MARKET_RECORD_LEN: usize = 46;
const MARKET_PACKET_LEN: usize = 1 + 2 * MARKET_RECORD_LEN;
const ORDER_ENTRY_RECORD_LEN: usize = 49;
const ORDER_ENTRY_PACKET_LEN: usize = 1 + 2 * ORDER_ENTRY_RECORD_LEN;
const NEW_ORDER_WIRE_LEN: usize = 47;

type CompositionEngine = ExecutionEngine<64, 16, 8, 16, 16>;
type CompositionReactor = HotPathReactor<64, 16, 8, 16, 16>;

#[derive(Debug, Default)]
struct FakeNativeAdapter {
    codec_state: u64,
    durable_commits: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FakeProofMode {
    Accept,
    Reject,
    Ambiguous,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FakeTransmissionProof {
    frame_ordinal: u64,
    adapter_identity: VenueIdentity,
    venue_sequence: Sequence,
    scheduler_commit_ordinal: u64,
    scheduler_capture_ordinal: CaptureOrdinal,
    scheduler_source_event_crc32c: u32,
    egress: ReactorEgress,
    encoded_bytes: [u8; 64],
    encoded_len: usize,
    disposition: NativeTransmissionDisposition,
    mode: FakeProofMode,
}

#[derive(Debug, Default, Eq, PartialEq)]
struct FakeTransportVerifier {
    calls: u64,
    commits: u64,
}

impl NativeTransmissionProofVerifier for FakeTransportVerifier {
    type Proof = FakeTransmissionProof;
    type Checkpoint = (u64, u64);

    fn checkpoint(&self) -> Self::Checkpoint {
        (self.calls, self.commits)
    }

    fn restore(&mut self, checkpoint: Self::Checkpoint) {
        (self.calls, self.commits) = checkpoint;
    }

    fn commit(&mut self, _checkpoint: Self::Checkpoint) {
        self.commits = self.commits.checked_add(1).expect("bounded test commits");
    }

    fn verify(
        &mut self,
        context: NativeTransmissionContext<'_>,
        proof: &Self::Proof,
    ) -> Result<NativeTransmissionDisposition, NativeTransmissionProofError> {
        self.calls = self.calls.checked_add(1).expect("bounded test calls");
        if context.frame_ordinal != proof.frame_ordinal
            || context.adapter_identity != proof.adapter_identity
            || context.venue_sequence != proof.venue_sequence
            || context.scheduler_commit_ordinal != proof.scheduler_commit_ordinal
            || context.scheduler_capture_ordinal != proof.scheduler_capture_ordinal
            || context.scheduler_source_event_crc32c != proof.scheduler_source_event_crc32c
            || context.egress != proof.egress
            || context.encoded_bytes != &proof.encoded_bytes[..proof.encoded_len]
        {
            return Err(NativeTransmissionProofError::Rejected);
        }
        match proof.mode {
            FakeProofMode::Accept => Ok(proof.disposition),
            FakeProofMode::Reject => Err(NativeTransmissionProofError::Rejected),
            FakeProofMode::Ambiguous => Err(NativeTransmissionProofError::Ambiguous),
        }
    }
}

impl VenueDescriptor for FakeNativeAdapter {
    const IDENTITY: VenueIdentity = IDENTITY;
    const CAPABILITIES: VenueCapabilities = CAPABILITIES;
}

impl TransactionalCodec for FakeNativeAdapter {
    type Checkpoint = (u64, u64);

    fn checkpoint(&self) -> Self::Checkpoint {
        (self.codec_state, self.durable_commits)
    }

    fn restore(&mut self, checkpoint: Self::Checkpoint) {
        (self.codec_state, self.durable_commits) = checkpoint;
    }

    fn commit(&mut self, _checkpoint: Self::Checkpoint) {
        self.durable_commits = self
            .durable_commits
            .checked_add(1)
            .expect("bounded nested test commits");
    }
}

impl DirectMarketDataDecoder for FakeNativeAdapter {
    fn decode_market_data(
        &mut self,
        packet: &[u8],
        hardware_receive_timestamp: TimestampNs,
        output: &mut [Option<MarketDataMessage>],
    ) -> Result<DecodeResult, WireError> {
        self.codec_state = self.codec_state.wrapping_add(1);
        let messages = usize::from(*packet.first().ok_or(WireError::MalformedPacket)?);
        require_slots(output.len(), messages)?;
        let consumed_bytes = 1_usize
            .checked_add(
                messages
                    .checked_mul(MARKET_RECORD_LEN)
                    .ok_or(WireError::MalformedPacket)?,
            )
            .ok_or(WireError::MalformedPacket)?;
        if packet.len() < consumed_bytes {
            return Err(WireError::MalformedPacket);
        }
        for (index, slot) in output.iter_mut().take(messages).enumerate() {
            let offset = 1 + index * MARKET_RECORD_LEN;
            let payload = match packet[offset] {
                0x40 => {
                    let side = match packet[offset + 29] {
                        value if value == Side::Buy as u8 => Side::Buy,
                        value if value == Side::Sell as u8 => Side::Sell,
                        _ => return Err(WireError::InvalidField),
                    };
                    MarketDataPayload::Book(BookDelta::Add {
                        order_id: quant_hft_core::MarketByOrderId(read_u64(packet, offset + 21)?),
                        side,
                        price: PriceTicks(read_i64(packet, offset + 30)?),
                        quantity: Quantity(read_i64(packet, offset + 38)?),
                    })
                }
                0x41 => MarketDataPayload::TradingStatus {
                    status_code: u16::from(packet[offset + 21]),
                },
                kind => {
                    return Err(WireError::UnsupportedMessage {
                        message_type: u16::from(kind),
                    });
                }
            };
            *slot = Some(MarketDataMessage {
                sequence: Sequence(read_u64(packet, offset + 1)?),
                exchange_timestamp: TimestampNs(read_u64(packet, offset + 9)?),
                hardware_receive_timestamp,
                instrument: InstrumentId(read_u32(packet, offset + 17)?),
                payload,
            });
        }
        Ok(DecodeResult {
            messages,
            consumed_bytes,
        })
    }

    fn decode_snapshot(
        &mut self,
        packet: &[u8],
        hardware_receive_timestamp: TimestampNs,
        output: &mut [Option<SnapshotMessage>],
    ) -> Result<DecodeResult, WireError> {
        self.codec_state = self.codec_state.wrapping_add(1);
        require_slots(output.len(), 1)?;
        if packet.len() < 25 {
            return Err(WireError::MalformedPacket);
        }
        let snapshot_id = read_u64(packet, 9)?;
        let last_incremental_sequence = Sequence(read_u64(packet, 17)?);
        let payload = match packet[0] {
            0x50 => SnapshotPayload::Begin {
                snapshot_id,
                last_incremental_sequence,
            },
            0x52 => SnapshotPayload::End {
                snapshot_id,
                last_incremental_sequence,
            },
            _ => return Err(WireError::MalformedPacket),
        };
        output[0] = Some(SnapshotMessage {
            exchange_timestamp: TimestampNs(read_u64(packet, 1)?),
            hardware_receive_timestamp,
            payload,
        });
        Ok(DecodeResult {
            messages: 1,
            consumed_bytes: 25,
        })
    }
}

impl NativeOrderEntryDecoder for FakeNativeAdapter {
    fn decode_order_entry(
        &mut self,
        packet: &[u8],
        hardware_receive_timestamp: TimestampNs,
        output: &mut [Option<InboundMessage>],
    ) -> Result<DecodeResult, WireError> {
        self.codec_state = self.codec_state.wrapping_add(1);
        let messages = usize::from(*packet.first().ok_or(WireError::MalformedPacket)?);
        require_slots(output.len(), messages)?;
        let consumed_bytes = 1_usize
            .checked_add(
                messages
                    .checked_mul(ORDER_ENTRY_RECORD_LEN)
                    .ok_or(WireError::MalformedPacket)?,
            )
            .ok_or(WireError::MalformedPacket)?;
        if packet.len() < consumed_bytes {
            return Err(WireError::MalformedPacket);
        }
        for (index, slot) in output.iter_mut().take(messages).enumerate() {
            let offset = 1 + index * ORDER_ENTRY_RECORD_LEN;
            let payload = match packet[offset] {
                1 => InboundPayload::Session(SessionEvent::LogonAccepted),
                4 => InboundPayload::Order(OrderEvent::Accepted(Accepted {
                    client_order_id: ClientOrderId(read_u64(packet, offset + 17)?),
                    venue_order_id: VenueOrderId(read_u64(packet, offset + 25)?),
                    price: PriceTicks(read_i64(packet, offset + 33)?),
                    quantity: Quantity(read_i64(packet, offset + 41)?),
                })),
                kind => {
                    return Err(WireError::UnsupportedMessage {
                        message_type: u16::from(kind),
                    });
                }
            };
            *slot = Some(InboundMessage {
                sequence: Sequence(read_u64(packet, offset + 1)?),
                exchange_timestamp: TimestampNs(read_u64(packet, offset + 9)?),
                hardware_receive_timestamp,
                payload,
            });
        }
        Ok(DecodeResult {
            messages,
            consumed_bytes,
        })
    }
}

impl NativeOrderEntryEncoder for FakeNativeAdapter {
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
        self.codec_state = self.codec_state.wrapping_add(1);
        let OrderCommand::New(order) = command else {
            return Err(WireError::UnsupportedMessage { message_type: 0 });
        };
        if output.len() < NEW_ORDER_WIRE_LEN {
            return Err(WireError::BufferTooSmall {
                required: NEW_ORDER_WIRE_LEN,
                provided: output.len(),
            });
        }
        write_new_order_wire(output, sequence, order);
        Ok(NEW_ORDER_WIRE_LEN)
    }
}

#[test]
fn market_data_multi_message_frame_is_exact_and_fully_consumed() {
    let mut adapter = FakeNativeAdapter::default();
    let mut feed = live_feed(&mut adapter, Sequence(100));
    let packet = market_packet();
    let hardware_receive_timestamp = TimestampNs(1_000);
    let messages = market_messages(hardware_receive_timestamp);
    let metadata = NativePacketMetadata {
        frame_ordinal: 1,
        adapter_identity: IDENTITY,
        source: market_source(),
        hardware_receive_timestamp,
        monotonic_timestamp: MonotonicTimestampNs(1_010),
        recovery: false,
    };
    let expected = normalized_market_events(metadata, messages);
    let capture = NativeIngressCapture {
        metadata,
        lane: NativeIngressLane::MarketData,
        packet: &packet,
        expected_events: &expected,
    };
    let mut decoded = [None; 2];
    let mut verifier = NativeReplayVerifier::new(1).unwrap();

    assert_eq!(
        verifier.verify_market_data(&mut feed, &mut adapter, capture, &mut decoded),
        Ok(2)
    );
    assert_eq!(decoded, messages.map(Some));
    assert_eq!(feed.expected_sequence(), Sequence(102));
    assert_eq!(verifier.next_frame_ordinal(), 2);
    assert!(!verifier.failed());
}

#[test]
fn order_entry_multi_message_frame_is_exact_and_fully_consumed() {
    let mut adapter = FakeNativeAdapter::default();
    let mut session = VenueSession::new::<FakeNativeAdapter>(
        Sequence(500),
        Sequence(20),
        10_000,
        support::instrument_definition(IDENTITY.venue, InstrumentId(9)),
    )
    .unwrap();
    session.connect(TimestampNs(100)).unwrap();
    let packet = order_entry_packet(20);
    let hardware_receive_timestamp = TimestampNs(200);
    let messages = order_entry_messages(20, hardware_receive_timestamp);
    let metadata = NativePacketMetadata {
        frame_ordinal: 7,
        adapter_identity: IDENTITY,
        source: order_entry_source(),
        hardware_receive_timestamp,
        monotonic_timestamp: MonotonicTimestampNs(210),
        recovery: false,
    };
    let expected = normalized_order_entry_events(metadata, messages);
    let capture = NativeIngressCapture {
        metadata,
        lane: NativeIngressLane::OrderEntry,
        packet: &packet,
        expected_events: &expected,
    };
    let mut decoded = [None; 2];
    let mut verifier = NativeReplayVerifier::new(7).unwrap();

    assert_eq!(
        verifier.verify_order_entry(&mut session, &mut adapter, capture, &mut decoded),
        Ok(2)
    );
    assert_eq!(decoded, messages.map(Some));
    assert_eq!(session.expected_inbound(), Sequence(22));
    assert_eq!(verifier.next_frame_ordinal(), 8);
    assert!(!verifier.failed());
}

#[test]
fn snapshot_context_spans_frames_and_mismatch_rolls_back_exactly() {
    let begin_message = SnapshotMessage {
        exchange_timestamp: TimestampNs(100),
        hardware_receive_timestamp: TimestampNs(101),
        payload: SnapshotPayload::Begin {
            snapshot_id: 77,
            last_incremental_sequence: Sequence(99),
        },
    };
    let end_message = SnapshotMessage {
        exchange_timestamp: TimestampNs(110),
        hardware_receive_timestamp: TimestampNs(111),
        payload: SnapshotPayload::End {
            snapshot_id: 77,
            last_incremental_sequence: Sequence(99),
        },
    };
    let begin_metadata = NativePacketMetadata {
        frame_ordinal: 1,
        adapter_identity: IDENTITY,
        source: market_source(),
        hardware_receive_timestamp: begin_message.hardware_receive_timestamp,
        monotonic_timestamp: MonotonicTimestampNs(102),
        recovery: true,
    };
    let end_metadata = NativePacketMetadata {
        frame_ordinal: 2,
        adapter_identity: IDENTITY,
        source: market_source(),
        hardware_receive_timestamp: end_message.hardware_receive_timestamp,
        monotonic_timestamp: MonotonicTimestampNs(112),
        recovery: true,
    };
    let begin_event = normalize_snapshot(
        SnapshotCaptureMetadata {
            venue: venue_metadata(begin_metadata, CaptureOrdinal(1)),
            snapshot_id: 77,
            last_incremental_sequence: Sequence(99),
        },
        begin_message,
    )
    .unwrap();
    let end_event = normalize_snapshot(
        SnapshotCaptureMetadata {
            venue: venue_metadata(end_metadata, CaptureOrdinal(2)),
            snapshot_id: 77,
            last_incremental_sequence: Sequence(99),
        },
        end_message,
    )
    .unwrap();
    let begin_packet = snapshot_packet(0x50, 77, Sequence(99), TimestampNs(100));
    let end_packet = snapshot_packet(0x52, 77, Sequence(99), TimestampNs(110));

    let mut adapter = FakeNativeAdapter::default();
    let mut feed = MarketDataFeed::new::<FakeNativeAdapter>(Sequence(100)).unwrap();
    feed.connect().unwrap();
    feed.begin_snapshot().unwrap();
    let mut context = NativeSnapshotContext::new();
    let mut verifier = NativeReplayVerifier::new(1).unwrap();
    let mut decoded = [Some(begin_message)];
    assert_eq!(
        verifier.verify_snapshot(
            &mut feed,
            &mut adapter,
            &mut context,
            NativeIngressCapture {
                metadata: begin_metadata,
                lane: NativeIngressLane::Snapshot,
                packet: &begin_packet,
                expected_events: &[begin_event],
            },
            &mut decoded,
        ),
        Ok(1)
    );
    assert!(context.is_active());
    assert_eq!(context.active_snapshot_id(), Some(77));
    assert_eq!(context.last_incremental_sequence(), Some(Sequence(99)));

    assert_eq!(
        verifier.verify_snapshot(
            &mut feed,
            &mut adapter,
            &mut context,
            NativeIngressCapture {
                metadata: end_metadata,
                lane: NativeIngressLane::Snapshot,
                packet: &end_packet,
                expected_events: &[end_event],
            },
            &mut decoded,
        ),
        Ok(1)
    );
    assert!(!context.is_active());
    assert_eq!(context.active_snapshot_id(), None);
    assert_eq!(feed.snapshot_apply_token().unwrap().snapshot_id(), 77);
    assert_eq!(verifier.next_frame_ordinal(), 3);
    assert_eq!(verifier.finish_corpus(), Ok(()));

    let mut rejected_adapter = FakeNativeAdapter::default();
    let mut rejected_feed = MarketDataFeed::new::<FakeNativeAdapter>(Sequence(100)).unwrap();
    rejected_feed.connect().unwrap();
    rejected_feed.begin_snapshot().unwrap();
    let mut rejected_context = NativeSnapshotContext::new();
    let mut rejected_verifier = NativeReplayVerifier::new(1).unwrap();
    rejected_verifier
        .verify_snapshot(
            &mut rejected_feed,
            &mut rejected_adapter,
            &mut rejected_context,
            NativeIngressCapture {
                metadata: begin_metadata,
                lane: NativeIngressLane::Snapshot,
                packet: &begin_packet,
                expected_events: &[begin_event],
            },
            &mut [None; 1],
        )
        .unwrap();
    let adapter_after_begin = rejected_adapter.checkpoint();
    let wrong_end_message = SnapshotMessage {
        payload: SnapshotPayload::End {
            snapshot_id: 78,
            last_incremental_sequence: Sequence(99),
        },
        ..end_message
    };
    let wrong_end_event = normalize_snapshot(
        SnapshotCaptureMetadata {
            venue: venue_metadata(end_metadata, CaptureOrdinal(2)),
            snapshot_id: 78,
            last_incremental_sequence: Sequence(99),
        },
        wrong_end_message,
    )
    .unwrap();
    let wrong_end_packet = snapshot_packet(0x52, 78, Sequence(99), TimestampNs(110));
    let mut rejected_decoded = [Some(wrong_end_message)];
    assert!(
        rejected_verifier
            .verify_snapshot(
                &mut rejected_feed,
                &mut rejected_adapter,
                &mut rejected_context,
                NativeIngressCapture {
                    metadata: end_metadata,
                    lane: NativeIngressLane::Snapshot,
                    packet: &wrong_end_packet,
                    expected_events: &[wrong_end_event],
                },
                &mut rejected_decoded,
            )
            .is_err()
    );
    assert!(rejected_verifier.failed());
    assert_eq!(rejected_verifier.next_frame_ordinal(), 2);
    assert!(rejected_context.is_active());
    assert_eq!(rejected_context.active_snapshot_id(), Some(77));
    assert_eq!(rejected_adapter.checkpoint(), adapter_after_begin);
    assert!(rejected_decoded.iter().all(Option::is_none));
    assert_eq!(rejected_feed.snapshot_apply_token(), None);
}

#[test]
fn encoded_order_is_byte_exact_and_linked_to_egress_and_transmission() {
    let (mut session, mut adapter) = live_session(700);
    let (scheduler_commit, scheduler_source_event, egress_records) = linked_quote_commit(91);
    let egress = egress_records[0];
    let expected_wire = expected_new_order_wire(Sequence(700), egress.command);
    let transmission = TransmissionInput {
        command: egress.command,
        status: TransmissionStatus::Sent,
        monotonic_now: MonotonicTimestampNs(410),
    };
    let capture = egress_capture(
        1,
        91,
        scheduler_commit,
        scheduler_source_event,
        Sequence(700),
        egress,
        &expected_wire,
        transmission,
    );
    let proof = fake_transport_proof(
        1,
        Sequence(700),
        scheduler_commit,
        egress,
        &expected_wire,
        transmission.status,
        transmission.monotonic_now,
        FakeProofMode::Accept,
    );
    let mut encoded = [0xA5; 64];
    let mut verifier = NativeReplayVerifier::new(1).unwrap();
    let mut transport = FakeTransportVerifier::default();

    assert_eq!(
        verifier.verify_encoded_order(
            &mut session,
            &mut adapter,
            &mut transport,
            scheduler_commit,
            egress,
            &proof,
            capture,
            &mut encoded,
        ),
        Ok(transmission)
    );
    assert_eq!(&encoded[..NEW_ORDER_WIRE_LEN], &expected_wire);
    assert!(encoded[NEW_ORDER_WIRE_LEN..].iter().all(|byte| *byte == 0));
    assert_eq!(session.next_outbound(), Sequence(701));
    assert_eq!(transport.calls, 1);
    assert_eq!(transport.commits, 1);
    assert_eq!(verifier.next_frame_ordinal(), 2);
    assert!(!verifier.failed());
}

#[test]
fn raw_frame_composes_through_actual_reactor_native_encode_and_sent_feedback() {
    let hardware_receive_timestamp = TimestampNs(1_090);
    let messages = composition_market_messages(hardware_receive_timestamp);
    let packet = composition_market_packet(messages);
    let metadata = NativePacketMetadata {
        frame_ordinal: 1,
        adapter_identity: IDENTITY,
        source: market_source(),
        hardware_receive_timestamp,
        monotonic_timestamp: MonotonicTimestampNs(1_100),
        recovery: false,
    };
    let expected_events = normalized_market_events(metadata, messages);
    let capture = NativeIngressCapture {
        metadata,
        lane: NativeIngressLane::MarketData,
        packet: &packet,
        expected_events: &expected_events,
    };
    let mut market_adapter = FakeNativeAdapter::default();
    let mut feed = live_feed(&mut market_adapter, Sequence(100));
    let mut decoded = [None; 2];
    let mut verifier = NativeReplayVerifier::new(1).unwrap();

    assert_eq!(
        verifier.verify_market_data(&mut feed, &mut market_adapter, capture, &mut decoded,),
        Ok(2)
    );
    assert_eq!(decoded, messages.map(Some));

    let mut reactor = CompositionReactor::new(composition_ready_engine());
    let mut quote_egress = [None; 2];
    let mut quote_commit = None;
    for (index, event) in expected_events.into_iter().enumerate() {
        let mut egress = [None; 2];
        let outcome = dispatch_reactor_replay_event(&mut reactor, event, &mut egress).unwrap();
        let commit_ordinal = u64::try_from(index + 1).unwrap();
        let commit =
            SchedulerCommit::from_replay_outcome(commit_ordinal, event, outcome, &egress).unwrap();
        commit.verify_source(event).unwrap();
        if index == 0 {
            assert_eq!(outcome.commands, 0);
            assert!(egress.iter().all(Option::is_none));
        } else {
            assert_eq!(outcome.commands, 2);
            quote_egress = egress;
            quote_commit = Some(commit);
        }
    }
    let quote_commit = quote_commit.unwrap();
    assert_eq!(quote_commit.commit_ordinal, 2);
    assert_eq!(reactor.outstanding_transmissions(), 2);
    for (index, item) in quote_egress.iter().flatten().enumerate() {
        assert_eq!(item.input_ordinal, InputOrdinal(2));
        assert_eq!(usize::from(item.command_index), index);
        assert!(matches!(item.command, OrderCommand::New(_)));
    }

    let (mut session, mut order_adapter) = live_session(700);
    let mut transport = FakeTransportVerifier::default();
    for (index, egress) in quote_egress.into_iter().map(Option::unwrap).enumerate() {
        let offset = u64::try_from(index).unwrap();
        let sequence = Sequence(700 + offset);
        let expected_wire = expected_new_order_wire(sequence, egress.command);
        let transmission = TransmissionInput {
            command: egress.command,
            status: TransmissionStatus::Sent,
            monotonic_now: MonotonicTimestampNs(1_110 + offset),
        };
        let transmission_event =
            normalize_transmission(CaptureOrdinal(3 + offset), transmission).unwrap();
        let egress_capture = NativeOrderEgressCapture {
            frame_ordinal: 2 + offset,
            scheduler_commit_ordinal: quote_commit.commit_ordinal,
            scheduler_source_event: Some(expected_events[1]),
            egress,
            adapter_identity: IDENTITY,
            venue_sequence: sequence,
            encoded_bytes: &expected_wire,
            transmission_minimum_monotonic: transmission.monotonic_now,
            transmission_event,
        };
        let proof = fake_transport_proof(
            2 + offset,
            sequence,
            quote_commit,
            egress,
            &expected_wire,
            transmission.status,
            transmission.monotonic_now,
            FakeProofMode::Accept,
        );
        let mut encoded = [0xA5; 64];
        let replayed_transmission = verifier
            .verify_encoded_order(
                &mut session,
                &mut order_adapter,
                &mut transport,
                quote_commit,
                egress,
                &proof,
                egress_capture,
                &mut encoded,
            )
            .unwrap();
        assert_eq!(replayed_transmission, transmission);
        assert_eq!(&encoded[..NEW_ORDER_WIRE_LEN], &expected_wire);

        let outcome =
            dispatch_reactor_replay_event(&mut reactor, transmission_event, &mut [None; 2])
                .unwrap();
        assert_eq!(outcome.commands, 0);
    }

    assert_eq!(reactor.outstanding_transmissions(), 0);
    assert_eq!(session.next_outbound(), Sequence(702));
    assert_eq!(transport.calls, 2);
    assert_eq!(transport.commits, 2);
    assert_eq!(verifier.next_frame_ordinal(), 4);
    assert!(!verifier.failed());
}

#[test]
fn proven_unsent_proof_restores_encoder_state_and_consumes_exact_slot() {
    let (scheduler_commit, scheduler_source_event, egress) = linked_quote_commit(130);
    let (mut session, mut adapter) = live_session(1_100);
    let adapter_before = adapter.checkpoint();
    let mut transport = FakeTransportVerifier::default();
    let mut verifier = NativeReplayVerifier::new(1).unwrap();
    let mut encoded = [0xA5; 64];

    let transmission = verify_quote_slot(
        &mut verifier,
        &mut session,
        &mut adapter,
        &mut transport,
        scheduler_commit,
        scheduler_source_event,
        egress[0],
        1,
        3,
        Sequence(1_100),
        TransmissionStatus::ProvenUnsent,
        MonotonicTimestampNs(1_120),
        FakeProofMode::Accept,
        &mut encoded,
    )
    .unwrap();

    assert_eq!(transmission.status, TransmissionStatus::ProvenUnsent);
    assert_eq!(session.next_outbound(), Sequence(1_100));
    assert_eq!(adapter.checkpoint(), adapter_before);
    assert!(encoded.iter().all(|byte| *byte == 0));
    assert_eq!(transport.calls, 1);
    assert_eq!(transport.commits, 1);
    assert_eq!(verifier.next_frame_ordinal(), 2);
    assert_eq!(verifier.last_capture_ordinal(), Some(CaptureOrdinal(3)));
}

#[test]
fn rejected_and_ambiguous_transport_proofs_rollback_every_mutable_boundary() {
    for (mode, proof_error) in [
        (
            FakeProofMode::Reject,
            NativeTransmissionProofError::Rejected,
        ),
        (
            FakeProofMode::Ambiguous,
            NativeTransmissionProofError::Ambiguous,
        ),
    ] {
        let (scheduler_commit, scheduler_source_event, egress) = linked_quote_commit(140);
        let (mut session, mut adapter) = live_session(1_200);
        let adapter_before = adapter.checkpoint();
        let mut transport = FakeTransportVerifier::default();
        let mut verifier = NativeReplayVerifier::new(1).unwrap();
        let mut encoded = [0xA5; 64];

        assert_eq!(
            verify_quote_slot(
                &mut verifier,
                &mut session,
                &mut adapter,
                &mut transport,
                scheduler_commit,
                scheduler_source_event,
                egress[0],
                1,
                3,
                Sequence(1_200),
                TransmissionStatus::Sent,
                MonotonicTimestampNs(1_220),
                mode,
                &mut encoded,
            ),
            Err(NativeReplayError::TransmissionProof(proof_error))
        );
        assert!(verifier.failed());
        assert_eq!(verifier.next_frame_ordinal(), 1);
        assert_eq!(verifier.last_capture_ordinal(), None);
        assert_eq!(session.next_outbound(), Sequence(1_200));
        assert_eq!(adapter.checkpoint(), adapter_before);
        assert_eq!(transport, FakeTransportVerifier::default());
        assert!(encoded.iter().all(|byte| *byte == 0));
    }
}

#[test]
fn scheduler_command_slots_are_ordered_unique_immutable_and_complete() {
    {
        let (commit, source, egress) = linked_quote_commit(150);
        let (mut session, mut adapter) = live_session(1_300);
        let mut transport = FakeTransportVerifier::default();
        let mut verifier = NativeReplayVerifier::new(1).unwrap();
        let mut encoded = [0xA5; 64];
        assert_eq!(
            verify_quote_slot(
                &mut verifier,
                &mut session,
                &mut adapter,
                &mut transport,
                commit,
                source,
                egress[1],
                1,
                3,
                Sequence(1_300),
                TransmissionStatus::Sent,
                MonotonicTimestampNs(1_310),
                FakeProofMode::Accept,
                &mut encoded,
            ),
            Err(NativeReplayError::OrphanSchedulerCommand {
                commit_ordinal: 150,
                command_index: 1,
            })
        );
        assert_eq!(session.next_outbound(), Sequence(1_300));
        assert_eq!(transport, FakeTransportVerifier::default());
        assert!(encoded.iter().all(|byte| *byte == 0));
    }

    {
        let (commit, source, egress) = linked_quote_commit(151);
        let (mut session, mut adapter) = live_session(1_400);
        let mut transport = FakeTransportVerifier::default();
        let mut verifier = NativeReplayVerifier::new(1).unwrap();
        let mut encoded = [0_u8; 64];
        verify_quote_slot(
            &mut verifier,
            &mut session,
            &mut adapter,
            &mut transport,
            commit,
            source,
            egress[0],
            1,
            3,
            Sequence(1_400),
            TransmissionStatus::Sent,
            MonotonicTimestampNs(1_410),
            FakeProofMode::Accept,
            &mut encoded,
        )
        .unwrap();
        let adapter_after_first = adapter.codec_state;
        encoded.fill(0xA5);
        assert_eq!(
            verify_quote_slot(
                &mut verifier,
                &mut session,
                &mut adapter,
                &mut transport,
                commit,
                source,
                egress[0],
                2,
                4,
                Sequence(1_401),
                TransmissionStatus::Sent,
                MonotonicTimestampNs(1_411),
                FakeProofMode::Accept,
                &mut encoded,
            ),
            Err(NativeReplayError::SchedulerCommandIndexMismatch {
                expected: 1,
                received: 0,
            })
        );
        assert_eq!(session.next_outbound(), Sequence(1_401));
        assert_eq!(adapter.codec_state, adapter_after_first);
        assert_eq!(transport.calls, 1);
        assert_eq!(transport.commits, 1);
        assert!(encoded.iter().all(|byte| *byte == 0));
    }

    {
        let (commit, source, egress) = linked_quote_commit(152);
        let (mut session, mut adapter) = live_session(1_500);
        let mut transport = FakeTransportVerifier::default();
        let mut verifier = NativeReplayVerifier::new(1).unwrap();
        let mut encoded = [0_u8; 64];
        verify_quote_slot(
            &mut verifier,
            &mut session,
            &mut adapter,
            &mut transport,
            commit,
            source,
            egress[0],
            1,
            3,
            Sequence(1_500),
            TransmissionStatus::Sent,
            MonotonicTimestampNs(1_510),
            FakeProofMode::Accept,
            &mut encoded,
        )
        .unwrap();

        let mut mutated = commit;
        mutated.commands[1] = mutated.commands[0];
        let mutated_egress = ReactorEgress {
            command: mutated.commands[1].unwrap(),
            ..egress[1]
        };
        encoded.fill(0xA5);
        assert_eq!(
            verify_quote_slot(
                &mut verifier,
                &mut session,
                &mut adapter,
                &mut transport,
                mutated,
                source,
                mutated_egress,
                2,
                4,
                Sequence(1_501),
                TransmissionStatus::Sent,
                MonotonicTimestampNs(1_511),
                FakeProofMode::Accept,
                &mut encoded,
            ),
            Err(NativeReplayError::SchedulerCommitMutation(152))
        );
        assert_eq!(session.next_outbound(), Sequence(1_501));
        assert!(encoded.iter().all(|byte| *byte == 0));
    }

    {
        let (commit, source, egress) = linked_quote_commit(153);
        let (mut session, mut adapter) = live_session(1_600);
        let mut transport = FakeTransportVerifier::default();
        let mut verifier = NativeReplayVerifier::new(1).unwrap();
        verify_quote_slot(
            &mut verifier,
            &mut session,
            &mut adapter,
            &mut transport,
            commit,
            source,
            egress[0],
            1,
            3,
            Sequence(1_600),
            TransmissionStatus::Sent,
            MonotonicTimestampNs(1_610),
            FakeProofMode::Accept,
            &mut [0_u8; 64],
        )
        .unwrap();
        assert_eq!(
            verifier.finish_corpus(),
            Err(NativeReplayError::IncompleteSchedulerCommit {
                commit_ordinal: 153,
                next_command_index: 1,
            })
        );
        assert!(!verifier.corpus_finished());
        assert_eq!(verifier.finish_corpus(), Err(NativeReplayError::Failed));
    }

    {
        let (commit, source, egress) = linked_quote_commit(154);
        let (mut session, mut adapter) = live_session(1_700);
        let mut transport = FakeTransportVerifier::default();
        let mut verifier = NativeReplayVerifier::new(1).unwrap();
        for (index, item) in egress.into_iter().enumerate() {
            let offset = u64::try_from(index).unwrap();
            verify_quote_slot(
                &mut verifier,
                &mut session,
                &mut adapter,
                &mut transport,
                commit,
                source,
                item,
                1 + offset,
                3 + offset,
                Sequence(1_700 + offset),
                TransmissionStatus::Sent,
                MonotonicTimestampNs(1_710 + offset),
                FakeProofMode::Accept,
                &mut [0_u8; 64],
            )
            .unwrap();
        }
        let session_before_finish = session;
        let adapter_before_finish = adapter.checkpoint();
        let transport_before_finish = (transport.calls, transport.commits);
        assert_eq!(verifier.finish_corpus(), Ok(()));
        assert!(verifier.corpus_finished());
        let mut encoded = [0xA5; 64];
        assert_eq!(
            verify_quote_slot(
                &mut verifier,
                &mut session,
                &mut adapter,
                &mut transport,
                commit,
                source,
                egress[0],
                3,
                5,
                Sequence(1_702),
                TransmissionStatus::Sent,
                MonotonicTimestampNs(1_712),
                FakeProofMode::Accept,
                &mut encoded,
            ),
            Err(NativeReplayError::CorpusFinished)
        );
        assert!(verifier.failed());
        assert!(verifier.corpus_finished());
        assert_eq!(session, session_before_finish);
        assert_eq!(adapter.checkpoint(), adapter_before_finish);
        assert_eq!(
            (transport.calls, transport.commits),
            transport_before_finish
        );
        assert!(encoded.iter().all(|byte| *byte == 0));
        assert_eq!(verifier.finish_corpus(), Err(NativeReplayError::Failed));
    }

    {
        let (commit, source, egress) = linked_quote_commit(155);
        let (mut session, mut adapter) = live_session(1_800);
        let mut transport = FakeTransportVerifier::default();
        let mut verifier = NativeReplayVerifier::new(1).unwrap();
        for (index, item) in egress.into_iter().enumerate() {
            let offset = u64::try_from(index).unwrap();
            verify_quote_slot(
                &mut verifier,
                &mut session,
                &mut adapter,
                &mut transport,
                commit,
                source,
                item,
                1 + offset,
                3 + offset,
                Sequence(1_800 + offset),
                TransmissionStatus::Sent,
                MonotonicTimestampNs(1_810 + offset),
                FakeProofMode::Accept,
                &mut [0_u8; 64],
            )
            .unwrap();
        }
        let mut encoded = [0xA5; 64];
        assert_eq!(
            verify_quote_slot(
                &mut verifier,
                &mut session,
                &mut adapter,
                &mut transport,
                commit,
                source,
                egress[0],
                3,
                5,
                Sequence(1_802),
                TransmissionStatus::Sent,
                MonotonicTimestampNs(1_812),
                FakeProofMode::Accept,
                &mut encoded,
            ),
            Err(NativeReplayError::SchedulerCommitRegression {
                previous: 155,
                received: 155,
            })
        );
        assert!(encoded.iter().all(|byte| *byte == 0));
    }
}

#[test]
fn capture_ordinals_are_gapless_and_scheduler_sources_strictly_precede_feedback() {
    {
        let mut adapter = FakeNativeAdapter::default();
        let mut feed = live_feed(&mut adapter, Sequence(100));
        let adapter_before = adapter.codec_state;
        let packet = market_packet();
        let messages = market_messages(TimestampNs(1_000));
        let metadata = NativePacketMetadata {
            frame_ordinal: 1,
            adapter_identity: IDENTITY,
            source: market_source(),
            hardware_receive_timestamp: TimestampNs(1_000),
            monotonic_timestamp: MonotonicTimestampNs(1_010),
            recovery: false,
        };
        let mut expected = normalized_market_events(metadata, messages);
        expected[1].capture_ordinal = CaptureOrdinal(1);
        let capture = NativeIngressCapture {
            metadata,
            lane: NativeIngressLane::MarketData,
            packet: &packet,
            expected_events: &expected,
        };
        let mut decoded = messages.map(Some);
        let mut verifier = NativeReplayVerifier::new(1).unwrap();
        assert_eq!(
            verifier.verify_market_data(&mut feed, &mut adapter, capture, &mut decoded),
            Err(NativeReplayError::CaptureOrdinalNotContiguous {
                expected: CaptureOrdinal(2),
                received: CaptureOrdinal(1),
            })
        );
        assert_eq!(feed.expected_sequence(), Sequence(100));
        assert_eq!(adapter.codec_state, adapter_before);
        assert!(decoded.iter().all(Option::is_none));
    }

    {
        let mut adapter = FakeNativeAdapter::default();
        let mut feed = live_feed(&mut adapter, Sequence(100));
        let packet = market_packet();
        let messages = market_messages(TimestampNs(1_000));
        let mut metadata = NativePacketMetadata {
            frame_ordinal: 1,
            adapter_identity: IDENTITY,
            source: market_source(),
            hardware_receive_timestamp: TimestampNs(1_000),
            monotonic_timestamp: MonotonicTimestampNs(1_010),
            recovery: false,
        };
        let expected = normalized_market_events(metadata, messages);
        let mut verifier = NativeReplayVerifier::new(1).unwrap();
        verifier
            .verify_market_data(
                &mut feed,
                &mut adapter,
                NativeIngressCapture {
                    metadata,
                    lane: NativeIngressLane::MarketData,
                    packet: &packet,
                    expected_events: &expected,
                },
                &mut [None; 2],
            )
            .unwrap();
        let adapter_after_first = adapter.codec_state;
        metadata.frame_ordinal = 2;
        let mut decoded = messages.map(Some);
        assert_eq!(
            verifier.verify_market_data(
                &mut feed,
                &mut adapter,
                NativeIngressCapture {
                    metadata,
                    lane: NativeIngressLane::MarketData,
                    packet: &packet,
                    expected_events: &expected,
                },
                &mut decoded,
            ),
            Err(NativeReplayError::CaptureOrdinalRegression {
                previous: CaptureOrdinal(2),
                received: CaptureOrdinal(1),
            })
        );
        assert_eq!(feed.expected_sequence(), Sequence(102));
        assert_eq!(adapter.codec_state, adapter_after_first);
        assert!(decoded.iter().all(Option::is_none));
    }

    for transmission_capture_ordinal in [2, 1] {
        let (commit, source, egress) = linked_quote_commit(160);
        let (mut session, mut adapter) = live_session(1_800);
        let wire = expected_new_order_wire(Sequence(1_800), egress[0].command);
        let transmission = TransmissionInput {
            command: egress[0].command,
            status: TransmissionStatus::Sent,
            monotonic_now: MonotonicTimestampNs(1_810),
        };
        let capture = egress_capture(
            1,
            transmission_capture_ordinal,
            commit,
            source,
            Sequence(1_800),
            egress[0],
            &wire,
            transmission,
        );
        let proof = fake_transport_proof(
            1,
            Sequence(1_800),
            commit,
            egress[0],
            &wire,
            transmission.status,
            transmission.monotonic_now,
            FakeProofMode::Accept,
        );
        let mut transport = FakeTransportVerifier::default();
        let mut verifier = NativeReplayVerifier::new(1).unwrap();
        let mut encoded = [0xA5; 64];
        assert_eq!(
            verifier.verify_encoded_order(
                &mut session,
                &mut adapter,
                &mut transport,
                commit,
                egress[0],
                &proof,
                capture,
                &mut encoded,
            ),
            Err(NativeReplayError::SchedulerSourceNotBeforeTransmission {
                source: CaptureOrdinal(2),
                transmission: CaptureOrdinal(transmission_capture_ordinal),
            })
        );
        assert_eq!(session.next_outbound(), Sequence(1_800));
        assert_eq!(transport, FakeTransportVerifier::default());
        assert!(encoded.iter().all(|byte| *byte == 0));
    }
}

#[test]
fn one_byte_trailing_link_status_and_frame_mismatches_fail_latched() {
    reject_one_byte_wire_mismatch();
    reject_trailing_market_data_garbage();
    reject_swapped_egress_link();
    reject_transmission_status_mismatch();
    reject_frame_ordinal_gap_and_latch();
}

fn reject_one_byte_wire_mismatch() {
    let (mut session, mut adapter) = live_session(800);
    let adapter_before = adapter.checkpoint();
    let (scheduler_commit, scheduler_source_event, egress_records) = linked_quote_commit(101);
    let egress = egress_records[0];
    let canonical_wire = expected_new_order_wire(Sequence(800), egress.command);
    let mut wrong_wire = canonical_wire;
    wrong_wire[22] ^= 1;
    let transmission = TransmissionInput {
        command: egress.command,
        status: TransmissionStatus::Sent,
        monotonic_now: MonotonicTimestampNs(510),
    };
    let capture = egress_capture(
        1,
        101,
        scheduler_commit,
        scheduler_source_event,
        Sequence(800),
        egress,
        &wrong_wire,
        transmission,
    );
    let proof = fake_transport_proof(
        1,
        Sequence(800),
        scheduler_commit,
        egress,
        &canonical_wire,
        transmission.status,
        transmission.monotonic_now,
        FakeProofMode::Accept,
    );
    let mut encoded = [0xA5; 64];
    let mut verifier = NativeReplayVerifier::new(1).unwrap();
    let mut transport = FakeTransportVerifier::default();

    assert!(
        verifier
            .verify_encoded_order(
                &mut session,
                &mut adapter,
                &mut transport,
                scheduler_commit,
                egress,
                &proof,
                capture,
                &mut encoded,
            )
            .is_err()
    );
    assert!(verifier.failed());
    assert_eq!(verifier.next_frame_ordinal(), 1);
    assert_eq!(session.next_outbound(), Sequence(800));
    assert_eq!(adapter.checkpoint(), adapter_before);
    assert_eq!(transport, FakeTransportVerifier::default());
    assert!(encoded.iter().all(|byte| *byte == 0));

    encoded.fill(0xA5);
    assert_eq!(
        verifier.verify_encoded_order(
            &mut session,
            &mut adapter,
            &mut transport,
            scheduler_commit,
            egress,
            &proof,
            capture,
            &mut encoded,
        ),
        Err(NativeReplayError::Failed)
    );
    assert_eq!(session.next_outbound(), Sequence(800));
    assert_eq!(adapter.checkpoint(), adapter_before);
    assert!(encoded.iter().all(|byte| *byte == 0));
}

fn reject_trailing_market_data_garbage() {
    let mut adapter = FakeNativeAdapter::default();
    let mut feed = live_feed(&mut adapter, Sequence(100));
    let adapter_before = adapter.checkpoint();
    let packet = market_packet();
    let mut trailing = [0_u8; MARKET_PACKET_LEN + 1];
    trailing[..MARKET_PACKET_LEN].copy_from_slice(&packet);
    trailing[MARKET_PACKET_LEN] = 0xA5;
    let timestamp = TimestampNs(1_000);
    let messages = market_messages(timestamp);
    let metadata = NativePacketMetadata {
        frame_ordinal: 1,
        adapter_identity: IDENTITY,
        source: market_source(),
        hardware_receive_timestamp: timestamp,
        monotonic_timestamp: MonotonicTimestampNs(1_010),
        recovery: false,
    };
    let expected = normalized_market_events(metadata, messages);
    let capture = NativeIngressCapture {
        metadata,
        lane: NativeIngressLane::MarketData,
        packet: &trailing,
        expected_events: &expected,
    };
    let mut decoded = messages.map(Some);
    let mut verifier = NativeReplayVerifier::new(1).unwrap();

    assert!(
        verifier
            .verify_market_data(&mut feed, &mut adapter, capture, &mut decoded)
            .is_err()
    );
    assert!(verifier.failed());
    assert_eq!(verifier.next_frame_ordinal(), 1);
    assert_eq!(feed.expected_sequence(), Sequence(100));
    assert_eq!(adapter.checkpoint(), adapter_before);
    assert!(decoded.iter().all(Option::is_none));
}

fn reject_swapped_egress_link() {
    let (mut session, mut adapter) = live_session(900);
    let adapter_before = adapter.codec_state;
    let (scheduler_commit, scheduler_source_event, egress_records) = linked_quote_commit(111);
    let captured_egress = egress_records[0];
    let swapped_egress = egress_records[1];
    let wire = expected_new_order_wire(Sequence(900), captured_egress.command);
    let transmission = TransmissionInput {
        command: captured_egress.command,
        status: TransmissionStatus::Sent,
        monotonic_now: MonotonicTimestampNs(610),
    };
    let capture = egress_capture(
        1,
        111,
        scheduler_commit,
        scheduler_source_event,
        Sequence(900),
        captured_egress,
        &wire,
        transmission,
    );
    let proof = fake_transport_proof(
        1,
        Sequence(900),
        scheduler_commit,
        captured_egress,
        &wire,
        transmission.status,
        transmission.monotonic_now,
        FakeProofMode::Accept,
    );
    let mut encoded = [0xA5; 64];
    let mut verifier = NativeReplayVerifier::new(1).unwrap();
    let mut transport = FakeTransportVerifier::default();

    assert!(
        verifier
            .verify_encoded_order(
                &mut session,
                &mut adapter,
                &mut transport,
                scheduler_commit,
                swapped_egress,
                &proof,
                capture,
                &mut encoded,
            )
            .is_err()
    );
    assert!(verifier.failed());
    assert_eq!(session.next_outbound(), Sequence(900));
    assert_eq!(adapter.codec_state, adapter_before);
    assert_eq!(transport, FakeTransportVerifier::default());
    assert!(encoded.iter().all(|byte| *byte == 0));
}

fn reject_transmission_status_mismatch() {
    let (mut session, mut adapter) = live_session(1_000);
    let adapter_before = adapter.checkpoint();
    let (scheduler_commit, scheduler_source_event, egress_records) = linked_quote_commit(121);
    let egress = egress_records[0];
    let wire = expected_new_order_wire(Sequence(1_000), egress.command);
    let wrong_transmission = TransmissionInput {
        command: egress.command,
        status: TransmissionStatus::ProvenUnsent,
        monotonic_now: MonotonicTimestampNs(710),
    };
    let capture = egress_capture(
        1,
        121,
        scheduler_commit,
        scheduler_source_event,
        Sequence(1_000),
        egress,
        &wire,
        wrong_transmission,
    );
    let proof = fake_transport_proof(
        1,
        Sequence(1_000),
        scheduler_commit,
        egress,
        &wire,
        TransmissionStatus::Sent,
        wrong_transmission.monotonic_now,
        FakeProofMode::Accept,
    );
    let mut encoded = [0xA5; 64];
    let mut verifier = NativeReplayVerifier::new(1).unwrap();
    let mut transport = FakeTransportVerifier::default();

    assert!(
        verifier
            .verify_encoded_order(
                &mut session,
                &mut adapter,
                &mut transport,
                scheduler_commit,
                egress,
                &proof,
                capture,
                &mut encoded,
            )
            .is_err()
    );
    assert!(verifier.failed());
    assert_eq!(session.next_outbound(), Sequence(1_000));
    assert_eq!(adapter.checkpoint(), adapter_before);
    assert_eq!(transport, FakeTransportVerifier::default());
    assert!(encoded.iter().all(|byte| *byte == 0));
}

#[test]
fn replay_distinguishes_raw_effective_and_sequenced_transmission_time() {
    let canonical = verify_timed_egress(
        MonotonicTimestampNs(700),
        MonotonicTimestampNs(800),
        MonotonicTimestampNs(900),
    )
    .unwrap();
    assert_eq!(canonical.monotonic_now, MonotonicTimestampNs(900));

    let zero_clock_fallback = verify_timed_egress(
        MonotonicTimestampNs::ZERO,
        MonotonicTimestampNs(800),
        MonotonicTimestampNs(900),
    )
    .unwrap();
    assert_eq!(zero_clock_fallback.monotonic_now, MonotonicTimestampNs(900));
}

#[test]
fn replay_rejects_invalid_transmission_time_layers() {
    assert_eq!(
        verify_timed_egress(
            MonotonicTimestampNs(800),
            MonotonicTimestampNs(700),
            MonotonicTimestampNs(900),
        ),
        Err(NativeReplayError::TransmissionMinimumBeforeTransport {
            minimum: MonotonicTimestampNs(700),
            transport: MonotonicTimestampNs(800),
        })
    );
    assert_eq!(
        verify_timed_egress(
            MonotonicTimestampNs(700),
            MonotonicTimestampNs(900),
            MonotonicTimestampNs(800),
        ),
        Err(NativeReplayError::TransmissionEventBeforeMinimum {
            minimum: MonotonicTimestampNs(900),
            event: MonotonicTimestampNs(800),
        })
    );
    assert_eq!(
        verify_timed_egress(
            MonotonicTimestampNs::ZERO,
            MonotonicTimestampNs::ZERO,
            MonotonicTimestampNs(800),
        ),
        Err(NativeReplayError::InvalidTransmissionMinimum(
            MonotonicTimestampNs::ZERO,
        ))
    );
}

fn reject_frame_ordinal_gap_and_latch() {
    let mut adapter = FakeNativeAdapter::default();
    let mut feed = live_feed(&mut adapter, Sequence(100));
    let adapter_before = adapter.codec_state;
    let packet = market_packet();
    let timestamp = TimestampNs(1_000);
    let messages = market_messages(timestamp);
    let mut metadata = NativePacketMetadata {
        frame_ordinal: 11,
        adapter_identity: IDENTITY,
        source: market_source(),
        hardware_receive_timestamp: timestamp,
        monotonic_timestamp: MonotonicTimestampNs(1_010),
        recovery: false,
    };
    let expected = normalized_market_events(metadata, messages);
    let mut verifier = NativeReplayVerifier::new(10).unwrap();
    let mut decoded = messages.map(Some);
    let gap = NativeIngressCapture {
        metadata,
        lane: NativeIngressLane::MarketData,
        packet: &packet,
        expected_events: &expected,
    };
    assert!(
        verifier
            .verify_market_data(&mut feed, &mut adapter, gap, &mut decoded)
            .is_err()
    );
    assert!(verifier.failed());
    assert_eq!(verifier.next_frame_ordinal(), 10);
    assert!(decoded.iter().all(Option::is_none));

    metadata.frame_ordinal = 10;
    let exact = NativeIngressCapture {
        metadata,
        lane: NativeIngressLane::MarketData,
        packet: &packet,
        expected_events: &expected,
    };
    decoded = messages.map(Some);
    assert_eq!(
        verifier.verify_market_data(&mut feed, &mut adapter, exact, &mut decoded),
        Err(NativeReplayError::Failed)
    );
    assert_eq!(feed.expected_sequence(), Sequence(100));
    assert_eq!(adapter.codec_state, adapter_before);
    assert!(decoded.iter().all(Option::is_none));
}

fn live_feed(adapter: &mut FakeNativeAdapter, first_incremental: Sequence) -> MarketDataFeed {
    let mut feed = MarketDataFeed::new::<FakeNativeAdapter>(first_incremental).unwrap();
    feed.connect().unwrap();
    feed.begin_snapshot().unwrap();
    let last_incremental = Sequence(first_incremental.0 - 1);
    let begin = snapshot_packet(0x50, 77, last_incremental, TimestampNs(100));
    let end = snapshot_packet(0x52, 77, last_incremental, TimestampNs(110));
    let mut output = [None; 1];
    feed.decode_snapshot(adapter, &begin, TimestampNs(101), &mut output)
        .unwrap();
    feed.decode_snapshot(adapter, &end, TimestampNs(111), &mut output)
        .unwrap();
    let token = feed.snapshot_apply_token().unwrap();
    feed.complete_snapshot(token, TimestampNs(120)).unwrap();
    feed
}

fn live_session(first_outbound: u64) -> (VenueSession, FakeNativeAdapter) {
    let mut adapter = FakeNativeAdapter::default();
    let mut session = VenueSession::new::<FakeNativeAdapter>(
        Sequence(first_outbound),
        Sequence(1),
        10_000,
        support::instrument_definition(IDENTITY.venue, InstrumentId(9)),
    )
    .unwrap();
    session.connect(TimestampNs(10)).unwrap();
    let packet = single_logon_packet(Sequence(1), TimestampNs(20));
    let mut output = [None; 1];
    session
        .decode_inbound(&mut adapter, &packet, TimestampNs(30), &mut output)
        .unwrap();
    (session, adapter)
}

fn market_source() -> EventSource {
    EventSource::new(
        SourceId::new(IDENTITY.market_data_protocol.0, 1),
        SequenceDomain::MarketData,
        SessionEpoch(1),
    )
}

fn order_entry_source() -> EventSource {
    EventSource::new(
        SourceId::new(IDENTITY.order_entry_protocol.0, 1),
        SequenceDomain::OrderEntry,
        SessionEpoch(1),
    )
}

fn composition_config() -> EngineConfig {
    EngineConfig {
        venue: IDENTITY.venue,
        instrument: InstrumentId(9),
        first_market_sequence: Sequence(100),
        first_order_sequence: Sequence(1),
        first_client_order_id: ClientOrderId(10_000),
        first_risk_order_id: OrderId(20_000),
        instrument_definition: support::instrument_definition(IDENTITY.venue, InstrumentId(9)),
        max_clock_uncertainty_ns: 1_000,
        max_clock_offset_step_ns: 100,
        max_clock_holdover_ns: 100_000,
        clock_drift_parts_per_billion: 10,
        risk_session: RiskSessionId(1),
        risk_definition: InstrumentRiskDefinition {
            instrument: InstrumentId(9),
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

fn composition_ready_engine() -> CompositionEngine {
    let mut engine = CompositionEngine::new(composition_config()).unwrap();
    engine
        .observe_clock(ClockSample {
            utc: TimestampNs(1_000),
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
                last_incremental_sequence: Sequence(99),
            },
        ),
        (
            1_020,
            SnapshotPayload::Order(SnapshotOrder {
                instrument: InstrumentId(9),
                order_id: quant_hft_core::MarketByOrderId(9_001),
                side: Side::Sell,
                price: PriceTicks(101),
                quantity: Quantity(100),
            }),
        ),
        (
            1_030,
            SnapshotPayload::End {
                snapshot_id: 1,
                last_incremental_sequence: Sequence(99),
            },
        ),
    ] {
        engine
            .on_snapshot(
                SnapshotMessage {
                    exchange_timestamp: TimestampNs(monotonic - 5),
                    hardware_receive_timestamp: TimestampNs(monotonic),
                    payload,
                },
                MonotonicTimestampNs(monotonic),
                &mut output,
            )
            .unwrap();
    }
    engine
        .on_order_entry(
            InboundMessage {
                sequence: Sequence(1),
                exchange_timestamp: TimestampNs(1_035),
                hardware_receive_timestamp: TimestampNs(1_040),
                payload: InboundPayload::Session(SessionEvent::LogonAccepted),
            },
            MonotonicTimestampNs(1_040),
            &mut output,
        )
        .unwrap();
    engine
        .apply_control_decision(
            support::authenticated_arm(
                1,
                ConfigDigest([0xA5; 32]),
                Sequence(1),
                TimestampNs(1_050),
                TimestampNs(u64::MAX),
            ),
            &mut output,
        )
        .unwrap();
    engine
}

fn linked_quote_commit(
    commit_ordinal: u64,
) -> (SchedulerCommit, NormalizedEvent, [ReactorEgress; 2]) {
    let messages = composition_market_messages(TimestampNs(1_090));
    let metadata = NativePacketMetadata {
        frame_ordinal: 1,
        adapter_identity: IDENTITY,
        source: market_source(),
        hardware_receive_timestamp: TimestampNs(1_090),
        monotonic_timestamp: MonotonicTimestampNs(1_100),
        recovery: false,
    };
    let events = normalized_market_events(metadata, messages);
    let mut reactor = CompositionReactor::new(composition_ready_engine());
    let first = dispatch_reactor_replay_event(&mut reactor, events[0], &mut [None; 2]).unwrap();
    assert_eq!(first.commands, 0);
    let mut egress = [None; 2];
    let outcome = dispatch_reactor_replay_event(&mut reactor, events[1], &mut egress).unwrap();
    assert_eq!(outcome.commands, 2);
    let commit =
        SchedulerCommit::from_replay_outcome(commit_ordinal, events[1], outcome, &egress).unwrap();
    (
        commit,
        events[1],
        egress.map(|slot| slot.expect("two quote egress records")),
    )
}

fn normalized_market_events(
    metadata: NativePacketMetadata,
    messages: [MarketDataMessage; 2],
) -> [NormalizedEvent; 2] {
    [
        normalize_market_data(venue_metadata(metadata, CaptureOrdinal(1)), messages[0]).unwrap(),
        normalize_market_data(venue_metadata(metadata, CaptureOrdinal(2)), messages[1]).unwrap(),
    ]
}

fn normalized_order_entry_events(
    metadata: NativePacketMetadata,
    messages: [InboundMessage; 2],
) -> [NormalizedEvent; 2] {
    [
        normalize_order_entry(venue_metadata(metadata, CaptureOrdinal(7)), messages[0]).unwrap(),
        normalize_order_entry(venue_metadata(metadata, CaptureOrdinal(8)), messages[1]).unwrap(),
    ]
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

fn market_messages(hardware_receive_timestamp: TimestampNs) -> [MarketDataMessage; 2] {
    [
        MarketDataMessage {
            sequence: Sequence(100),
            exchange_timestamp: TimestampNs(900),
            hardware_receive_timestamp,
            instrument: InstrumentId(9),
            payload: MarketDataPayload::Book(BookDelta::Add {
                order_id: quant_hft_core::MarketByOrderId(8_001),
                side: Side::Buy,
                price: PriceTicks(12_345),
                quantity: Quantity(17),
            }),
        },
        MarketDataMessage {
            sequence: Sequence(101),
            exchange_timestamp: TimestampNs(901),
            hardware_receive_timestamp,
            instrument: InstrumentId(9),
            payload: MarketDataPayload::Book(BookDelta::Add {
                order_id: quant_hft_core::MarketByOrderId(8_002),
                side: Side::Sell,
                price: PriceTicks(12_346),
                quantity: Quantity(19),
            }),
        },
    ]
}

fn composition_market_messages(hardware_receive_timestamp: TimestampNs) -> [MarketDataMessage; 2] {
    [
        MarketDataMessage {
            sequence: Sequence(100),
            exchange_timestamp: TimestampNs(1_080),
            hardware_receive_timestamp,
            instrument: InstrumentId(9),
            payload: MarketDataPayload::Book(BookDelta::Add {
                order_id: quant_hft_core::MarketByOrderId(9_000),
                side: Side::Buy,
                price: PriceTicks(99),
                quantity: Quantity(100),
            }),
        },
        MarketDataMessage {
            sequence: Sequence(101),
            exchange_timestamp: TimestampNs(1_081),
            hardware_receive_timestamp,
            instrument: InstrumentId(9),
            payload: MarketDataPayload::TradingStatus { status_code: 1 },
        },
    ]
}

fn order_entry_messages(
    first_sequence: u64,
    hardware_receive_timestamp: TimestampNs,
) -> [InboundMessage; 2] {
    [
        InboundMessage {
            sequence: Sequence(first_sequence),
            exchange_timestamp: TimestampNs(150),
            hardware_receive_timestamp,
            payload: InboundPayload::Session(SessionEvent::LogonAccepted),
        },
        InboundMessage {
            sequence: Sequence(first_sequence + 1),
            exchange_timestamp: TimestampNs(151),
            hardware_receive_timestamp,
            payload: InboundPayload::Order(OrderEvent::Accepted(Accepted {
                client_order_id: ClientOrderId(5_001),
                venue_order_id: VenueOrderId(7_001),
                price: PriceTicks(12_345),
                quantity: Quantity(17),
            })),
        },
    ]
}

fn market_packet() -> [u8; MARKET_PACKET_LEN] {
    let messages = market_messages(TimestampNs(1_000));
    let mut packet = [0_u8; MARKET_PACKET_LEN];
    packet[0] = 2;
    for (index, message) in messages.iter().enumerate() {
        let offset = 1 + index * MARKET_RECORD_LEN;
        let MarketDataPayload::Book(BookDelta::Add {
            order_id,
            side,
            price,
            quantity,
        }) = message.payload
        else {
            unreachable!("fixed test payload")
        };
        packet[offset] = 0x40;
        write_u64(&mut packet, offset + 1, message.sequence.0);
        write_u64(&mut packet, offset + 9, message.exchange_timestamp.0);
        write_u32(&mut packet, offset + 17, message.instrument.0);
        write_u64(&mut packet, offset + 21, order_id.0);
        packet[offset + 29] = side as u8;
        write_i64(&mut packet, offset + 30, price.0);
        write_i64(&mut packet, offset + 38, quantity.0);
    }
    packet
}

fn composition_market_packet(messages: [MarketDataMessage; 2]) -> [u8; MARKET_PACKET_LEN] {
    let mut packet = [0_u8; MARKET_PACKET_LEN];
    packet[0] = 2;
    for (index, message) in messages.iter().enumerate() {
        let offset = 1 + index * MARKET_RECORD_LEN;
        write_u64(&mut packet, offset + 1, message.sequence.0);
        write_u64(&mut packet, offset + 9, message.exchange_timestamp.0);
        write_u32(&mut packet, offset + 17, message.instrument.0);
        match message.payload {
            MarketDataPayload::Book(BookDelta::Add {
                order_id,
                side,
                price,
                quantity,
            }) => {
                packet[offset] = 0x40;
                write_u64(&mut packet, offset + 21, order_id.0);
                packet[offset + 29] = side as u8;
                write_i64(&mut packet, offset + 30, price.0);
                write_i64(&mut packet, offset + 38, quantity.0);
            }
            MarketDataPayload::TradingStatus { status_code } => {
                packet[offset] = 0x41;
                packet[offset + 21] = u8::try_from(status_code).unwrap();
            }
            _ => unreachable!("fixed composition payload"),
        }
    }
    packet
}

fn order_entry_packet(first_sequence: u64) -> [u8; ORDER_ENTRY_PACKET_LEN] {
    let messages = order_entry_messages(first_sequence, TimestampNs(200));
    let mut packet = [0_u8; ORDER_ENTRY_PACKET_LEN];
    packet[0] = 2;
    for (index, message) in messages.iter().enumerate() {
        let offset = 1 + index * ORDER_ENTRY_RECORD_LEN;
        packet[offset] = if index == 0 { 1 } else { 4 };
        write_u64(&mut packet, offset + 1, message.sequence.0);
        write_u64(&mut packet, offset + 9, message.exchange_timestamp.0);
        if let InboundPayload::Order(OrderEvent::Accepted(accepted)) = message.payload {
            write_u64(&mut packet, offset + 17, accepted.client_order_id.0);
            write_u64(&mut packet, offset + 25, accepted.venue_order_id.0);
            write_i64(&mut packet, offset + 33, accepted.price.0);
            write_i64(&mut packet, offset + 41, accepted.quantity.0);
        }
    }
    packet
}

fn single_logon_packet(sequence: Sequence, exchange_timestamp: TimestampNs) -> [u8; 50] {
    let mut packet = [0_u8; 50];
    packet[0] = 1;
    packet[1] = 1;
    write_u64(&mut packet, 2, sequence.0);
    write_u64(&mut packet, 10, exchange_timestamp.0);
    packet
}

fn snapshot_packet(
    kind: u8,
    snapshot_id: u64,
    last_sequence: Sequence,
    exchange_timestamp: TimestampNs,
) -> [u8; 25] {
    let mut packet = [0_u8; 25];
    packet[0] = kind;
    write_u64(&mut packet, 1, exchange_timestamp.0);
    write_u64(&mut packet, 9, snapshot_id);
    write_u64(&mut packet, 17, last_sequence.0);
    packet
}

fn expected_new_order_wire(sequence: Sequence, command: OrderCommand) -> [u8; NEW_ORDER_WIRE_LEN] {
    let OrderCommand::New(order) = command else {
        unreachable!("fixed test command")
    };
    let mut wire = [0_u8; NEW_ORDER_WIRE_LEN];
    write_new_order_wire(&mut wire, sequence, order);
    wire
}

fn write_new_order_wire(output: &mut [u8], sequence: Sequence, order: NewOrder) {
    output[0] = 0x20;
    write_u64(output, 1, sequence.0);
    write_u64(output, 9, order.client_order_id.0);
    write_u32(output, 17, order.instrument.0);
    output[21] = order.side as u8;
    write_i64(output, 22, order.price.0);
    write_i64(output, 30, order.quantity.0);
    output[38] = order.time_in_force as u8;
    write_u64(output, 39, order.created_at.0);
}

#[allow(clippy::too_many_arguments)]
fn egress_capture<'a>(
    frame_ordinal: u64,
    capture_ordinal: u64,
    scheduler_commit: SchedulerCommit,
    scheduler_source_event: NormalizedEvent,
    venue_sequence: Sequence,
    egress: ReactorEgress,
    encoded_bytes: &'a [u8],
    transmission: TransmissionInput,
) -> NativeOrderEgressCapture<'a> {
    NativeOrderEgressCapture {
        frame_ordinal,
        scheduler_commit_ordinal: scheduler_commit.commit_ordinal,
        scheduler_source_event: Some(scheduler_source_event),
        egress,
        adapter_identity: IDENTITY,
        venue_sequence,
        encoded_bytes,
        transmission_minimum_monotonic: transmission.monotonic_now,
        transmission_event: normalize_transmission(CaptureOrdinal(capture_ordinal), transmission)
            .unwrap(),
    }
}

fn verify_timed_egress(
    raw_transport: MonotonicTimestampNs,
    effective_minimum: MonotonicTimestampNs,
    canonical_time: MonotonicTimestampNs,
) -> Result<TransmissionInput, NativeReplayError> {
    let (mut session, mut adapter) = live_session(1_000);
    let (scheduler_commit, scheduler_source_event, egress_records) = linked_quote_commit(121);
    let egress = egress_records[0];
    let wire = expected_new_order_wire(Sequence(1_000), egress.command);
    let transmission = TransmissionInput {
        command: egress.command,
        status: TransmissionStatus::Sent,
        monotonic_now: canonical_time,
    };
    let mut capture = egress_capture(
        1,
        3,
        scheduler_commit,
        scheduler_source_event,
        Sequence(1_000),
        egress,
        &wire,
        transmission,
    );
    capture.transmission_minimum_monotonic = effective_minimum;
    let proof = fake_transport_proof(
        1,
        Sequence(1_000),
        scheduler_commit,
        egress,
        &wire,
        transmission.status,
        raw_transport,
        FakeProofMode::Accept,
    );
    let mut verifier = NativeReplayVerifier::new(1).unwrap();
    let mut transport = FakeTransportVerifier::default();
    let mut encoded = [0xA5; 64];
    verifier.verify_encoded_order(
        &mut session,
        &mut adapter,
        &mut transport,
        scheduler_commit,
        egress,
        &proof,
        capture,
        &mut encoded,
    )
}

#[allow(clippy::too_many_arguments)]
fn fake_transport_proof(
    frame_ordinal: u64,
    venue_sequence: Sequence,
    scheduler_commit: SchedulerCommit,
    egress: ReactorEgress,
    encoded_bytes: &[u8],
    status: TransmissionStatus,
    monotonic_now: MonotonicTimestampNs,
    mode: FakeProofMode,
) -> FakeTransmissionProof {
    let mut fixed_bytes = [0_u8; 64];
    fixed_bytes[..encoded_bytes.len()].copy_from_slice(encoded_bytes);
    FakeTransmissionProof {
        frame_ordinal,
        adapter_identity: IDENTITY,
        venue_sequence,
        scheduler_commit_ordinal: scheduler_commit.commit_ordinal,
        scheduler_capture_ordinal: scheduler_commit.capture_ordinal,
        scheduler_source_event_crc32c: scheduler_commit.source_event_crc32c,
        egress,
        encoded_bytes: fixed_bytes,
        encoded_len: encoded_bytes.len(),
        disposition: NativeTransmissionDisposition {
            status,
            monotonic_now,
        },
        mode,
    }
}

#[allow(clippy::too_many_arguments)]
fn verify_quote_slot(
    verifier: &mut NativeReplayVerifier,
    session: &mut VenueSession,
    adapter: &mut FakeNativeAdapter,
    transport: &mut FakeTransportVerifier,
    scheduler_commit: SchedulerCommit,
    scheduler_source_event: NormalizedEvent,
    egress: ReactorEgress,
    frame_ordinal: u64,
    capture_ordinal: u64,
    venue_sequence: Sequence,
    status: TransmissionStatus,
    monotonic_now: MonotonicTimestampNs,
    mode: FakeProofMode,
    encode_buffer: &mut [u8; 64],
) -> Result<TransmissionInput, NativeReplayError> {
    let wire = expected_new_order_wire(venue_sequence, egress.command);
    let transmission = TransmissionInput {
        command: egress.command,
        status,
        monotonic_now,
    };
    let capture = egress_capture(
        frame_ordinal,
        capture_ordinal,
        scheduler_commit,
        scheduler_source_event,
        venue_sequence,
        egress,
        &wire,
        transmission,
    );
    let proof = fake_transport_proof(
        frame_ordinal,
        venue_sequence,
        scheduler_commit,
        egress,
        &wire,
        status,
        monotonic_now,
        mode,
    );
    verifier.verify_encoded_order(
        session,
        adapter,
        transport,
        scheduler_commit,
        egress,
        &proof,
        capture,
        encode_buffer,
    )
}

fn require_slots(provided: usize, required: usize) -> Result<(), WireError> {
    if provided < required {
        Err(WireError::BufferTooSmall { required, provided })
    } else {
        Ok(())
    }
}

fn write_u32(output: &mut [u8], offset: usize, value: u32) {
    output[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(output: &mut [u8], offset: usize, value: u64) {
    output[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn write_i64(output: &mut [u8], offset: usize, value: i64) {
    output[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn read_u32(input: &[u8], offset: usize) -> Result<u32, WireError> {
    let bytes = input
        .get(offset..offset + 4)
        .ok_or(WireError::MalformedPacket)?;
    Ok(u32::from_le_bytes(
        bytes.try_into().map_err(|_| WireError::MalformedPacket)?,
    ))
}

fn read_u64(input: &[u8], offset: usize) -> Result<u64, WireError> {
    let bytes = input
        .get(offset..offset + 8)
        .ok_or(WireError::MalformedPacket)?;
    Ok(u64::from_le_bytes(
        bytes.try_into().map_err(|_| WireError::MalformedPacket)?,
    ))
}

fn read_i64(input: &[u8], offset: usize) -> Result<i64, WireError> {
    let bytes = input
        .get(offset..offset + 8)
        .ok_or(WireError::MalformedPacket)?;
    Ok(i64::from_le_bytes(
        bytes.try_into().map_err(|_| WireError::MalformedPacket)?,
    ))
}
