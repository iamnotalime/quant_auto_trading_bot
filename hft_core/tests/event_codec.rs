mod support;

use quant_hft_core::clock::ClockSample;
use quant_hft_core::control::ConfigDigest;
use quant_hft_core::engine::TransmissionStatus;
use quant_hft_core::event_codec::{
    EventCodecError, ReplayInput, SnapshotCaptureMetadata, VenueCaptureMetadata, decode_clock,
    decode_control_decision, decode_market_data, decode_order_entry, decode_owned_mbo_binding,
    decode_replay_input, decode_snapshot, decode_timer, decode_transmission, normalize_clock,
    normalize_control_decision, normalize_market_data, normalize_order_entry,
    normalize_owned_mbo_binding, normalize_snapshot, normalize_timer, normalize_transmission,
};
use quant_hft_core::events::{
    CanonicalField, CaptureOrdinal, EventError, EventKind, EventSource, NormalizedEvent,
    SequenceDomain, SessionEpoch, SourceId,
};
use quant_hft_core::journal::{RECORD_LEN, decode_record, encode_record, replay_bytes};
use quant_hft_core::reactor::{
    ClockInput, ControlInput, MarketDataInput, OrderEntryInput, OwnedMboBindingInput, ReactorInput,
    SnapshotInput, TimerAction, TimerId, TimerInput, TransmissionInput,
};
use quant_hft_core::types::{
    InstrumentId, MonotonicTimestampNs, PriceTicks, Quantity, Sequence, Side, TimestampNs, VenueId,
};
use quant_hft_core::venue::{
    Accepted, BookDelta, CancelAll, CancelOrder, CancelScope, Canceled, ClientOrderId, Fill,
    InboundMessage, InboundPayload, LifecycleCorrectionDigest, LifecycleCorrectionId,
    LifecycleCorrectionKind, LifecycleCorrectionObserved, LiquidityFlag, MarketByOrderId,
    MarketDataMessage, MarketDataPayload, NewOrder, OrderCommand, OrderEvent, OwnedMboBinding,
    OwnedMboBindingMethod, RejectCode, Rejected, ReplaceOrder, SessionEvent, SnapshotMessage,
    SnapshotOrder, SnapshotPayload, TimeInForce, TradeId, VenueOrderId,
};

const VENUE: VenueId = VenueId(7);
const INSTRUMENT: InstrumentId = InstrumentId(42);

fn metadata(domain: SequenceDomain, ordinal: u64, recovery: bool) -> VenueCaptureMetadata {
    VenueCaptureMetadata {
        venue: VENUE,
        source: EventSource::new(
            SourceId::new(
                if domain == SequenceDomain::MarketData {
                    11
                } else {
                    12
                },
                1,
            ),
            domain,
            SessionEpoch(3),
        ),
        capture_ordinal: CaptureOrdinal(ordinal),
        monotonic_timestamp: MonotonicTimestampNs(10_000 + ordinal),
        recovery,
    }
}

fn timestamps(sequence: u64) -> (TimestampNs, TimestampNs) {
    (
        TimestampNs(1_000_000 + sequence),
        TimestampNs(1_000_100 + sequence),
    )
}

fn journal_round_trip(event: NormalizedEvent) -> NormalizedEvent {
    let mut record = [0xa5_u8; RECORD_LEN + 8];
    assert_eq!(encode_record(event, &mut record), Ok(RECORD_LEN));
    assert_eq!(&record[RECORD_LEN..], &[0xa5; 8]);
    let (decoded, consumed) = decode_record(&record).unwrap();
    assert_eq!(consumed, RECORD_LEN);
    assert_eq!(decoded, event);
    decoded
}

#[test]
fn every_market_data_payload_round_trips_through_v5_and_reactor_route() {
    let payloads = [
        MarketDataPayload::Book(BookDelta::Add {
            order_id: MarketByOrderId(101),
            side: Side::Buy,
            price: PriceTicks(10_000),
            quantity: Quantity(8),
        }),
        MarketDataPayload::Book(BookDelta::Modify {
            order_id: MarketByOrderId(101),
            price: PriceTicks(10_001),
            quantity: Quantity(7),
        }),
        MarketDataPayload::Book(BookDelta::Cancel {
            order_id: MarketByOrderId(101),
        }),
        MarketDataPayload::Book(BookDelta::Execute {
            order_id: MarketByOrderId(102),
            price: PriceTicks(10_002),
            quantity: Quantity(2),
        }),
        MarketDataPayload::Book(BookDelta::Clear),
        MarketDataPayload::Trade {
            trade_id: TradeId(99),
            side: Side::Sell,
            price: PriceTicks(10_003),
            quantity: Quantity(3),
        },
        MarketDataPayload::TradingStatus { status_code: 17 },
    ];

    for (index, payload) in payloads.into_iter().enumerate() {
        let ordinal = u64::try_from(index).unwrap() + 1;
        let sequence = ordinal;
        let (exchange_timestamp, hardware_receive_timestamp) = timestamps(sequence);
        let message = MarketDataMessage {
            instrument: INSTRUMENT,
            sequence: Sequence(sequence),
            exchange_timestamp,
            hardware_receive_timestamp,
            payload,
        };
        let capture = metadata(SequenceDomain::MarketData, ordinal, false);
        let event = normalize_market_data(capture, message).unwrap();
        let decoded = journal_round_trip(event);
        assert_eq!(decode_market_data(decoded), Ok(message));
        assert_eq!(
            decode_replay_input(decoded),
            Ok(ReplayInput::Reactor(ReactorInput::MarketData(
                MarketDataInput {
                    message,
                    monotonic_now: capture.monotonic_timestamp,
                }
            )))
        );
    }

    let (exchange_timestamp, hardware_receive_timestamp) = timestamps(8);
    let recovered_status = normalize_market_data(
        metadata(SequenceDomain::MarketData, 8, true),
        MarketDataMessage {
            instrument: INSTRUMENT,
            sequence: Sequence(8),
            exchange_timestamp,
            hardware_receive_timestamp,
            payload: MarketDataPayload::TradingStatus { status_code: 1 },
        },
    )
    .unwrap();
    assert!(recovered_status.is_recovery());
}

#[test]
fn every_order_and_session_payload_round_trips_losslessly() {
    let payloads = [
        InboundPayload::Order(OrderEvent::Accepted(Accepted {
            client_order_id: ClientOrderId(10),
            venue_order_id: VenueOrderId(20),
            price: PriceTicks(500),
            quantity: Quantity(9),
        })),
        InboundPayload::Order(OrderEvent::Rejected(Rejected {
            client_order_id: ClientOrderId(11),
            code: RejectCode(u32::MAX),
        })),
        InboundPayload::Order(OrderEvent::Canceled(Canceled {
            client_order_id: ClientOrderId(12),
            venue_order_id: VenueOrderId(22),
            canceled_quantity: Quantity(4),
            leaves_quantity: Quantity(5),
        })),
        InboundPayload::Order(OrderEvent::Fill(Fill {
            client_order_id: ClientOrderId(13),
            venue_order_id: VenueOrderId(23),
            trade_id: TradeId(33),
            price: PriceTicks(501),
            quantity: Quantity(3),
            leaves_quantity: Quantity(6),
            liquidity: LiquidityFlag::Removed,
        })),
        InboundPayload::Order(OrderEvent::LifecycleCorrectionObserved(
            LifecycleCorrectionObserved {
                correction_id: LifecycleCorrectionId(34),
                target_trade_id: TradeId(33),
                kind: LifecycleCorrectionKind::Bust,
                canonical_payload_digest: LifecycleCorrectionDigest([0xC7; 32]),
            },
        )),
        InboundPayload::Session(SessionEvent::LogonAccepted),
        InboundPayload::Session(SessionEvent::LogonRejected {
            code: RejectCode(44),
        }),
        InboundPayload::Session(SessionEvent::Heartbeat),
        InboundPayload::Session(SessionEvent::ReplayComplete {
            through: Sequence(123),
        }),
        InboundPayload::Session(SessionEvent::SnapshotRequired),
        InboundPayload::Session(SessionEvent::Logout {
            code: RejectCode(45),
        }),
    ];

    for (index, payload) in payloads.into_iter().enumerate() {
        let ordinal = u64::try_from(index).unwrap() + 1;
        let (exchange_timestamp, hardware_receive_timestamp) = timestamps(ordinal);
        let message = InboundMessage {
            sequence: Sequence(ordinal),
            exchange_timestamp,
            hardware_receive_timestamp,
            payload,
        };
        let capture = metadata(SequenceDomain::OrderEntry, ordinal, false);
        let event = normalize_order_entry(capture, message).unwrap();
        let decoded = journal_round_trip(event);
        assert_eq!(decode_order_entry(decoded), Ok(message));
        assert_eq!(
            decode_replay_input(decoded),
            Ok(ReplayInput::Reactor(ReactorInput::OrderEntry(
                OrderEntryInput {
                    message,
                    monotonic_now: capture.monotonic_timestamp,
                }
            )))
        );
    }
}

#[test]
fn lifecycle_correction_requires_exact_nonzero_identity_and_digest() {
    let (exchange_timestamp, hardware_receive_timestamp) = timestamps(1);
    let message = |correction| InboundMessage {
        sequence: Sequence(1),
        exchange_timestamp,
        hardware_receive_timestamp,
        payload: InboundPayload::Order(OrderEvent::LifecycleCorrectionObserved(correction)),
    };
    let valid = LifecycleCorrectionObserved {
        correction_id: LifecycleCorrectionId(34),
        target_trade_id: TradeId(33),
        kind: LifecycleCorrectionKind::Correct,
        canonical_payload_digest: LifecycleCorrectionDigest([0xC7; 32]),
    };

    assert_eq!(
        normalize_order_entry(
            metadata(SequenceDomain::OrderEntry, 1, false),
            message(LifecycleCorrectionObserved {
                correction_id: LifecycleCorrectionId(0),
                ..valid
            }),
        ),
        Err(EventCodecError::InvalidEvent(
            EventError::ReferenceRequired(EventKind::LifecycleCorrectionObserved,)
        ))
    );
    assert_eq!(
        normalize_order_entry(
            metadata(SequenceDomain::OrderEntry, 1, false),
            message(LifecycleCorrectionObserved {
                target_trade_id: TradeId(0),
                ..valid
            }),
        ),
        Err(EventCodecError::InvalidEvent(
            EventError::CanonicalZeroRequired {
                kind: EventKind::LifecycleCorrectionObserved,
                field: CanonicalField::TertiaryId,
            }
        ))
    );
    assert_eq!(
        normalize_order_entry(
            metadata(SequenceDomain::OrderEntry, 1, false),
            message(LifecycleCorrectionObserved {
                canonical_payload_digest: LifecycleCorrectionDigest([0; 32]),
                ..valid
            }),
        ),
        Err(EventCodecError::InvalidEvent(EventError::InvalidBlob(
            EventKind::LifecycleCorrectionObserved,
        )))
    );
}

#[test]
fn snapshot_transaction_retains_anchor_id_orders_and_timestamps() {
    let capture = SnapshotCaptureMetadata {
        venue: metadata(SequenceDomain::MarketData, 1, false),
        snapshot_id: 77,
        last_incremental_sequence: Sequence(0),
    };
    let messages = [
        SnapshotMessage {
            exchange_timestamp: TimestampNs(1_000),
            hardware_receive_timestamp: TimestampNs(1_100),
            payload: SnapshotPayload::Begin {
                snapshot_id: 77,
                last_incremental_sequence: Sequence(0),
            },
        },
        SnapshotMessage {
            exchange_timestamp: TimestampNs(1_001),
            hardware_receive_timestamp: TimestampNs(1_101),
            payload: SnapshotPayload::Order(SnapshotOrder {
                instrument: INSTRUMENT,
                order_id: MarketByOrderId(88),
                side: Side::Sell,
                price: PriceTicks(900),
                quantity: Quantity(12),
            }),
        },
        SnapshotMessage {
            exchange_timestamp: TimestampNs(1_002),
            hardware_receive_timestamp: TimestampNs(1_102),
            payload: SnapshotPayload::End {
                snapshot_id: 77,
                last_incremental_sequence: Sequence(0),
            },
        },
    ];

    for (index, message) in messages.into_iter().enumerate() {
        let mut item_capture = capture;
        item_capture.venue.capture_ordinal = CaptureOrdinal(u64::try_from(index).unwrap() + 1);
        item_capture.venue.monotonic_timestamp =
            MonotonicTimestampNs(20_000 + u64::try_from(index).unwrap());
        let event = normalize_snapshot(item_capture, message).unwrap();
        let decoded = journal_round_trip(event);
        assert_eq!(decode_snapshot(decoded), Ok(message));
        assert_eq!(
            decode_replay_input(decoded),
            Ok(ReplayInput::Reactor(ReactorInput::Snapshot(
                SnapshotInput {
                    message,
                    monotonic_now: item_capture.venue.monotonic_timestamp,
                }
            )))
        );
    }
}

#[test]
fn clock_control_and_timer_local_inputs_round_trip_without_venue_cursors() {
    let clock = ClockSample {
        utc: TimestampNs(5_000_000),
        monotonic: MonotonicTimestampNs(4_000_000),
        uncertainty_ns: 37,
    };
    let clock_event = journal_round_trip(normalize_clock(CaptureOrdinal(1), clock).unwrap());
    assert_eq!(decode_clock(clock_event), Ok(clock));
    assert_eq!(
        decode_replay_input(clock_event),
        Ok(ReplayInput::Reactor(ReactorInput::Clock(ClockInput {
            sample: clock
        })))
    );

    let decisions = [
        support::authenticated_arm(
            9,
            ConfigDigest([0x5a; 32]),
            Sequence(10),
            TimestampNs(5_000_001),
            TimestampNs(5_100_001),
        ),
        support::authenticated_disarm(
            9,
            ConfigDigest([0x5a; 32]),
            Sequence(11),
            TimestampNs(5_000_002),
        ),
        support::authenticated_heartbeat(
            9,
            ConfigDigest([0x5a; 32]),
            Sequence(12),
            TimestampNs(5_000_003),
            TimestampNs(5_100_003),
        ),
        support::authenticated_kill(
            9,
            ConfigDigest([0x5a; 32]),
            Sequence(13),
            TimestampNs(5_000_004),
        ),
    ];
    for (index, decision) in decisions.into_iter().enumerate() {
        let event =
            normalize_control_decision(CaptureOrdinal(u64::try_from(index).unwrap() + 2), decision)
                .unwrap();
        let decoded = journal_round_trip(event);
        assert_eq!(decode_control_decision(decoded), Ok(decision));
        assert_eq!(
            decode_replay_input(decoded),
            Ok(ReplayInput::Reactor(ReactorInput::Control(
                ControlInput::new(decision),
            )))
        );
    }

    let timer = TimerInput {
        timer_id: TimerId(99),
        action: TimerAction::KillCancelSweep,
        scheduled_at: MonotonicTimestampNs(4_000_001),
        fired_at: MonotonicTimestampNs(4_000_005),
    };
    let timer_event = journal_round_trip(normalize_timer(CaptureOrdinal(6), timer).unwrap());
    assert_eq!(decode_timer(timer_event), Ok(timer));
    assert_eq!(
        decode_replay_input(timer_event),
        Ok(ReplayInput::Reactor(ReactorInput::Timer(timer)))
    );
    let lease_timer = TimerInput {
        timer_id: TimerId(100),
        action: TimerAction::ControlLivenessCheck,
        scheduled_at: MonotonicTimestampNs(4_000_006),
        fired_at: MonotonicTimestampNs(4_000_007),
    };
    let lease_timer_event =
        journal_round_trip(normalize_timer(CaptureOrdinal(7), lease_timer).unwrap());
    assert_eq!(decode_timer(lease_timer_event), Ok(lease_timer));
    assert_eq!(
        decode_replay_input(lease_timer_event),
        Ok(ReplayInput::Reactor(ReactorInput::Timer(lease_timer)))
    );

    let mut journal = Vec::new();
    for event in [clock_event, timer_event] {
        let mut record = [0_u8; RECORD_LEN];
        encode_record(event, &mut record).unwrap();
        journal.extend_from_slice(&record);
    }
    // Deliberately use a contiguous pair for the local-only cursor assertion.
    let second = normalize_timer(
        CaptureOrdinal(2),
        TimerInput {
            timer_id: TimerId(100),
            ..timer
        },
    )
    .unwrap();
    journal.clear();
    for event in [clock_event, second] {
        let mut record = [0_u8; RECORD_LEN];
        encode_record(event, &mut record).unwrap();
        journal.extend_from_slice(&record);
    }
    let summary = replay_bytes::<1>(&journal, Sequence(1)).unwrap();
    assert_eq!(summary.records, 2);
    assert_eq!(summary.streams, 0);
    assert_eq!(summary.last_receive_timestamp, TimestampNs::ZERO);
    assert_eq!(
        summary.last_monotonic_timestamp,
        MonotonicTimestampNs(4_000_005)
    );
}

#[test]
fn manually_reconstructed_control_event_has_no_live_control_provenance() {
    let decision = support::authenticated_arm(
        9,
        ConfigDigest([0x5a; 32]),
        Sequence(10),
        TimestampNs(5_000_001),
        TimestampNs(5_100_001),
    );
    let authenticated = normalize_control_decision(CaptureOrdinal(1), decision).unwrap();
    let untrusted = NormalizedEvent::new_full(
        authenticated.header,
        authenticated.source,
        authenticated.capture_ordinal,
        authenticated.monotonic_timestamp,
        authenticated.kind,
        authenticated.side,
        authenticated.flags,
        authenticated.order_id,
        authenticated.secondary_id,
        authenticated.tertiary_id,
        authenticated.price,
        authenticated.quantity,
        authenticated.leaves_quantity,
        authenticated.reference,
        authenticated.auxiliary,
        authenticated.blob,
    );

    assert_eq!(untrusted.validate(), Ok(()));
    assert_eq!(
        decode_control_decision(untrusted),
        Err(EventCodecError::InvalidControlDecision)
    );

    let mut record = [0_u8; RECORD_LEN];
    assert_eq!(encode_record(untrusted, &mut record), Ok(RECORD_LEN));
    let (replayed, consumed) = decode_record(&record).unwrap();
    assert_eq!(consumed, RECORD_LEN);
    let replay_decision = decode_control_decision(replayed).unwrap();
    assert_eq!(replay_decision, decision);
    assert_eq!(
        normalize_control_decision(CaptureOrdinal(2), replay_decision),
        Err(EventCodecError::InvalidControlDecision)
    );
}

#[test]
fn every_transmission_command_round_trips_on_priority_lane() {
    let commands = [
        OrderCommand::New(NewOrder {
            client_order_id: ClientOrderId(1),
            instrument: INSTRUMENT,
            side: Side::Buy,
            price: PriceTicks(100),
            quantity: Quantity(5),
            time_in_force: TimeInForce::PostOnly,
            created_at: TimestampNs(9_000),
        }),
        OrderCommand::Cancel(CancelOrder {
            client_order_id: ClientOrderId(2),
            venue_order_id: VenueOrderId(20),
            created_at: TimestampNs(9_001),
        }),
        OrderCommand::Replace(ReplaceOrder {
            current_client_order_id: ClientOrderId(3),
            replacement_client_order_id: ClientOrderId(4),
            venue_order_id: VenueOrderId(21),
            new_price: PriceTicks(101),
            new_quantity: Quantity(6),
            created_at: TimestampNs(9_002),
        }),
        OrderCommand::CancelAll(CancelAll {
            scope: CancelScope::Session,
            created_at: TimestampNs(9_003),
        }),
        OrderCommand::CancelAll(CancelAll {
            scope: CancelScope::Instrument(INSTRUMENT),
            created_at: TimestampNs(9_004),
        }),
    ];

    for (index, command) in commands.into_iter().enumerate() {
        let input = TransmissionInput {
            command,
            status: if index % 2 == 0 {
                TransmissionStatus::Sent
            } else {
                TransmissionStatus::ProvenUnsent
            },
            monotonic_now: MonotonicTimestampNs(10_000 + u64::try_from(index).unwrap()),
        };
        let event =
            normalize_transmission(CaptureOrdinal(u64::try_from(index).unwrap() + 1), input)
                .unwrap();
        let decoded = journal_round_trip(event);
        assert_eq!(decode_transmission(decoded), Ok(input));
        assert_eq!(
            decode_replay_input(decoded),
            Ok(ReplayInput::Transmission(input))
        );
    }
}

#[test]
fn owned_mbo_bindings_round_trip_without_collapsing_id_namespaces() {
    let inputs = [
        OwnedMboBindingInput {
            binding: OwnedMboBinding {
                venue: VENUE,
                client_order_id: ClientOrderId(500),
                venue_order_id: VenueOrderId(600),
                market_by_order_id: MarketByOrderId(700),
                order_entry_sequence: Sequence(80),
                method: OwnedMboBindingMethod::ExplicitNativeIdentifier,
            },
            monotonic_now: MonotonicTimestampNs(90_000),
        },
        OwnedMboBindingInput {
            binding: OwnedMboBinding {
                venue: VENUE,
                client_order_id: ClientOrderId(501),
                venue_order_id: VenueOrderId(601),
                market_by_order_id: MarketByOrderId(701),
                order_entry_sequence: Sequence(81),
                method: OwnedMboBindingMethod::CertifiedDeterministicRule { rule_id: u32::MAX },
            },
            monotonic_now: MonotonicTimestampNs(90_001),
        },
    ];

    for (index, input) in inputs.into_iter().enumerate() {
        let event =
            normalize_owned_mbo_binding(CaptureOrdinal(u64::try_from(index).unwrap() + 1), input)
                .unwrap();
        let decoded = journal_round_trip(event);
        assert_eq!(decode_owned_mbo_binding(decoded), Ok(input));
        assert_eq!(
            decode_replay_input(decoded),
            Ok(ReplayInput::Reactor(ReactorInput::OwnedMboBinding(input)))
        );
    }
}

#[test]
fn local_events_do_not_reset_global_venue_receive_time_or_consume_stream_capacity() {
    let (exchange_one, receive_one) = timestamps(1);
    let first_message = MarketDataMessage {
        instrument: INSTRUMENT,
        sequence: Sequence(1),
        exchange_timestamp: exchange_one,
        hardware_receive_timestamp: receive_one,
        payload: MarketDataPayload::Book(BookDelta::Add {
            order_id: MarketByOrderId(1),
            side: Side::Buy,
            price: PriceTicks(100),
            quantity: Quantity(10),
        }),
    };
    let first = normalize_market_data(
        metadata(SequenceDomain::MarketData, 1, false),
        first_message,
    )
    .unwrap();
    let local = normalize_clock(
        CaptureOrdinal(2),
        ClockSample {
            utc: TimestampNs(8_000_000),
            monotonic: MonotonicTimestampNs(7_000_000),
            uncertainty_ns: 10,
        },
    )
    .unwrap();
    let (exchange_two, receive_two) = timestamps(2);
    let mut second_capture = metadata(SequenceDomain::MarketData, 3, false);
    second_capture.monotonic_timestamp = MonotonicTimestampNs(7_000_001);
    let second = normalize_market_data(
        second_capture,
        MarketDataMessage {
            sequence: Sequence(2),
            exchange_timestamp: exchange_two,
            hardware_receive_timestamp: receive_two,
            payload: MarketDataPayload::Book(BookDelta::Modify {
                order_id: MarketByOrderId(1),
                price: PriceTicks(101),
                quantity: Quantity(9),
            }),
            ..first_message
        },
    )
    .unwrap();

    let mut journal = Vec::new();
    for event in [first, local, second] {
        let mut record = [0_u8; RECORD_LEN];
        encode_record(event, &mut record).unwrap();
        journal.extend_from_slice(&record);
    }
    let summary = replay_bytes::<1>(&journal, Sequence(1)).unwrap();
    assert_eq!(summary.records, 3);
    assert_eq!(summary.streams, 1);
    assert_eq!(summary.last_capture_ordinal, CaptureOrdinal(3));
    assert_eq!(summary.last_receive_timestamp, receive_two);
}
