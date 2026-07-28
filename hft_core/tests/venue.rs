use quant_hft_core::venue::{
    Accepted, BookDelta, CancelAll, CancelOnDisconnect, CancelScope, ClientOrderId, DecodeResult,
    DirectMarketDataDecoder, FeedPhase, Fill, Heartbeat, InboundMessage, InboundPayload,
    LiquidityFlag, MarketByOrderId, MarketDataFeed, MarketDataMessage, MarketDataPayload,
    NativeOrderEntryDecoder, NativeOrderEntryEncoder, NewOrder, OrderCommand, OrderEvent,
    ProtocolId, ReplayRequest, SessionCommand, SessionEvent, SessionId, SessionPhase,
    SnapshotMessage, SnapshotOrder, SnapshotPayload, TimeInForce, TradeId, TransactionalCodec,
    VenueCapabilities, VenueDescriptor, VenueError, VenueIdentity, VenueOrderId, VenueSession,
    WireError,
};
use quant_hft_core::{
    CurrencyId, FixedInstrumentValue, InstrumentDefinition, InstrumentDefinitionError,
    InstrumentId, InstrumentRuleViolation, NativeProductId, PriceTicks, Quantity, RationalScale,
    ReferenceDataAuthorityId, ReferenceDataDigest, SelfTradePreventionInstruction, Sequence, Side,
    TimestampNs, VenueId,
};

const IDENTITY: VenueIdentity = VenueIdentity {
    venue: VenueId(7),
    market_data_protocol: ProtocolId(101),
    order_entry_protocol: ProtocolId(202),
    session: SessionId(303),
};

const fn instrument_definition() -> InstrumentDefinition {
    InstrumentDefinition {
        venue: IDENTITY.venue,
        instrument: InstrumentId(9),
        native_product: NativeProductId(9009),
        authority: ReferenceDataAuthorityId(1),
        reference_data_version: 1,
        reference_data_digest: ReferenceDataDigest([0xC3; 32]),
        valid_from: TimestampNs(1),
        valid_until: TimestampNs(u64::MAX),
        price_scale: RationalScale {
            numerator: 1,
            denominator: 100,
        },
        quantity_scale: RationalScale {
            numerator: 1,
            denominator: 1,
        },
        fixed_value: FixedInstrumentValue {
            settlement_currency: CurrencyId(840),
            settlement_units_per_price_tick: 1,
            contract_multiplier: 1,
        },
        minimum_price: PriceTicks(1),
        maximum_price: PriceTicks(i64::MAX),
        price_increment: PriceTicks(1),
        minimum_quantity: Quantity(1),
        maximum_quantity: Quantity(i64::MAX),
        quantity_increment: Quantity(1),
        continuous_trading_status_code: 1,
        self_trade_prevention: SelfTradePreventionInstruction(7),
        cancel_on_disconnect_required: false,
    }
}

const CAPABILITIES: VenueCapabilities = VenueCapabilities::MARKET_DATA_L3
    .union(VenueCapabilities::NEW_ORDER)
    .union(VenueCapabilities::CANCEL_ORDER)
    .union(VenueCapabilities::REPLACE_ORDER)
    .union(VenueCapabilities::HEARTBEAT)
    .union(VenueCapabilities::SEQUENCE_REPLAY)
    .union(VenueCapabilities::SNAPSHOT_RECOVERY)
    .union(VenueCapabilities::CANCEL_ALL)
    .union(VenueCapabilities::CANCEL_ON_DISCONNECT);

const NO_REPLAY_CAPABILITIES: VenueCapabilities = VenueCapabilities::NEW_ORDER
    .union(VenueCapabilities::CANCEL_ORDER)
    .union(VenueCapabilities::REPLACE_ORDER)
    .union(VenueCapabilities::HEARTBEAT)
    .union(VenueCapabilities::SNAPSHOT_RECOVERY)
    .union(VenueCapabilities::CANCEL_ALL)
    .union(VenueCapabilities::CANCEL_ON_DISCONNECT);

#[derive(Debug, Default)]
struct FakeWireAdapter {
    codec_state: u64,
    dirty_tail: bool,
    emit_second_order_entry: bool,
}

impl VenueDescriptor for FakeWireAdapter {
    const IDENTITY: VenueIdentity = IDENTITY;
    const CAPABILITIES: VenueCapabilities = CAPABILITIES;
}

impl TransactionalCodec for FakeWireAdapter {
    type Checkpoint = u64;

    fn checkpoint(&self) -> Self::Checkpoint {
        self.codec_state
    }

    fn restore(&mut self, checkpoint: Self::Checkpoint) {
        self.codec_state = checkpoint;
    }
}

impl NativeOrderEntryEncoder for FakeWireAdapter {
    fn encode_session(
        &mut self,
        sequence: Sequence,
        command: SessionCommand,
        output: &mut [u8],
    ) -> Result<usize, WireError> {
        self.codec_state = self.codec_state.wrapping_add(1);
        match command {
            SessionCommand::Logon(logon) => {
                require_capacity(output, 33)?;
                output[0] = 0x10;
                write_u64(output, 1, sequence.0);
                write_u64(output, 9, logon.session.0);
                write_u64(output, 17, logon.next_expected_inbound.0);
                write_u64(output, 25, logon.sent_at.0);
                Ok(33)
            }
            SessionCommand::Heartbeat(Heartbeat { sent_at }) => {
                require_capacity(output, 17)?;
                output[0] = 0x11;
                write_u64(output, 1, sequence.0);
                write_u64(output, 9, sent_at.0);
                Ok(17)
            }
            SessionCommand::Replay(ReplayRequest {
                from,
                through,
                sent_at,
            }) => {
                require_capacity(output, 33)?;
                output[0] = 0x12;
                write_u64(output, 1, sequence.0);
                write_u64(output, 9, from.0);
                write_u64(output, 17, through.0);
                write_u64(output, 25, sent_at.0);
                Ok(33)
            }
            SessionCommand::CancelOnDisconnect(CancelOnDisconnect { enabled, sent_at }) => {
                require_capacity(output, 18)?;
                output[0] = 0x13;
                write_u64(output, 1, sequence.0);
                output[9] = u8::from(enabled);
                write_u64(output, 10, sent_at.0);
                Ok(18)
            }
        }
    }

    fn encode_order(
        &mut self,
        sequence: Sequence,
        command: OrderCommand,
        _instrument: InstrumentDefinition,
        output: &mut [u8],
    ) -> Result<usize, WireError> {
        self.codec_state = self.codec_state.wrapping_add(1);
        match command {
            OrderCommand::New(order) => {
                require_capacity(output, 47)?;
                output[0] = 0x20;
                write_u64(output, 1, sequence.0);
                write_u64(output, 9, order.client_order_id.0);
                write_u32(output, 17, order.instrument.0);
                output[21] = order.side as u8;
                write_i64(output, 22, order.price.0);
                write_i64(output, 30, order.quantity.0);
                output[38] = order.time_in_force as u8;
                write_u64(output, 39, order.created_at.0);
                Ok(47)
            }
            OrderCommand::Cancel(order) => {
                require_capacity(output, 33)?;
                output[0] = 0x21;
                write_u64(output, 1, sequence.0);
                write_u64(output, 9, order.client_order_id.0);
                write_u64(output, 17, order.venue_order_id.0);
                write_u64(output, 25, order.created_at.0);
                Ok(33)
            }
            OrderCommand::Replace(order) => {
                require_capacity(output, 57)?;
                output[0] = 0x22;
                write_u64(output, 1, sequence.0);
                write_u64(output, 9, order.current_client_order_id.0);
                write_u64(output, 17, order.replacement_client_order_id.0);
                write_u64(output, 25, order.venue_order_id.0);
                write_i64(output, 33, order.new_price.0);
                write_i64(output, 41, order.new_quantity.0);
                write_u64(output, 49, order.created_at.0);
                Ok(57)
            }
            OrderCommand::CancelAll(command) => {
                require_capacity(output, 22)?;
                output[0] = 0x23;
                write_u64(output, 1, sequence.0);
                match command.scope {
                    CancelScope::Session => {
                        output[9] = 0;
                        write_u32(output, 10, 0);
                    }
                    CancelScope::Instrument(instrument) => {
                        output[9] = 1;
                        write_u32(output, 10, instrument.0);
                    }
                }
                write_u64(output, 14, command.created_at.0);
                Ok(22)
            }
        }
    }
}

impl NativeOrderEntryDecoder for FakeWireAdapter {
    fn decode_order_entry(
        &mut self,
        packet: &[u8],
        hardware_receive_timestamp: TimestampNs,
        output: &mut [Option<InboundMessage>],
    ) -> Result<DecodeResult, WireError> {
        self.codec_state = self.codec_state.wrapping_add(1);
        if packet.first() == Some(&0xFE) {
            return Ok(DecodeResult {
                messages: 0,
                consumed_bytes: 0,
            });
        }
        if output.is_empty() {
            return Err(WireError::BufferTooSmall {
                required: 1,
                provided: 0,
            });
        }
        if packet.len() < 17 {
            return Err(WireError::MalformedPacket);
        }
        let kind = packet[0];
        let sequence = Sequence(read_u64(packet, 1)?);
        let exchange_timestamp = TimestampNs(read_u64(packet, 9)?);
        let (payload, consumed_bytes) = match kind {
            1 => (InboundPayload::Session(SessionEvent::LogonAccepted), 17),
            2 => (InboundPayload::Session(SessionEvent::Heartbeat), 17),
            3 => {
                let through = Sequence(read_u64(packet, 17)?);
                (
                    InboundPayload::Session(SessionEvent::ReplayComplete { through }),
                    25,
                )
            }
            4 => {
                let client_order_id = ClientOrderId(read_u64(packet, 17)?);
                let venue_order_id = VenueOrderId(read_u64(packet, 25)?);
                let price = PriceTicks(read_i64(packet, 33)?);
                let quantity = Quantity(read_i64(packet, 41)?);
                (
                    InboundPayload::Order(OrderEvent::Accepted(Accepted {
                        client_order_id,
                        venue_order_id,
                        price,
                        quantity,
                    })),
                    49,
                )
            }
            5 => (InboundPayload::Session(SessionEvent::SnapshotRequired), 17),
            6 => {
                let liquidity = match packet.get(65) {
                    Some(1) => LiquidityFlag::Added,
                    Some(2) => LiquidityFlag::Removed,
                    Some(3) => LiquidityFlag::Unknown,
                    _ => return Err(WireError::InvalidField),
                };
                (
                    InboundPayload::Order(OrderEvent::Fill(Fill {
                        client_order_id: ClientOrderId(read_u64(packet, 17)?),
                        venue_order_id: VenueOrderId(read_u64(packet, 25)?),
                        trade_id: TradeId(read_u64(packet, 33)?),
                        price: PriceTicks(read_i64(packet, 41)?),
                        quantity: Quantity(read_i64(packet, 49)?),
                        leaves_quantity: Quantity(read_i64(packet, 57)?),
                        liquidity,
                    })),
                    66,
                )
            }
            _ => {
                return Err(WireError::UnsupportedMessage {
                    message_type: u16::from(kind),
                });
            }
        };
        if packet.len() < consumed_bytes {
            return Err(WireError::MalformedPacket);
        }
        let message = InboundMessage {
            sequence,
            exchange_timestamp,
            hardware_receive_timestamp,
            payload,
        };
        output[0] = Some(message);
        if self.dirty_tail
            && let Some(slot) = output.get_mut(1)
        {
            *slot = Some(message);
        }
        let messages = if self.emit_second_order_entry {
            let Some(slot) = output.get_mut(1) else {
                return Err(WireError::BufferTooSmall {
                    required: 2,
                    provided: output.len(),
                });
            };
            let Some(sequence) = sequence.0.checked_add(1) else {
                return Err(WireError::InvalidField);
            };
            *slot = Some(InboundMessage {
                sequence: Sequence(sequence),
                exchange_timestamp,
                hardware_receive_timestamp,
                payload: InboundPayload::Session(SessionEvent::Heartbeat),
            });
            2
        } else {
            1
        };
        Ok(DecodeResult {
            messages,
            consumed_bytes,
        })
    }
}

impl DirectMarketDataDecoder for FakeWireAdapter {
    fn decode_market_data(
        &mut self,
        packet: &[u8],
        hardware_receive_timestamp: TimestampNs,
        output: &mut [Option<MarketDataMessage>],
    ) -> Result<DecodeResult, WireError> {
        self.codec_state = self.codec_state.wrapping_add(1);
        if packet.first() == Some(&0xFE) {
            return Ok(DecodeResult {
                messages: 0,
                consumed_bytes: 0,
            });
        }
        if output.is_empty() {
            return Err(WireError::BufferTooSmall {
                required: 1,
                provided: 0,
            });
        }
        if packet.len() < 46 || packet[0] != 0x40 {
            return Err(WireError::MalformedPacket);
        }
        let message = MarketDataMessage {
            sequence: Sequence(read_u64(packet, 1)?),
            exchange_timestamp: TimestampNs(read_u64(packet, 9)?),
            hardware_receive_timestamp,
            instrument: InstrumentId(read_u32(packet, 17)?),
            payload: MarketDataPayload::Book(BookDelta::Add {
                order_id: MarketByOrderId(read_u64(packet, 21)?),
                side: if packet[29] == Side::Buy as u8 {
                    Side::Buy
                } else if packet[29] == Side::Sell as u8 {
                    Side::Sell
                } else {
                    return Err(WireError::InvalidField);
                },
                price: PriceTicks(read_i64(packet, 30)?),
                quantity: Quantity(read_i64(packet, 38)?),
            }),
        };
        output[0] = Some(message);
        if self.dirty_tail
            && let Some(slot) = output.get_mut(1)
        {
            *slot = Some(message);
        }
        Ok(DecodeResult {
            messages: 1,
            consumed_bytes: 46,
        })
    }

    fn decode_snapshot(
        &mut self,
        packet: &[u8],
        hardware_receive_timestamp: TimestampNs,
        output: &mut [Option<SnapshotMessage>],
    ) -> Result<DecodeResult, WireError> {
        self.codec_state = self.codec_state.wrapping_add(1);
        if packet.first() == Some(&0xFE) {
            return Ok(DecodeResult {
                messages: 0,
                consumed_bytes: 0,
            });
        }
        if output.is_empty() {
            return Err(WireError::BufferTooSmall {
                required: 1,
                provided: 0,
            });
        }
        let kind = *packet.first().ok_or(WireError::MalformedPacket)?;
        let (payload, consumed_bytes, exchange_offset) = match kind {
            0x50 | 0x52 if packet.len() >= 25 => {
                let snapshot_id = read_u64(packet, 9)?;
                let last_incremental_sequence = Sequence(read_u64(packet, 17)?);
                let payload = if kind == 0x50 {
                    SnapshotPayload::Begin {
                        snapshot_id,
                        last_incremental_sequence,
                    }
                } else {
                    SnapshotPayload::End {
                        snapshot_id,
                        last_incremental_sequence,
                    }
                };
                (payload, 25, 1)
            }
            0x51 if packet.len() >= 38 => {
                let side = match packet[21] {
                    1 => Side::Buy,
                    2 => Side::Sell,
                    _ => return Err(WireError::InvalidField),
                };
                (
                    SnapshotPayload::Order(SnapshotOrder {
                        instrument: InstrumentId(read_u32(packet, 9)?),
                        order_id: MarketByOrderId(read_u64(packet, 13)?),
                        side,
                        price: PriceTicks(read_i64(packet, 22)?),
                        quantity: Quantity(read_i64(packet, 30)?),
                    }),
                    38,
                    1,
                )
            }
            _ => return Err(WireError::MalformedPacket),
        };
        let message = SnapshotMessage {
            exchange_timestamp: TimestampNs(read_u64(packet, exchange_offset)?),
            hardware_receive_timestamp,
            payload,
        };
        output[0] = Some(message);
        if self.dirty_tail
            && let Some(slot) = output.get_mut(1)
        {
            *slot = Some(message);
        }
        Ok(DecodeResult {
            messages: 1,
            consumed_bytes,
        })
    }
}

#[derive(Debug, Default)]
struct NoReplayAdapter(FakeWireAdapter);

impl VenueDescriptor for NoReplayAdapter {
    const IDENTITY: VenueIdentity = IDENTITY;
    const CAPABILITIES: VenueCapabilities = NO_REPLAY_CAPABILITIES;
}

impl TransactionalCodec for NoReplayAdapter {
    type Checkpoint = u64;

    fn checkpoint(&self) -> Self::Checkpoint {
        self.0.codec_state
    }

    fn restore(&mut self, checkpoint: Self::Checkpoint) {
        self.0.codec_state = checkpoint;
    }
}

impl NativeOrderEntryEncoder for NoReplayAdapter {
    fn encode_session(
        &mut self,
        sequence: Sequence,
        command: SessionCommand,
        output: &mut [u8],
    ) -> Result<usize, WireError> {
        self.0.encode_session(sequence, command, output)
    }

    fn encode_order(
        &mut self,
        sequence: Sequence,
        command: OrderCommand,
        instrument: InstrumentDefinition,
        output: &mut [u8],
    ) -> Result<usize, WireError> {
        self.0.encode_order(sequence, command, instrument, output)
    }
}

impl NativeOrderEntryDecoder for NoReplayAdapter {
    fn decode_order_entry(
        &mut self,
        packet: &[u8],
        hardware_receive_timestamp: TimestampNs,
        output: &mut [Option<InboundMessage>],
    ) -> Result<DecodeResult, WireError> {
        self.0
            .decode_order_entry(packet, hardware_receive_timestamp, output)
    }
}

#[derive(Debug)]
struct NoCancelOnDisconnectDescriptor;

impl VenueDescriptor for NoCancelOnDisconnectDescriptor {
    const IDENTITY: VenueIdentity = IDENTITY;
    const CAPABILITIES: VenueCapabilities = VenueCapabilities::NEW_ORDER;
}

#[test]
fn logon_gates_orders_and_wire_bytes_are_deterministic() {
    let mut first = VenueSession::new::<FakeWireAdapter>(
        Sequence(7),
        Sequence(10),
        1_000,
        instrument_definition(),
    )
    .unwrap();
    let mut second = first;
    let mut first_adapter = FakeWireAdapter::default();
    let mut second_adapter = FakeWireAdapter::default();
    let command = new_order(TimestampNs(130));

    let mut blocked = [0xAA; 64];
    assert_eq!(
        first.encode_order(&mut first_adapter, command, &mut blocked),
        Err(VenueError::InvalidSessionState(SessionPhase::Disconnected))
    );
    assert!(blocked.iter().all(|byte| *byte == 0));
    assert_eq!(first.next_outbound(), Sequence(7));

    first.connect(TimestampNs(100)).unwrap();
    second.connect(TimestampNs(100)).unwrap();
    let mut first_logon = [0_u8; 64];
    let mut second_logon = [0_u8; 64];
    let first_frame = first
        .encode_logon(&mut first_adapter, TimestampNs(100), &mut first_logon)
        .unwrap();
    let second_frame = second
        .encode_logon(&mut second_adapter, TimestampNs(100), &mut second_logon)
        .unwrap();
    assert_eq!(first_frame, second_frame);
    assert_eq!(
        &first_logon[..first_frame.bytes],
        &second_logon[..second_frame.bytes]
    );
    assert_eq!(read_u64(&first_logon, 17).unwrap(), 10);

    accept_logon(&mut first, &mut first_adapter, Sequence(10), 110, 120);
    accept_logon(&mut second, &mut second_adapter, Sequence(10), 110, 120);

    let mut first_wire = [0_u8; 64];
    let mut second_wire = [0_u8; 64];
    let first_order = first
        .encode_order(&mut first_adapter, command, &mut first_wire)
        .unwrap();
    let second_order = second
        .encode_order(&mut second_adapter, command, &mut second_wire)
        .unwrap();
    assert_eq!(first_order, second_order);
    assert_eq!(
        &first_wire[..first_order.bytes],
        &second_wire[..second_order.bytes]
    );
    assert_eq!(first_wire[0], 0x20);
    assert_eq!(read_u64(&first_wire, 1).unwrap(), 8);

    let mut wrong_descriptor = NoReplayAdapter::default();
    let mut rejected = [0xAA; 64];
    assert!(matches!(
        first.encode_heartbeat(&mut wrong_descriptor, TimestampNs(140), &mut rejected),
        Err(VenueError::AdapterDescriptorMismatch { .. })
    ));
    assert_eq!(wrong_descriptor.0.codec_state, 0);
    assert!(rejected.iter().all(|byte| *byte == 0));
}

#[test]
fn instrument_definition_rejects_route_band_increment_and_expiry_before_codec_mutation() {
    let mut definition = instrument_definition();
    definition.valid_from = TimestampNs(100);
    definition.valid_until = TimestampNs(200);
    definition.minimum_price = PriceTicks(100);
    definition.maximum_price = PriceTicks(20_000);
    definition.price_increment = PriceTicks(5);
    definition.minimum_quantity = Quantity(10);
    definition.maximum_quantity = Quantity(100);
    definition.quantity_increment = Quantity(10);

    let mut session =
        VenueSession::new::<FakeWireAdapter>(Sequence(7), Sequence(10), 1_000, definition).unwrap();
    let mut adapter = FakeWireAdapter::default();
    session.connect(TimestampNs(100)).unwrap();
    accept_logon(&mut session, &mut adapter, Sequence(10), 110, 120);

    let valid = NewOrder {
        client_order_id: ClientOrderId(5_001),
        instrument: definition.instrument,
        side: Side::Buy,
        price: PriceTicks(12_345),
        quantity: Quantity(20),
        time_in_force: TimeInForce::PostOnly,
        created_at: TimestampNs(150),
    };
    let cases = [
        (
            NewOrder {
                instrument: InstrumentId(10),
                ..valid
            },
            VenueError::InstrumentRule(InstrumentRuleViolation::InstrumentMismatch {
                expected: definition.instrument,
                received: InstrumentId(10),
            }),
        ),
        (
            NewOrder {
                price: PriceTicks(20_005),
                ..valid
            },
            VenueError::InstrumentRule(InstrumentRuleViolation::PriceOutOfBounds {
                minimum: definition.minimum_price,
                maximum: definition.maximum_price,
                received: PriceTicks(20_005),
            }),
        ),
        (
            NewOrder {
                price: PriceTicks(12_346),
                ..valid
            },
            VenueError::InstrumentRule(InstrumentRuleViolation::PriceIncrementMismatch {
                increment: definition.price_increment,
                received: PriceTicks(12_346),
            }),
        ),
        (
            NewOrder {
                quantity: Quantity(21),
                ..valid
            },
            VenueError::InstrumentRule(InstrumentRuleViolation::QuantityIncrementMismatch {
                increment: definition.quantity_increment,
                received: Quantity(21),
            }),
        ),
        (
            NewOrder {
                created_at: TimestampNs(201),
                ..valid
            },
            VenueError::InstrumentRule(InstrumentRuleViolation::ReferenceDataNotEffective {
                valid_from: definition.valid_from,
                valid_until: definition.valid_until,
                observed: TimestampNs(201),
            }),
        ),
    ];
    for (order, expected) in cases {
        let before_session = session;
        let before_codec = adapter.codec_state;
        let mut output = [0xA5; 64];
        assert_eq!(
            session.encode_order(&mut adapter, OrderCommand::New(order), &mut output),
            Err(expected)
        );
        assert_eq!(session, before_session);
        assert_eq!(adapter.codec_state, before_codec);
        assert!(output.iter().all(|byte| *byte == 0));
    }

    let mut output = [0_u8; 64];
    assert_eq!(
        session
            .encode_order(&mut adapter, OrderCommand::New(valid), &mut output)
            .unwrap()
            .sequence,
        Sequence(7)
    );
    assert_eq!(adapter.codec_state, 2);
}

#[test]
fn session_construction_rejects_invalid_or_cross_venue_reference_data() {
    let mut invalid = instrument_definition();
    invalid.reference_data_digest = ReferenceDataDigest([0; 32]);
    assert_eq!(
        VenueSession::new::<FakeWireAdapter>(Sequence(1), Sequence(1), 1_000, invalid),
        Err(VenueError::InstrumentDefinition(
            InstrumentDefinitionError::InvalidReferenceDataDigest,
        ))
    );

    let mut wrong_venue = instrument_definition();
    wrong_venue.venue = VenueId(8);
    assert_eq!(
        VenueSession::new::<FakeWireAdapter>(Sequence(1), Sequence(1), 1_000, wrong_venue),
        Err(VenueError::InstrumentRule(
            InstrumentRuleViolation::VenueMismatch {
                expected: VenueId(8),
                received: IDENTITY.venue,
            },
        ))
    );

    let mut protected = instrument_definition();
    protected.cancel_on_disconnect_required = true;
    assert_eq!(
        VenueSession::new::<NoCancelOnDisconnectDescriptor>(
            Sequence(1),
            Sequence(1),
            1_000,
            protected,
        ),
        Err(VenueError::MissingCapability {
            required: VenueCapabilities::CANCEL_ON_DISCONNECT,
        })
    );
}

#[test]
fn buffer_capacity_failure_scrubs_bytes_and_preserves_sequence() {
    let mut session = VenueSession::new::<FakeWireAdapter>(
        Sequence(1),
        Sequence(1),
        1_000,
        instrument_definition(),
    )
    .unwrap();
    let mut adapter = FakeWireAdapter::default();
    session.connect(TimestampNs(10)).unwrap();
    let mut logon = [0_u8; 64];
    session
        .encode_logon(&mut adapter, TimestampNs(10), &mut logon)
        .unwrap();
    accept_logon(&mut session, &mut adapter, Sequence(1), 11, 12);

    let before = session.next_outbound();
    let codec_before = adapter.codec_state;
    let mut too_small = [0xAA; 8];
    assert_eq!(
        session.encode_order(&mut adapter, new_order(TimestampNs(20)), &mut too_small),
        Err(VenueError::Wire(WireError::BufferTooSmall {
            required: 47,
            provided: 8,
        }))
    );
    assert!(too_small.iter().all(|byte| *byte == 0));
    assert_eq!(session.next_outbound(), before);
    assert_eq!(adapter.codec_state, codec_before);

    let mut invalid_time = [0xAA; 64];
    assert_eq!(
        session.encode_order(
            &mut adapter,
            new_order(TimestampNs::ZERO),
            &mut invalid_time
        ),
        Err(VenueError::InvalidTimestamp(TimestampNs::ZERO))
    );
    assert!(invalid_time.iter().all(|byte| *byte == 0));
    assert_eq!(session.next_outbound(), before);
    assert_eq!(adapter.codec_state, codec_before);
}

#[test]
fn dirty_decoder_tails_roll_back_every_native_input_lane() {
    let mut session = VenueSession::new::<FakeWireAdapter>(
        Sequence(1),
        Sequence(10),
        1_000,
        instrument_definition(),
    )
    .unwrap();
    let mut adapter = FakeWireAdapter::default();
    let mut wire = [0_u8; 64];
    session.connect(TimestampNs(100)).unwrap();
    session
        .encode_logon(&mut adapter, TimestampNs(101), &mut wire)
        .unwrap();
    adapter.dirty_tail = true;

    let session_before = session;
    let codec_before = adapter.codec_state;
    let mut inbound = [None; 3];
    assert_eq!(
        session.decode_inbound(
            &mut adapter,
            &session_packet(1, Sequence(10), 102, None),
            TimestampNs(103),
            &mut inbound,
        ),
        Err(VenueError::NonEmptyDecodedTail {
            index: 1,
            reported_messages: 1,
        })
    );
    assert_eq!(session, session_before);
    assert_eq!(adapter.codec_state, codec_before);
    assert!(inbound.iter().all(Option::is_none));

    let mut feed = MarketDataFeed::new::<FakeWireAdapter>(Sequence(100)).unwrap();
    feed.connect().unwrap();
    feed.begin_snapshot().unwrap();
    let feed_before_snapshot = feed;
    let mut snapshot = [None; 3];
    assert_eq!(
        feed.decode_snapshot(
            &mut adapter,
            &snapshot_boundary_packet(0x50, 77, 105, 110),
            TimestampNs(111),
            &mut snapshot,
        ),
        Err(VenueError::NonEmptyDecodedTail {
            index: 1,
            reported_messages: 1,
        })
    );
    assert_eq!(feed, feed_before_snapshot);
    assert_eq!(adapter.codec_state, codec_before);
    assert!(snapshot.iter().all(Option::is_none));

    adapter.dirty_tail = false;
    feed.decode_snapshot(
        &mut adapter,
        &snapshot_boundary_packet(0x50, 77, 105, 112),
        TimestampNs(113),
        &mut snapshot,
    )
    .unwrap();
    feed.decode_snapshot(
        &mut adapter,
        &snapshot_boundary_packet(0x52, 77, 105, 114),
        TimestampNs(115),
        &mut snapshot,
    )
    .unwrap();
    feed.complete_snapshot(feed.snapshot_apply_token().unwrap(), TimestampNs(116))
        .unwrap();

    adapter.dirty_tail = true;
    let feed_before_incremental = feed;
    let codec_before_incremental = adapter.codec_state;
    let mut market_data = [None; 3];
    assert_eq!(
        feed.decode_incrementals(
            &mut adapter,
            &market_packet(106, 117),
            TimestampNs(118),
            &mut market_data,
        ),
        Err(VenueError::NonEmptyDecodedTail {
            index: 1,
            reported_messages: 1,
        })
    );
    assert_eq!(feed, feed_before_incremental);
    assert_eq!(adapter.codec_state, codec_before_incremental);
    assert!(market_data.iter().all(Option::is_none));
}

#[test]
fn exact_multi_message_decoder_prefix_commits_as_one_batch() {
    let mut session = VenueSession::new::<FakeWireAdapter>(
        Sequence(1),
        Sequence(10),
        1_000,
        instrument_definition(),
    )
    .unwrap();
    let mut adapter = FakeWireAdapter {
        emit_second_order_entry: true,
        ..FakeWireAdapter::default()
    };
    let mut wire = [0_u8; 64];
    session.connect(TimestampNs(100)).unwrap();
    session
        .encode_logon(&mut adapter, TimestampNs(101), &mut wire)
        .unwrap();
    let codec_before = adapter.codec_state;
    let mut inbound = [None; 3];

    let decoded = session
        .decode_inbound(
            &mut adapter,
            &session_packet(1, Sequence(10), 102, None),
            TimestampNs(103),
            &mut inbound,
        )
        .unwrap();

    assert_eq!(
        decoded,
        DecodeResult {
            messages: 2,
            consumed_bytes: 17,
        }
    );
    assert!(matches!(
        inbound[0],
        Some(InboundMessage {
            sequence: Sequence(10),
            payload: InboundPayload::Session(SessionEvent::LogonAccepted),
            ..
        })
    ));
    assert!(matches!(
        inbound[1],
        Some(InboundMessage {
            sequence: Sequence(11),
            payload: InboundPayload::Session(SessionEvent::Heartbeat),
            ..
        })
    ));
    assert!(inbound[2].is_none());
    assert_eq!(session.phase(), SessionPhase::Live);
    assert_eq!(session.expected_inbound(), Sequence(12));
    assert_eq!(adapter.codec_state, codec_before + 1);
}

#[test]
fn sequence_exhaustion_and_logon_timeout_fail_before_codec_use() {
    let mut exhausted = VenueSession::new::<FakeWireAdapter>(
        Sequence(u64::MAX),
        Sequence(1),
        1_000,
        instrument_definition(),
    )
    .unwrap();
    let mut adapter = FakeWireAdapter::default();
    exhausted.connect(TimestampNs(100)).unwrap();
    let mut wire = [0xAA; 64];
    assert_eq!(
        exhausted.encode_logon(&mut adapter, TimestampNs(101), &mut wire),
        Err(VenueError::OutboundSequenceExhausted)
    );
    assert_eq!(adapter.codec_state, 0);
    assert!(wire.iter().all(|byte| *byte == 0));

    let mut timed_out = VenueSession::new::<FakeWireAdapter>(
        Sequence(1),
        Sequence(1),
        1_000,
        instrument_definition(),
    )
    .unwrap();
    timed_out.connect(TimestampNs(200)).unwrap();
    assert_eq!(
        timed_out.check_heartbeat(TimestampNs(1_201)),
        Err(VenueError::LogonTimeout {
            connected_at: TimestampNs(200),
            checked_at: TimestampNs(1_201),
        })
    );
    assert_eq!(timed_out.phase(), SessionPhase::Disconnected);
}

#[test]
fn no_replay_capability_moves_a_gap_directly_to_snapshot_required() {
    let mut session = VenueSession::new::<NoReplayAdapter>(
        Sequence(1),
        Sequence(10),
        1_000,
        instrument_definition(),
    )
    .unwrap();
    let mut adapter = NoReplayAdapter::default();
    let mut wire = [0_u8; 64];
    session.connect(TimestampNs(100)).unwrap();
    session
        .encode_logon(&mut adapter, TimestampNs(101), &mut wire)
        .unwrap();
    let logon = session_packet(1, Sequence(10), 102, None);
    let mut output = [None; 1];
    session
        .decode_inbound(&mut adapter, &logon, TimestampNs(103), &mut output)
        .unwrap();

    let gap = fill_packet(Sequence(12), 104);
    assert_eq!(
        session.decode_inbound(&mut adapter, &gap, TimestampNs(105), &mut output),
        Err(VenueError::SequenceGap {
            expected: Sequence(11),
            received: Sequence(12),
        })
    );
    assert_eq!(session.phase(), SessionPhase::SnapshotRequired);
    assert_eq!(session.recovery_through(), None);
    assert!(output.iter().all(Option::is_none));
}

#[test]
fn native_cancel_all_and_cancel_on_disconnect_are_typed_and_sequenced() {
    let mut session = VenueSession::new::<FakeWireAdapter>(
        Sequence(1),
        Sequence(1),
        1_000,
        instrument_definition(),
    )
    .unwrap();
    let mut adapter = FakeWireAdapter::default();
    let mut wire = [0_u8; 64];
    session.connect(TimestampNs(10)).unwrap();
    session
        .encode_logon(&mut adapter, TimestampNs(10), &mut wire)
        .unwrap();
    accept_logon(&mut session, &mut adapter, Sequence(1), 11, 12);

    let cod = session
        .encode_cancel_on_disconnect(
            &mut adapter,
            CancelOnDisconnect {
                enabled: true,
                sent_at: TimestampNs(20),
            },
            &mut wire,
        )
        .unwrap();
    assert_eq!(cod.sequence, Sequence(2));
    assert_eq!(wire[0], 0x13);

    let cancel_all = session
        .encode_cancel_all(
            &mut adapter,
            CancelAll {
                scope: CancelScope::Instrument(InstrumentId(9)),
                created_at: TimestampNs(21),
            },
            &mut wire,
        )
        .unwrap();
    assert_eq!(cancel_all.sequence, Sequence(3));
    assert_eq!(wire[0], 0x23);
    assert_eq!(read_u32(&wire, 10).unwrap(), 9);
}

#[test]
fn inbound_gap_requires_exact_replay_and_duplicates_are_rejected() {
    let mut session = VenueSession::new::<FakeWireAdapter>(
        Sequence(1),
        Sequence(10),
        1_000,
        instrument_definition(),
    )
    .unwrap();
    let mut adapter = FakeWireAdapter::default();
    session.connect(TimestampNs(100)).unwrap();
    let mut wire = [0_u8; 64];
    session
        .encode_logon(&mut adapter, TimestampNs(100), &mut wire)
        .unwrap();
    accept_logon(&mut session, &mut adapter, Sequence(10), 101, 102);

    let gap = fill_packet(Sequence(13), 110);
    let mut decoded = [None; 2];
    let codec_before_gap = adapter.codec_state;
    assert_eq!(
        session.decode_inbound(&mut adapter, &gap, TimestampNs(120), &mut decoded),
        Err(VenueError::SequenceGap {
            expected: Sequence(11),
            received: Sequence(13),
        })
    );
    assert_eq!(session.phase(), SessionPhase::RecoveryRequired);
    assert_eq!(session.recovery_through(), Some(Sequence(13)));
    assert_eq!(adapter.codec_state, codec_before_gap);
    assert!(decoded.iter().all(Option::is_none));

    let replay = session
        .encode_replay_request(&mut adapter, TimestampNs(130), &mut wire)
        .unwrap();
    assert_eq!(session.phase(), SessionPhase::Recovering);
    assert_eq!(wire[0], 0x12);
    assert_eq!(read_u64(&wire, 9).unwrap(), 11);
    assert_eq!(read_u64(&wire, 17).unwrap(), 13);
    assert_eq!(replay.sequence, Sequence(2));

    decode_session_event(&mut session, &mut adapter, 2, Sequence(11), 131, 140, None);
    decode_session_event(&mut session, &mut adapter, 2, Sequence(12), 141, 150, None);
    decode_fill_event(&mut session, &mut adapter, Sequence(13), 151, 160);
    decode_session_event(
        &mut session,
        &mut adapter,
        3,
        Sequence(14),
        161,
        170,
        Some(Sequence(13)),
    );
    assert_eq!(session.phase(), SessionPhase::Live);
    assert_eq!(session.expected_inbound(), Sequence(15));

    let duplicate = session_packet(2, Sequence(14), 171, None);
    assert_eq!(
        session.decode_inbound(&mut adapter, &duplicate, TimestampNs(180), &mut decoded),
        Err(VenueError::DuplicateSequence {
            expected: Sequence(15),
            received: Sequence(14),
        })
    );
    assert_eq!(session.phase(), SessionPhase::Live);
    assert!(decoded.iter().all(Option::is_none));
}

#[test]
fn reconnect_logon_preserves_both_sequence_domains() {
    let mut session = VenueSession::new::<FakeWireAdapter>(
        Sequence(40),
        Sequence(70),
        1_000,
        instrument_definition(),
    )
    .unwrap();
    let mut adapter = FakeWireAdapter::default();
    session.connect(TimestampNs(100)).unwrap();
    let mut wire = [0_u8; 64];
    session
        .encode_logon(&mut adapter, TimestampNs(100), &mut wire)
        .unwrap();
    accept_logon(&mut session, &mut adapter, Sequence(70), 101, 102);
    assert_eq!(session.next_outbound(), Sequence(41));
    assert_eq!(session.expected_inbound(), Sequence(71));

    session.disconnect();
    session.connect(TimestampNs(110)).unwrap();
    let frame = session
        .encode_logon(&mut adapter, TimestampNs(111), &mut wire)
        .unwrap();
    assert_eq!(frame.sequence, Sequence(41));
    assert_eq!(read_u64(&wire, 17).unwrap(), 71);
    accept_logon(&mut session, &mut adapter, Sequence(71), 112, 113);
    assert_eq!(session.phase(), SessionPhase::Live);
    assert_eq!(session.next_outbound(), Sequence(42));
    assert_eq!(session.expected_inbound(), Sequence(72));
}

#[test]
fn market_data_gap_forces_a_fresh_snapshot() {
    let mut feed = MarketDataFeed::new::<FakeWireAdapter>(Sequence(100)).unwrap();
    let mut adapter = FakeWireAdapter::default();
    let mut output = [None; 1];
    feed.connect().unwrap();
    assert_eq!(feed.phase(), FeedPhase::SnapshotRequired);
    assert_eq!(
        feed.decode_incrementals(
            &mut adapter,
            &market_packet(100, 900),
            TimestampNs(910),
            &mut output,
        ),
        Err(VenueError::InvalidFeedState(FeedPhase::SnapshotRequired))
    );

    feed.begin_snapshot().unwrap();
    let mut snapshot_output = [None; 1];
    feed.decode_snapshot(
        &mut adapter,
        &snapshot_boundary_packet(0x50, 77, 105, 920),
        TimestampNs(930),
        &mut snapshot_output,
    )
    .unwrap();
    feed.decode_snapshot(
        &mut adapter,
        &snapshot_order_packet(940),
        TimestampNs(950),
        &mut snapshot_output,
    )
    .unwrap();
    assert!(matches!(
        snapshot_output[0],
        Some(SnapshotMessage {
            payload: SnapshotPayload::Order(_),
            ..
        })
    ));
    feed.decode_snapshot(
        &mut adapter,
        &snapshot_boundary_packet(0x52, 77, 105, 960),
        TimestampNs(970),
        &mut snapshot_output,
    )
    .unwrap();
    let token = feed.snapshot_apply_token().unwrap();
    assert_eq!(token.snapshot_id(), 77);
    assert_eq!(
        feed.complete_snapshot(token, TimestampNs(969)),
        Err(VenueError::TimestampRegression {
            previous: TimestampNs(970),
            received: TimestampNs(969),
        })
    );
    feed.complete_snapshot(token, TimestampNs(1_000)).unwrap();
    assert_eq!(feed.expected_sequence(), Sequence(106));

    output[0] = Some(sample_market_message(Sequence(106), 1_001, 1_002));
    let before_invalid_time = adapter.codec_state;
    assert_eq!(
        feed.decode_incrementals(
            &mut adapter,
            &market_packet(106, 1_001),
            TimestampNs::ZERO,
            &mut output,
        ),
        Err(VenueError::InvalidTimestamp(TimestampNs::ZERO))
    );
    assert!(output.iter().all(Option::is_none));
    assert_eq!(adapter.codec_state, before_invalid_time);
    assert_eq!(feed.expected_sequence(), Sequence(106));

    let exact = market_packet(106, 1_001);
    feed.decode_incrementals(&mut adapter, &exact, TimestampNs(1_002), &mut output)
        .unwrap();
    assert_eq!(feed.expected_sequence(), Sequence(107));

    let before_zero_progress = adapter.codec_state;
    assert_eq!(
        feed.decode_incrementals(&mut adapter, &[0xFE], TimestampNs(1_003), &mut output,),
        Err(VenueError::DecoderContractViolation {
            messages: 0,
            slots: 1,
            consumed_bytes: 0,
            packet_bytes: 1,
        })
    );
    assert_eq!(adapter.codec_state, before_zero_progress);
    assert!(output.iter().all(Option::is_none));

    let gap = market_packet(109, 1_004);
    assert_eq!(
        feed.decode_incrementals(&mut adapter, &gap, TimestampNs(1_005), &mut output,),
        Err(VenueError::SequenceGap {
            expected: Sequence(107),
            received: Sequence(109),
        })
    );
    assert_eq!(feed.phase(), FeedPhase::SnapshotRequired);
    assert!(output.iter().all(Option::is_none));
}

fn new_order(created_at: TimestampNs) -> OrderCommand {
    OrderCommand::New(NewOrder {
        client_order_id: ClientOrderId(5_001),
        instrument: InstrumentId(9),
        side: Side::Buy,
        price: PriceTicks(12_345),
        quantity: Quantity(17),
        time_in_force: TimeInForce::PostOnly,
        created_at,
    })
}

fn accept_logon(
    session: &mut VenueSession,
    adapter: &mut FakeWireAdapter,
    sequence: Sequence,
    exchange_timestamp: u64,
    receive_timestamp: u64,
) {
    decode_session_event(
        session,
        adapter,
        1,
        sequence,
        exchange_timestamp,
        receive_timestamp,
        None,
    );
}

#[allow(clippy::too_many_arguments)]
fn decode_session_event(
    session: &mut VenueSession,
    adapter: &mut FakeWireAdapter,
    kind: u8,
    sequence: Sequence,
    exchange_timestamp: u64,
    receive_timestamp: u64,
    through: Option<Sequence>,
) {
    let packet = session_packet(kind, sequence, exchange_timestamp, through);
    let mut output = [None; 1];
    session
        .decode_inbound(
            adapter,
            &packet,
            TimestampNs(receive_timestamp),
            &mut output,
        )
        .unwrap();
}

fn decode_fill_event(
    session: &mut VenueSession,
    adapter: &mut FakeWireAdapter,
    sequence: Sequence,
    exchange_timestamp: u64,
    receive_timestamp: u64,
) {
    let packet = fill_packet(sequence, exchange_timestamp);
    let mut output = [None; 1];
    session
        .decode_inbound(
            adapter,
            &packet,
            TimestampNs(receive_timestamp),
            &mut output,
        )
        .unwrap();
    assert!(matches!(
        output[0],
        Some(InboundMessage {
            payload: InboundPayload::Order(OrderEvent::Fill(_)),
            ..
        })
    ));
}

fn session_packet(
    kind: u8,
    sequence: Sequence,
    exchange_timestamp: u64,
    through: Option<Sequence>,
) -> Vec<u8> {
    let size = if through.is_some() { 25 } else { 17 };
    let mut packet = vec![0_u8; size];
    packet[0] = kind;
    write_u64(&mut packet, 1, sequence.0);
    write_u64(&mut packet, 9, exchange_timestamp);
    if let Some(through) = through {
        write_u64(&mut packet, 17, through.0);
    }
    packet
}

fn fill_packet(sequence: Sequence, exchange_timestamp: u64) -> Vec<u8> {
    let mut packet = vec![0_u8; 66];
    packet[0] = 6;
    write_u64(&mut packet, 1, sequence.0);
    write_u64(&mut packet, 9, exchange_timestamp);
    write_u64(&mut packet, 17, 5_001);
    write_u64(&mut packet, 25, 7_001);
    write_u64(&mut packet, 33, 9_001);
    write_i64(&mut packet, 41, 12_345);
    write_i64(&mut packet, 49, 3);
    write_i64(&mut packet, 57, 14);
    packet[65] = LiquidityFlag::Added as u8;
    packet
}

fn market_packet(sequence: u64, exchange_timestamp: u64) -> Vec<u8> {
    let mut packet = vec![0_u8; 46];
    packet[0] = 0x40;
    write_u64(&mut packet, 1, sequence);
    write_u64(&mut packet, 9, exchange_timestamp);
    write_u32(&mut packet, 17, 9);
    write_u64(&mut packet, 21, 8_001);
    packet[29] = Side::Sell as u8;
    write_i64(&mut packet, 30, 12_346);
    write_i64(&mut packet, 38, 100);
    packet
}

fn snapshot_boundary_packet(
    kind: u8,
    snapshot_id: u64,
    last_sequence: u64,
    exchange_timestamp: u64,
) -> Vec<u8> {
    let mut packet = vec![0_u8; 25];
    packet[0] = kind;
    write_u64(&mut packet, 1, exchange_timestamp);
    write_u64(&mut packet, 9, snapshot_id);
    write_u64(&mut packet, 17, last_sequence);
    packet
}

fn snapshot_order_packet(exchange_timestamp: u64) -> Vec<u8> {
    let mut packet = vec![0_u8; 38];
    packet[0] = 0x51;
    write_u64(&mut packet, 1, exchange_timestamp);
    write_u32(&mut packet, 9, 9);
    write_u64(&mut packet, 13, 8_001);
    packet[21] = Side::Sell as u8;
    write_i64(&mut packet, 22, 12_346);
    write_i64(&mut packet, 30, 100);
    packet
}

fn sample_market_message(
    sequence: Sequence,
    exchange_timestamp: u64,
    receive_timestamp: u64,
) -> MarketDataMessage {
    MarketDataMessage {
        instrument: InstrumentId(9),
        sequence,
        exchange_timestamp: TimestampNs(exchange_timestamp),
        hardware_receive_timestamp: TimestampNs(receive_timestamp),
        payload: MarketDataPayload::Book(BookDelta::Clear),
    }
}

fn require_capacity(output: &mut [u8], required: usize) -> Result<(), WireError> {
    if output.len() < required {
        if let Some(first) = output.first_mut() {
            *first = 0xEE;
        }
        return Err(WireError::BufferTooSmall {
            required,
            provided: output.len(),
        });
    }
    Ok(())
}

fn write_u64(output: &mut [u8], offset: usize, value: u64) {
    output[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn write_i64(output: &mut [u8], offset: usize, value: i64) {
    output[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(output: &mut [u8], offset: usize, value: u32) {
    output[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn read_u64(input: &[u8], offset: usize) -> Result<u64, WireError> {
    let bytes = input
        .get(offset..offset + 8)
        .ok_or(WireError::MalformedPacket)?;
    let mut value = [0_u8; 8];
    value.copy_from_slice(bytes);
    Ok(u64::from_le_bytes(value))
}

fn read_i64(input: &[u8], offset: usize) -> Result<i64, WireError> {
    let bytes = input
        .get(offset..offset + 8)
        .ok_or(WireError::MalformedPacket)?;
    let mut value = [0_u8; 8];
    value.copy_from_slice(bytes);
    Ok(i64::from_le_bytes(value))
}

fn read_u32(input: &[u8], offset: usize) -> Result<u32, WireError> {
    let bytes = input
        .get(offset..offset + 4)
        .ok_or(WireError::MalformedPacket)?;
    let mut value = [0_u8; 4];
    value.copy_from_slice(bytes);
    Ok(u32::from_le_bytes(value))
}
