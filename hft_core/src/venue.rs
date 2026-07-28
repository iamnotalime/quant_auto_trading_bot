//! Allocation-free contracts for venue-native market data and order entry.
//!
//! This module deliberately defines a protocol boundary, not a venue adapter. A
//! production adapter must implement the traits below against the venue's certified
//! binary protocol and transport. REST, WebSocket, and Python are not hot-path
//! substitutes for these contracts.

use crate::reference_data::{
    InstrumentDefinition, InstrumentDefinitionError, InstrumentRuleViolation,
};
use crate::types::{InstrumentId, PriceTicks, Quantity, Sequence, Side, TimestampNs, VenueId};

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct ProtocolId(pub u32);

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct SessionId(pub u64);

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct ClientOrderId(pub u64);

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct VenueOrderId(pub u64);

/// Public identifier in the venue's market-by-order feed. This is deliberately a
/// different type from the private order-entry [`VenueOrderId`] namespace.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct MarketByOrderId(pub u64);

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct TradeId(pub u64);

/// Venue-native stable identity for one bust/correction fact. A certified adapter
/// must map both order-entry and drop-copy representations to the same nonzero key.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct LifecycleCorrectionId(pub u64);

/// Digest of the adapter's documented canonical native correction fact. The core
/// uses this only for exact cross-channel identity; authenticity remains an adapter
/// boundary responsibility.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct LifecycleCorrectionDigest(pub [u8; 32]);

impl LifecycleCorrectionDigest {
    #[must_use]
    pub const fn is_valid(self) -> bool {
        let mut index = 0;
        while index < self.0.len() {
            if self.0[index] != 0 {
                return true;
            }
            index += 1;
        }
        false
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum LifecycleCorrectionKind {
    Bust = 1,
    Correct = 2,
}

impl LifecycleCorrectionKind {
    #[must_use]
    pub const fn from_wire(value: u64) -> Option<Self> {
        match value {
            1 => Some(Self::Bust),
            2 => Some(Self::Correct),
            _ => None,
        }
    }
}

/// Authenticated observation that a prior execution was busted or corrected.
///
/// This fact deliberately contains no invented reversal economics. Receipt forces
/// quarantine; financial/lifecycle recovery requires an authoritative venue-specific
/// execution ledger or snapshot outside this generic core.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LifecycleCorrectionObserved {
    pub correction_id: LifecycleCorrectionId,
    pub target_trade_id: TradeId,
    pub kind: LifecycleCorrectionKind,
    pub canonical_payload_digest: LifecycleCorrectionDigest,
}

impl LifecycleCorrectionObserved {
    #[must_use]
    pub const fn is_valid(self) -> bool {
        self.correction_id.0 != 0
            && self.target_trade_id.0 != 0
            && self.canonical_payload_digest.is_valid()
    }
}

/// Certified rule used by a concrete adapter to correlate a private acknowledgement
/// with its public MBO representation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnedMboBindingMethod {
    /// The native order-entry message explicitly carries the public MBO identifier.
    ExplicitNativeIdentifier,
    /// A named, reviewed protocol rule deterministically maps the namespaces.
    CertifiedDeterministicRule { rule_id: u32 },
}

/// Adapter-authenticated one-to-one correlation between private and public order IDs.
/// No generic core code is permitted to infer this relation from numeric equality.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OwnedMboBinding {
    pub venue: VenueId,
    pub client_order_id: ClientOrderId,
    pub venue_order_id: VenueOrderId,
    pub market_by_order_id: MarketByOrderId,
    pub order_entry_sequence: Sequence,
    pub method: OwnedMboBindingMethod,
}

impl OwnedMboBinding {
    #[must_use]
    pub const fn is_valid(self) -> bool {
        self.venue.0 != 0
            && self.client_order_id.0 != 0
            && self.venue_order_id.0 != 0
            && self.market_by_order_id.0 != 0
            && self.order_entry_sequence.0 != 0
            && match self.method {
                OwnedMboBindingMethod::ExplicitNativeIdentifier => true,
                OwnedMboBindingMethod::CertifiedDeterministicRule { rule_id } => rule_id != 0,
            }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct RejectCode(pub u32);

/// Immutable protocol and session identity supplied by a concrete adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VenueIdentity {
    pub venue: VenueId,
    pub market_data_protocol: ProtocolId,
    pub order_entry_protocol: ProtocolId,
    pub session: SessionId,
}

impl VenueIdentity {
    #[must_use]
    pub const fn is_valid(self) -> bool {
        self.venue.0 != 0
            && self.market_data_protocol.0 != 0
            && self.order_entry_protocol.0 != 0
            && self.session.0 != 0
    }
}

/// Adapter capabilities declared as a compact bit set.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(transparent)]
pub struct VenueCapabilities(u32);

impl VenueCapabilities {
    pub const NONE: Self = Self(0);
    pub const MARKET_DATA_L3: Self = Self(1 << 0);
    pub const NEW_ORDER: Self = Self(1 << 1);
    pub const CANCEL_ORDER: Self = Self(1 << 2);
    pub const REPLACE_ORDER: Self = Self(1 << 3);
    pub const HEARTBEAT: Self = Self(1 << 4);
    pub const SEQUENCE_REPLAY: Self = Self(1 << 5);
    pub const SNAPSHOT_RECOVERY: Self = Self(1 << 6);
    pub const CANCEL_ALL: Self = Self(1 << 7);
    pub const CANCEL_ON_DISCONNECT: Self = Self(1 << 8);
    pub const OWNED_MBO_CORRELATION: Self = Self(1 << 9);

    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    #[must_use]
    pub const fn contains(self, required: Self) -> bool {
        (self.0 & required.0) == required.0
    }

    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum TimeInForce {
    Day = 1,
    ImmediateOrCancel = 2,
    FillOrKill = 3,
    GoodTillCancel = 4,
    PostOnly = 5,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NewOrder {
    pub client_order_id: ClientOrderId,
    pub instrument: InstrumentId,
    pub side: Side,
    pub price: PriceTicks,
    pub quantity: Quantity,
    pub time_in_force: TimeInForce,
    pub created_at: TimestampNs,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CancelOrder {
    pub client_order_id: ClientOrderId,
    pub venue_order_id: VenueOrderId,
    pub created_at: TimestampNs,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplaceOrder {
    pub current_client_order_id: ClientOrderId,
    pub replacement_client_order_id: ClientOrderId,
    pub venue_order_id: VenueOrderId,
    pub new_price: PriceTicks,
    pub new_quantity: Quantity,
    pub created_at: TimestampNs,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CancelScope {
    Session,
    Instrument(InstrumentId),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CancelAll {
    pub scope: CancelScope,
    pub created_at: TimestampNs,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OrderCommand {
    New(NewOrder),
    Cancel(CancelOrder),
    Replace(ReplaceOrder),
    CancelAll(CancelAll),
}

impl OrderCommand {
    const fn required_capability(self) -> VenueCapabilities {
        match self {
            Self::New(_) => VenueCapabilities::NEW_ORDER,
            Self::Cancel(_) => VenueCapabilities::CANCEL_ORDER,
            Self::Replace(_) => VenueCapabilities::REPLACE_ORDER,
            Self::CancelAll(_) => VenueCapabilities::CANCEL_ALL,
        }
    }

    pub(crate) fn validate(self) -> Result<(), VenueError> {
        match self {
            Self::New(order) => {
                if order.client_order_id.0 == 0
                    || order.instrument.0 == 0
                    || !order.price.is_positive()
                    || !order.quantity.is_positive()
                {
                    return Err(VenueError::InvalidOrderCommand);
                }
                validate_timestamp(order.created_at)
            }
            Self::Cancel(order) => {
                if order.client_order_id.0 == 0 || order.venue_order_id.0 == 0 {
                    return Err(VenueError::InvalidOrderCommand);
                }
                validate_timestamp(order.created_at)
            }
            Self::Replace(order) => {
                if order.current_client_order_id.0 == 0
                    || order.replacement_client_order_id.0 == 0
                    || order.current_client_order_id == order.replacement_client_order_id
                    || order.venue_order_id.0 == 0
                    || !order.new_price.is_positive()
                    || !order.new_quantity.is_positive()
                {
                    return Err(VenueError::InvalidOrderCommand);
                }
                validate_timestamp(order.created_at)
            }
            Self::CancelAll(command) => {
                if matches!(command.scope, CancelScope::Instrument(instrument) if instrument.0 == 0)
                {
                    return Err(VenueError::InvalidOrderCommand);
                }
                validate_timestamp(command.created_at)
            }
        }
    }

    const fn timestamp(self) -> TimestampNs {
        match self {
            Self::New(order) => order.created_at,
            Self::Cancel(order) => order.created_at,
            Self::Replace(order) => order.created_at,
            Self::CancelAll(command) => command.created_at,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Accepted {
    pub client_order_id: ClientOrderId,
    pub venue_order_id: VenueOrderId,
    pub price: PriceTicks,
    pub quantity: Quantity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Rejected {
    pub client_order_id: ClientOrderId,
    pub code: RejectCode,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Canceled {
    pub client_order_id: ClientOrderId,
    pub venue_order_id: VenueOrderId,
    pub canceled_quantity: Quantity,
    pub leaves_quantity: Quantity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum LiquidityFlag {
    Added = 1,
    Removed = 2,
    Unknown = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Fill {
    pub client_order_id: ClientOrderId,
    pub venue_order_id: VenueOrderId,
    pub trade_id: TradeId,
    pub price: PriceTicks,
    pub quantity: Quantity,
    pub leaves_quantity: Quantity,
    pub liquidity: LiquidityFlag,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OrderEvent {
    Accepted(Accepted),
    Rejected(Rejected),
    Canceled(Canceled),
    Fill(Fill),
    LifecycleCorrectionObserved(LifecycleCorrectionObserved),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LogonRequest {
    pub session: SessionId,
    pub next_expected_inbound: Sequence,
    pub sent_at: TimestampNs,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Heartbeat {
    pub sent_at: TimestampNs,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplayRequest {
    pub from: Sequence,
    pub through: Sequence,
    pub sent_at: TimestampNs,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CancelOnDisconnect {
    pub enabled: bool,
    pub sent_at: TimestampNs,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionCommand {
    Logon(LogonRequest),
    Heartbeat(Heartbeat),
    Replay(ReplayRequest),
    CancelOnDisconnect(CancelOnDisconnect),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionEvent {
    LogonAccepted,
    LogonRejected { code: RejectCode },
    Heartbeat,
    ReplayComplete { through: Sequence },
    SnapshotRequired,
    Logout { code: RejectCode },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InboundPayload {
    Session(SessionEvent),
    Order(OrderEvent),
}

/// A decoded order-entry message with both exchange and local hardware timestamps.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InboundMessage {
    pub sequence: Sequence,
    pub exchange_timestamp: TimestampNs,
    pub hardware_receive_timestamp: TimestampNs,
    pub payload: InboundPayload,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BookDelta {
    Add {
        order_id: MarketByOrderId,
        side: Side,
        price: PriceTicks,
        quantity: Quantity,
    },
    Modify {
        order_id: MarketByOrderId,
        price: PriceTicks,
        quantity: Quantity,
    },
    Cancel {
        order_id: MarketByOrderId,
    },
    Execute {
        order_id: MarketByOrderId,
        price: PriceTicks,
        quantity: Quantity,
    },
    Clear,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MarketDataPayload {
    Book(BookDelta),
    Trade {
        trade_id: TradeId,
        side: Side,
        price: PriceTicks,
        quantity: Quantity,
    },
    TradingStatus {
        status_code: u16,
    },
}

/// One normalized market-data event. A concrete decoder must retain both clocks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MarketDataMessage {
    pub instrument: InstrumentId,
    pub sequence: Sequence,
    pub exchange_timestamp: TimestampNs,
    pub hardware_receive_timestamp: TimestampNs,
    pub payload: MarketDataPayload,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SnapshotOrder {
    pub instrument: InstrumentId,
    pub order_id: MarketByOrderId,
    pub side: Side,
    pub price: PriceTicks,
    pub quantity: Quantity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SnapshotPayload {
    Begin {
        snapshot_id: u64,
        last_incremental_sequence: Sequence,
    },
    Order(SnapshotOrder),
    End {
        snapshot_id: u64,
        last_incremental_sequence: Sequence,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SnapshotMessage {
    pub exchange_timestamp: TimestampNs,
    pub hardware_receive_timestamp: TimestampNs,
    pub payload: SnapshotPayload,
}

/// Proof that a complete, matching begin/end snapshot was decoded. The caller
/// returns this token only after applying every decoded [`SnapshotOrder`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SnapshotApplyToken {
    snapshot_id: u64,
    last_incremental_sequence: Sequence,
}

impl SnapshotApplyToken {
    #[must_use]
    pub const fn snapshot_id(self) -> u64 {
        self.snapshot_id
    }

    #[must_use]
    pub const fn last_incremental_sequence(self) -> Sequence {
        self.last_incremental_sequence
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecodeResult {
    pub messages: usize,
    pub consumed_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CorrelationResult {
    pub bindings: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WireError {
    BufferTooSmall { required: usize, provided: usize },
    MalformedPacket,
    UnsupportedMessage { message_type: u16 },
    InvalidField,
}

/// Static identity and capabilities shared by all native protocol components.
pub trait VenueDescriptor {
    const IDENTITY: VenueIdentity;
    const CAPABILITIES: VenueCapabilities;
}

/// Transaction boundary for codec state.
///
/// A checkpoint is a durable, full-state savepoint covering every mutable parser,
/// encoder, authentication, anti-replay, and protocol counter. Checkpoints may be
/// nested: a later venue call, later checkpoint, or [`Self::commit`] of a nested
/// transaction must not invalidate an older checkpoint. Restoring an older
/// checkpoint must undo every intervening parser, authentication, and sequence-state
/// mutation. The core relies on that durability when a native frame is rejected
/// after one or more individually successful venue calls.
pub trait TransactionalCodec: VenueDescriptor {
    type Checkpoint: Copy;

    fn checkpoint(&self) -> Self::Checkpoint;
    fn restore(&mut self, checkpoint: Self::Checkpoint);

    fn commit(&mut self, _checkpoint: Self::Checkpoint) {}
}

/// Allocation-free direct-feed decoder. `packet` and `output` are caller-owned.
pub trait DirectMarketDataDecoder: TransactionalCodec {
    /// Decode one native market-data packet into a caller-provided fixed slice.
    /// Implementations must populate exactly the contiguous prefix reported by
    /// [`DecodeResult::messages`] and leave every unused output slot as [`None`].
    ///
    /// # Errors
    ///
    /// Returns [`WireError`] for malformed, unsupported, or capacity-limited input.
    fn decode_market_data(
        &mut self,
        packet: &[u8],
        hardware_receive_timestamp: TimestampNs,
        output: &mut [Option<MarketDataMessage>],
    ) -> Result<DecodeResult, WireError>;

    /// Decode the venue's native recovery snapshot into caller-owned slots.
    /// Implementations must populate exactly the contiguous prefix reported by
    /// [`DecodeResult::messages`] and leave every unused output slot as [`None`].
    ///
    /// # Errors
    ///
    /// Returns [`WireError`] for malformed, unsupported, or capacity-limited input.
    fn decode_snapshot(
        &mut self,
        packet: &[u8],
        hardware_receive_timestamp: TimestampNs,
        output: &mut [Option<SnapshotMessage>],
    ) -> Result<DecodeResult, WireError>;
}

/// Allocation-free native order-entry encoder using only caller-owned byte storage.
pub trait NativeOrderEntryEncoder: TransactionalCodec {
    /// Encode one session command at the supplied client sequence.
    ///
    /// # Errors
    ///
    /// Returns [`WireError`] without consuming the sequence when encoding fails.
    fn encode_session(
        &mut self,
        sequence: Sequence,
        command: SessionCommand,
        output: &mut [u8],
    ) -> Result<usize, WireError>;

    /// Encode one typed order command at the supplied client sequence. The exact
    /// immutable instrument definition is supplied explicitly so the adapter can map
    /// the native product, scales, and mandatory self-trade-prevention instruction;
    /// it must not consult mutable process-global reference data.
    ///
    /// # Errors
    ///
    /// Returns [`WireError`] without consuming the sequence when encoding fails.
    fn encode_order(
        &mut self,
        sequence: Sequence,
        command: OrderCommand,
        instrument: InstrumentDefinition,
        output: &mut [u8],
    ) -> Result<usize, WireError>;
}

/// Allocation-free decoder for native order acknowledgements and session traffic.
pub trait NativeOrderEntryDecoder: TransactionalCodec {
    /// Decode one native order-entry packet into caller-provided event slots.
    /// Implementations must populate exactly the contiguous prefix reported by
    /// [`DecodeResult::messages`] and leave every unused output slot as [`None`].
    ///
    /// # Errors
    ///
    /// Returns [`WireError`] for malformed, unsupported, or capacity-limited input.
    fn decode_order_entry(
        &mut self,
        packet: &[u8],
        hardware_receive_timestamp: TimestampNs,
        output: &mut [Option<InboundMessage>],
    ) -> Result<DecodeResult, WireError>;
}

/// Venue-specific, allocation-free merger of private order-entry identity and public
/// MBO identity. Implementations must use a licensed native field or a named certified
/// deterministic rule; numeric equality alone is forbidden.
///
/// Calls are part of the adapter transaction governed by [`TransactionalCodec`]. The
/// caller restores the checkpoint if a returned binding cannot be queued atomically.
pub trait NativeOwnedMboCorrelator: TransactionalCodec {
    /// Observe one accepted native order-entry input and emit zero or more newly proven
    /// bindings into caller-owned slots.
    ///
    /// # Errors
    ///
    /// Returns a wire error for invalid correlation state or insufficient output.
    fn correlate_order_entry(
        &mut self,
        message: InboundMessage,
        output: &mut [Option<OwnedMboBinding>],
    ) -> Result<CorrelationResult, WireError>;

    /// Observe one public incremental and emit newly proven bindings.
    ///
    /// # Errors
    ///
    /// Returns a wire error for invalid correlation state or insufficient output.
    fn correlate_market_data(
        &mut self,
        message: MarketDataMessage,
        output: &mut [Option<OwnedMboBinding>],
    ) -> Result<CorrelationResult, WireError>;

    /// Observe one snapshot item during recovery and emit newly proven bindings.
    ///
    /// # Errors
    ///
    /// Returns a wire error for invalid correlation state or insufficient output.
    fn correlate_snapshot(
        &mut self,
        message: SnapshotMessage,
        output: &mut [Option<OwnedMboBinding>],
    ) -> Result<CorrelationResult, WireError>;
}

/// Compile-time contract required of a concrete, direct venue adapter.
pub trait DirectVenueAdapter:
    DirectMarketDataDecoder + NativeOrderEntryEncoder + NativeOrderEntryDecoder
{
}

impl<T> DirectVenueAdapter for T where
    T: DirectMarketDataDecoder + NativeOrderEntryEncoder + NativeOrderEntryDecoder
{
}

/// Stronger adapter contract required before selecting the exact owned-order MBO
/// queue model.
pub trait DirectExactMboVenueAdapter: DirectVenueAdapter + NativeOwnedMboCorrelator {}

impl<T> DirectExactMboVenueAdapter for T where T: DirectVenueAdapter + NativeOwnedMboCorrelator {}

/// Validate the static descriptor required by the exact owned-order MBO model.
///
/// # Errors
///
/// Returns an identity or missing-capability error before any transport is opened.
pub fn validate_exact_mbo_adapter<A: DirectExactMboVenueAdapter>() -> Result<(), VenueError> {
    if !A::IDENTITY.is_valid() {
        return Err(VenueError::InvalidIdentity);
    }
    let required =
        VenueCapabilities::MARKET_DATA_L3.union(VenueCapabilities::OWNED_MBO_CORRELATION);
    if !A::CAPABILITIES.contains(required) {
        return Err(VenueError::MissingCapability { required });
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionPhase {
    Disconnected,
    AwaitingLogon,
    Live,
    RecoveryRequired,
    Recovering,
    SnapshotRequired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FeedPhase {
    Disconnected,
    SnapshotRequired,
    ApplyingSnapshot,
    Live,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VenueError {
    InvalidIdentity,
    InstrumentDefinition(InstrumentDefinitionError),
    InstrumentRule(InstrumentRuleViolation),
    AdapterDescriptorMismatch {
        expected_identity: VenueIdentity,
        actual_identity: VenueIdentity,
        expected_capabilities: VenueCapabilities,
        actual_capabilities: VenueCapabilities,
    },
    InvalidConfiguration,
    MissingCapability {
        required: VenueCapabilities,
    },
    InvalidTimestamp(TimestampNs),
    TimestampRegression {
        previous: TimestampNs,
        received: TimestampNs,
    },
    InvalidOrderCommand,
    InvalidInboundMessage,
    InvalidMarketDataMessage,
    InvalidSnapshotMessage,
    InvalidSessionState(SessionPhase),
    InvalidFeedState(FeedPhase),
    Wire(WireError),
    EncoderContractViolation {
        bytes: usize,
        capacity: usize,
    },
    DecoderContractViolation {
        messages: usize,
        slots: usize,
        consumed_bytes: usize,
        packet_bytes: usize,
    },
    EmptyDecodedSlot {
        index: usize,
    },
    NonEmptyDecodedTail {
        index: usize,
        reported_messages: usize,
    },
    OutboundSequenceExhausted,
    InboundSequenceExhausted,
    DuplicateSequence {
        expected: Sequence,
        received: Sequence,
    },
    SequenceGap {
        expected: Sequence,
        received: Sequence,
    },
    InvalidReplayCompletion {
        expected_through: Sequence,
        received_through: Sequence,
    },
    HeartbeatExpired {
        last_received: TimestampNs,
        checked_at: TimestampNs,
    },
    LogonTimeout {
        connected_at: TimestampNs,
        checked_at: TimestampNs,
    },
    SnapshotNotReady,
    InvalidSnapshotSequence {
        current_expected: Sequence,
        snapshot_last: Sequence,
    },
}

impl From<WireError> for VenueError {
    fn from(error: WireError) -> Self {
        Self::Wire(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EncodedFrame {
    pub sequence: Sequence,
    pub bytes: usize,
}

/// Order-entry session sequencing and fail-closed state transitions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VenueSession {
    identity: VenueIdentity,
    capabilities: VenueCapabilities,
    instrument_definition: InstrumentDefinition,
    phase: SessionPhase,
    next_outbound: Sequence,
    expected_inbound: Sequence,
    recovery_through: Option<Sequence>,
    last_outbound: TimestampNs,
    last_inbound: TimestampNs,
    connected_at: TimestampNs,
    heartbeat_timeout_ns: u64,
}

impl VenueSession {
    /// Construct a session from the concrete adapter's static descriptor.
    ///
    /// # Errors
    ///
    /// Returns [`VenueError`] for invalid identity, zero sequences, or a zero timeout.
    pub fn new<A: VenueDescriptor>(
        first_outbound: Sequence,
        first_inbound: Sequence,
        heartbeat_timeout_ns: u64,
        instrument_definition: InstrumentDefinition,
    ) -> Result<Self, VenueError> {
        if !A::IDENTITY.is_valid() {
            return Err(VenueError::InvalidIdentity);
        }
        instrument_definition
            .validate()
            .map_err(VenueError::InstrumentDefinition)?;
        if instrument_definition.venue != A::IDENTITY.venue {
            return Err(VenueError::InstrumentRule(
                InstrumentRuleViolation::VenueMismatch {
                    expected: instrument_definition.venue,
                    received: A::IDENTITY.venue,
                },
            ));
        }
        if instrument_definition.cancel_on_disconnect_required
            && !A::CAPABILITIES.contains(VenueCapabilities::CANCEL_ON_DISCONNECT)
        {
            return Err(VenueError::MissingCapability {
                required: VenueCapabilities::CANCEL_ON_DISCONNECT,
            });
        }
        if first_outbound.0 == 0 || first_inbound.0 == 0 || heartbeat_timeout_ns == 0 {
            return Err(VenueError::InvalidConfiguration);
        }
        Ok(Self {
            identity: A::IDENTITY,
            capabilities: A::CAPABILITIES,
            instrument_definition,
            phase: SessionPhase::Disconnected,
            next_outbound: first_outbound,
            expected_inbound: first_inbound,
            recovery_through: None,
            last_outbound: TimestampNs::ZERO,
            last_inbound: TimestampNs::ZERO,
            connected_at: TimestampNs::ZERO,
            heartbeat_timeout_ns,
        })
    }

    #[must_use]
    pub const fn identity(self) -> VenueIdentity {
        self.identity
    }

    #[must_use]
    pub const fn capabilities(self) -> VenueCapabilities {
        self.capabilities
    }

    #[must_use]
    pub const fn instrument_definition(self) -> InstrumentDefinition {
        self.instrument_definition
    }

    #[must_use]
    pub const fn phase(self) -> SessionPhase {
        self.phase
    }

    #[must_use]
    pub const fn next_outbound(self) -> Sequence {
        self.next_outbound
    }

    #[must_use]
    pub const fn expected_inbound(self) -> Sequence {
        self.expected_inbound
    }

    #[must_use]
    pub const fn recovery_through(self) -> Option<Sequence> {
        self.recovery_through
    }

    /// Enter the transport-connected state without resetting either sequence.
    ///
    /// # Errors
    ///
    /// Returns [`VenueError`] unless disconnected or the timestamp is invalid.
    pub fn connect(&mut self, now: TimestampNs) -> Result<(), VenueError> {
        validate_timestamp(now)?;
        if self.phase != SessionPhase::Disconnected {
            return Err(VenueError::InvalidSessionState(self.phase));
        }
        self.connected_at = now;
        self.phase = SessionPhase::AwaitingLogon;
        Ok(())
    }

    /// Record a transport disconnect while retaining recovery sequences.
    pub fn disconnect(&mut self) {
        self.phase = SessionPhase::Disconnected;
        self.recovery_through = None;
        self.connected_at = TimestampNs::ZERO;
    }

    /// Encode a native logon. The client sequence advances only on success.
    ///
    /// # Errors
    ///
    /// Returns [`VenueError`] on state, timestamp, adapter, capacity, or sequence faults.
    pub fn encode_logon<A: NativeOrderEntryEncoder>(
        &mut self,
        adapter: &mut A,
        now: TimestampNs,
        output: &mut [u8],
    ) -> Result<EncodedFrame, VenueError> {
        clear_bytes(output);
        self.verify_adapter::<A>()?;
        if self.phase != SessionPhase::AwaitingLogon {
            clear_bytes(output);
            return Err(VenueError::InvalidSessionState(self.phase));
        }
        self.validate_outbound_timestamp(now, output)?;
        let command = SessionCommand::Logon(LogonRequest {
            session: self.identity.session,
            next_expected_inbound: self.expected_inbound,
            sent_at: now,
        });
        self.encode_session_command(adapter, command, now, output)
    }

    /// Encode a heartbeat while a logged-on session is usable.
    ///
    /// # Errors
    ///
    /// Returns [`VenueError`] on state, capability, timestamp, adapter, or wire faults.
    pub fn encode_heartbeat<A: NativeOrderEntryEncoder>(
        &mut self,
        adapter: &mut A,
        now: TimestampNs,
        output: &mut [u8],
    ) -> Result<EncodedFrame, VenueError> {
        clear_bytes(output);
        self.verify_adapter::<A>()?;
        if !matches!(
            self.phase,
            SessionPhase::Live
                | SessionPhase::RecoveryRequired
                | SessionPhase::Recovering
                | SessionPhase::SnapshotRequired
        ) {
            clear_bytes(output);
            return Err(VenueError::InvalidSessionState(self.phase));
        }
        self.require_capability(VenueCapabilities::HEARTBEAT, output)?;
        self.validate_outbound_timestamp(now, output)?;
        self.encode_session_command(
            adapter,
            SessionCommand::Heartbeat(Heartbeat { sent_at: now }),
            now,
            output,
        )
    }

    /// Request the exact missing inclusive sequence range after a detected gap.
    ///
    /// # Errors
    ///
    /// Returns [`VenueError`] on state, capability, timestamp, adapter, or wire faults.
    pub fn encode_replay_request<A: NativeOrderEntryEncoder>(
        &mut self,
        adapter: &mut A,
        now: TimestampNs,
        output: &mut [u8],
    ) -> Result<EncodedFrame, VenueError> {
        clear_bytes(output);
        self.verify_adapter::<A>()?;
        if self.phase != SessionPhase::RecoveryRequired {
            clear_bytes(output);
            return Err(VenueError::InvalidSessionState(self.phase));
        }
        self.require_capability(VenueCapabilities::SEQUENCE_REPLAY, output)?;
        self.validate_outbound_timestamp(now, output)?;
        let through = self
            .recovery_through
            .ok_or(VenueError::InvalidSessionState(self.phase))?;
        let command = SessionCommand::Replay(ReplayRequest {
            from: self.expected_inbound,
            through,
            sent_at: now,
        });
        let frame = self.encode_session_command(adapter, command, now, output)?;
        self.phase = SessionPhase::Recovering;
        Ok(frame)
    }

    /// Encode a typed order only while the session is fully live.
    ///
    /// # Errors
    ///
    /// Returns [`VenueError`] on state, validation, capability, capacity, or wire faults.
    pub fn encode_order<A: NativeOrderEntryEncoder>(
        &mut self,
        adapter: &mut A,
        command: OrderCommand,
        output: &mut [u8],
    ) -> Result<EncodedFrame, VenueError> {
        clear_bytes(output);
        self.verify_adapter::<A>()?;
        if self.phase != SessionPhase::Live {
            return Err(VenueError::InvalidSessionState(self.phase));
        }
        self.encode_validated_order(adapter, command, output)
    }

    /// Encode a session- or instrument-scoped emergency cancel while logged on,
    /// including during replay or snapshot recovery.
    ///
    /// # Errors
    ///
    /// Returns [`VenueError`] on state, validation, capability, capacity, or wire faults.
    pub fn encode_cancel_all<A: NativeOrderEntryEncoder>(
        &mut self,
        adapter: &mut A,
        command: CancelAll,
        output: &mut [u8],
    ) -> Result<EncodedFrame, VenueError> {
        clear_bytes(output);
        self.verify_adapter::<A>()?;
        if !matches!(
            self.phase,
            SessionPhase::Live
                | SessionPhase::RecoveryRequired
                | SessionPhase::Recovering
                | SessionPhase::SnapshotRequired
        ) {
            return Err(VenueError::InvalidSessionState(self.phase));
        }
        self.encode_validated_order(adapter, OrderCommand::CancelAll(command), output)
    }

    /// Configure venue-native cancel-on-disconnect protection for this session.
    ///
    /// # Errors
    ///
    /// Returns [`VenueError`] on state, timestamp, capability, capacity, or wire faults.
    pub fn encode_cancel_on_disconnect<A: NativeOrderEntryEncoder>(
        &mut self,
        adapter: &mut A,
        command: CancelOnDisconnect,
        output: &mut [u8],
    ) -> Result<EncodedFrame, VenueError> {
        clear_bytes(output);
        self.verify_adapter::<A>()?;
        if self.phase != SessionPhase::Live {
            return Err(VenueError::InvalidSessionState(self.phase));
        }
        self.require_capability(VenueCapabilities::CANCEL_ON_DISCONNECT, output)?;
        self.validate_outbound_timestamp(command.sent_at, output)?;
        self.encode_session_command(
            adapter,
            SessionCommand::CancelOnDisconnect(command),
            command.sent_at,
            output,
        )
    }

    fn encode_validated_order<A: NativeOrderEntryEncoder>(
        &mut self,
        adapter: &mut A,
        command: OrderCommand,
        output: &mut [u8],
    ) -> Result<EncodedFrame, VenueError> {
        self.require_capability(command.required_capability(), output)?;
        if let Err(error) = command.validate() {
            clear_bytes(output);
            return Err(error);
        }
        let now = command.timestamp();
        self.validate_outbound_timestamp(now, output)?;
        if let Err(error) = self.validate_instrument_rules(command, now) {
            clear_bytes(output);
            return Err(error);
        }
        let sequence = self.next_outbound;
        let next_outbound = self.preflight_outbound_sequence(output)?;
        let checkpoint = adapter.checkpoint();
        let encoded = adapter.encode_order(sequence, command, self.instrument_definition, output);
        self.finish_encode(
            adapter,
            checkpoint,
            encoded,
            sequence,
            next_outbound,
            now,
            output,
        )
    }

    /// Decode and atomically validate a native inbound packet.
    ///
    /// Exact sequences are committed as one batch. Duplicate packets are rejected.
    /// A gap rejects the whole packet and moves the session to recovery-required.
    ///
    /// # Errors
    ///
    /// Returns [`VenueError`] on decoding, timestamp, session, or sequence faults.
    pub fn decode_inbound<A: NativeOrderEntryDecoder>(
        &mut self,
        adapter: &mut A,
        packet: &[u8],
        hardware_receive_timestamp: TimestampNs,
        output: &mut [Option<InboundMessage>],
    ) -> Result<DecodeResult, VenueError> {
        clear_slots(output);
        self.verify_adapter::<A>()?;
        if self.phase == SessionPhase::Disconnected {
            return Err(VenueError::InvalidSessionState(self.phase));
        }
        validate_timestamp(hardware_receive_timestamp)?;
        let checkpoint = adapter.checkpoint();
        let decoded = match adapter.decode_order_entry(packet, hardware_receive_timestamp, output) {
            Ok(result) => result,
            Err(error) => {
                adapter.restore(checkpoint);
                clear_slots(output);
                return Err(error.into());
            }
        };
        if let Err(error) = validate_decode_output(decoded, output, packet.len()) {
            adapter.restore(checkpoint);
            clear_slots(output);
            return Err(error);
        }
        if let Err(error) =
            self.preflight_inbound_batch(&output[..decoded.messages], hardware_receive_timestamp)
        {
            adapter.restore(checkpoint);
            clear_slots(output);
            return Err(error);
        }
        if let Err(error) = self.commit_inbound_batch(&output[..decoded.messages]) {
            adapter.restore(checkpoint);
            clear_slots(output);
            return Err(error);
        }
        adapter.commit(checkpoint);
        Ok(decoded)
    }

    fn preflight_inbound_batch(
        &mut self,
        messages: &[Option<InboundMessage>],
        hardware_receive_timestamp: TimestampNs,
    ) -> Result<(), VenueError> {
        let mut highest_sequence = self.expected_inbound;
        for (index, slot) in messages.iter().enumerate() {
            let Some(message) = slot.as_ref() else {
                return Err(VenueError::EmptyDecodedSlot { index });
            };
            validate_inbound_timestamp(
                message.exchange_timestamp,
                message.hardware_receive_timestamp,
                hardware_receive_timestamp,
                self.last_inbound,
            )?;
            if !valid_inbound_payload(message.payload) {
                return Err(VenueError::InvalidInboundMessage);
            }
            highest_sequence = highest_sequence.max(message.sequence);
        }

        let mut next = self.expected_inbound;
        for (index, slot) in messages.iter().enumerate() {
            let Some(message) = slot.as_ref() else {
                return Err(VenueError::EmptyDecodedSlot { index });
            };
            if message.sequence < next {
                if index > 0 {
                    self.require_replay_or_snapshot(highest_sequence);
                }
                return Err(VenueError::DuplicateSequence {
                    expected: self.expected_inbound,
                    received: message.sequence,
                });
            }
            if message.sequence > next {
                let received = message.sequence;
                self.require_replay_or_snapshot(highest_sequence);
                return Err(VenueError::SequenceGap {
                    expected: self.expected_inbound,
                    received,
                });
            }
            next = Sequence(
                next.0
                    .checked_add(1)
                    .ok_or(VenueError::InboundSequenceExhausted)?,
            );
        }
        Ok(())
    }

    fn require_replay_or_snapshot(&mut self, replay_through: Sequence) {
        if self
            .capabilities
            .contains(VenueCapabilities::SEQUENCE_REPLAY)
        {
            self.phase = SessionPhase::RecoveryRequired;
            self.recovery_through = Some(replay_through);
        } else {
            self.phase = SessionPhase::SnapshotRequired;
            self.recovery_through = None;
        }
    }

    fn commit_inbound_batch(
        &mut self,
        messages: &[Option<InboundMessage>],
    ) -> Result<(), VenueError> {
        let mut candidate = *self;
        for (index, slot) in messages.iter().enumerate() {
            let Some(message) = slot.as_ref() else {
                return Err(VenueError::EmptyDecodedSlot { index });
            };
            candidate.apply_inbound(*message)?;
        }
        *self = candidate;
        Ok(())
    }

    /// Mark an externally reconciled order snapshot complete without skipping sequence.
    ///
    /// # Errors
    ///
    /// Returns [`VenueError`] unless snapshot recovery is active and `now` is valid.
    pub fn complete_snapshot(&mut self, now: TimestampNs) -> Result<(), VenueError> {
        if self.phase != SessionPhase::SnapshotRequired {
            return Err(VenueError::InvalidSessionState(self.phase));
        }
        self.require_capability_without_buffer(VenueCapabilities::SNAPSHOT_RECOVERY)?;
        validate_timestamp(now)?;
        if now < self.last_inbound {
            return Err(VenueError::TimestampRegression {
                previous: self.last_inbound,
                received: now,
            });
        }
        self.last_inbound = now;
        self.phase = SessionPhase::Live;
        Ok(())
    }

    /// Enforce the configured liveness timeout and disconnect on expiration.
    ///
    /// # Errors
    ///
    /// Returns [`VenueError::HeartbeatExpired`] after transitioning to disconnected,
    /// or another [`VenueError`] for an invalid/regressing timestamp.
    pub fn check_heartbeat(&mut self, now: TimestampNs) -> Result<(), VenueError> {
        validate_timestamp(now)?;
        if self.phase == SessionPhase::AwaitingLogon {
            if now < self.connected_at {
                return Err(VenueError::TimestampRegression {
                    previous: self.connected_at,
                    received: now,
                });
            }
            if now.saturating_duration_since(self.connected_at) > self.heartbeat_timeout_ns {
                let connected_at = self.connected_at;
                self.disconnect();
                return Err(VenueError::LogonTimeout {
                    connected_at,
                    checked_at: now,
                });
            }
            return Ok(());
        }
        if self.last_inbound != TimestampNs::ZERO && now < self.last_inbound {
            return Err(VenueError::TimestampRegression {
                previous: self.last_inbound,
                received: now,
            });
        }
        if self.phase != SessionPhase::Disconnected
            && self.last_inbound != TimestampNs::ZERO
            && now.saturating_duration_since(self.last_inbound) > self.heartbeat_timeout_ns
        {
            let last_received = self.last_inbound;
            self.disconnect();
            return Err(VenueError::HeartbeatExpired {
                last_received,
                checked_at: now,
            });
        }
        Ok(())
    }

    fn apply_inbound(&mut self, message: InboundMessage) -> Result<(), VenueError> {
        match message.payload {
            InboundPayload::Session(event) => self.apply_session_event(event)?,
            InboundPayload::Order(_) => {
                if !matches!(self.phase, SessionPhase::Live | SessionPhase::Recovering) {
                    return Err(VenueError::InvalidSessionState(self.phase));
                }
            }
        }
        self.expected_inbound = Sequence(
            self.expected_inbound
                .0
                .checked_add(1)
                .ok_or(VenueError::InboundSequenceExhausted)?,
        );
        self.last_inbound = message.hardware_receive_timestamp;
        Ok(())
    }

    fn apply_session_event(&mut self, event: SessionEvent) -> Result<(), VenueError> {
        match event {
            SessionEvent::LogonAccepted => {
                if self.phase != SessionPhase::AwaitingLogon {
                    return Err(VenueError::InvalidSessionState(self.phase));
                }
                self.connected_at = TimestampNs::ZERO;
                self.phase = SessionPhase::Live;
            }
            SessionEvent::LogonRejected { .. } | SessionEvent::Logout { .. } => {
                self.phase = SessionPhase::Disconnected;
                self.recovery_through = None;
            }
            SessionEvent::Heartbeat => {
                if !matches!(
                    self.phase,
                    SessionPhase::Live
                        | SessionPhase::RecoveryRequired
                        | SessionPhase::Recovering
                        | SessionPhase::SnapshotRequired
                ) {
                    return Err(VenueError::InvalidSessionState(self.phase));
                }
            }
            SessionEvent::ReplayComplete { through } => {
                if self.phase != SessionPhase::Recovering {
                    return Err(VenueError::InvalidSessionState(self.phase));
                }
                let expected_through = self
                    .recovery_through
                    .ok_or(VenueError::InvalidSessionState(self.phase))?;
                if through != expected_through {
                    return Err(VenueError::InvalidReplayCompletion {
                        expected_through,
                        received_through: through,
                    });
                }
                self.phase = SessionPhase::Live;
                self.recovery_through = None;
            }
            SessionEvent::SnapshotRequired => {
                self.require_capability_without_buffer(VenueCapabilities::SNAPSHOT_RECOVERY)?;
                self.phase = SessionPhase::SnapshotRequired;
            }
        }
        Ok(())
    }

    fn encode_session_command<A: NativeOrderEntryEncoder>(
        &mut self,
        adapter: &mut A,
        command: SessionCommand,
        now: TimestampNs,
        output: &mut [u8],
    ) -> Result<EncodedFrame, VenueError> {
        clear_bytes(output);
        let sequence = self.next_outbound;
        let next_outbound = self.preflight_outbound_sequence(output)?;
        let checkpoint = adapter.checkpoint();
        let encoded = adapter.encode_session(sequence, command, output);
        self.finish_encode(
            adapter,
            checkpoint,
            encoded,
            sequence,
            next_outbound,
            now,
            output,
        )
    }

    fn validate_instrument_rules(
        &self,
        command: OrderCommand,
        now: TimestampNs,
    ) -> Result<(), VenueError> {
        let result = match command {
            OrderCommand::New(order) => self.instrument_definition.validate_order_economics(
                self.identity.venue,
                order.instrument,
                order.price,
                order.quantity,
                now,
            ),
            OrderCommand::Replace(order) => self.instrument_definition.validate_order_economics(
                self.identity.venue,
                self.instrument_definition.instrument,
                order.new_price,
                order.new_quantity,
                now,
            ),
            OrderCommand::Cancel(_)
            | OrderCommand::CancelAll(CancelAll {
                scope: CancelScope::Session,
                ..
            }) => Ok(()),
            OrderCommand::CancelAll(CancelAll {
                scope: CancelScope::Instrument(instrument),
                ..
            }) => {
                if instrument == self.instrument_definition.instrument {
                    Ok(())
                } else {
                    Err(InstrumentRuleViolation::InstrumentMismatch {
                        expected: self.instrument_definition.instrument,
                        received: instrument,
                    })
                }
            }
        };
        result.map_err(VenueError::InstrumentRule)
    }

    #[allow(clippy::too_many_arguments)]
    fn finish_encode<A: TransactionalCodec>(
        &mut self,
        adapter: &mut A,
        checkpoint: A::Checkpoint,
        encoded: Result<usize, WireError>,
        sequence: Sequence,
        next_outbound: Sequence,
        now: TimestampNs,
        output: &mut [u8],
    ) -> Result<EncodedFrame, VenueError> {
        let bytes = match encoded {
            Ok(bytes) if bytes > 0 && bytes <= output.len() => bytes,
            Ok(bytes) => {
                adapter.restore(checkpoint);
                clear_bytes(output);
                return Err(VenueError::EncoderContractViolation {
                    bytes,
                    capacity: output.len(),
                });
            }
            Err(error) => {
                adapter.restore(checkpoint);
                clear_bytes(output);
                return Err(error.into());
            }
        };
        adapter.commit(checkpoint);
        self.next_outbound = next_outbound;
        self.last_outbound = now;
        Ok(EncodedFrame { sequence, bytes })
    }

    fn verify_adapter<A: VenueDescriptor>(&self) -> Result<(), VenueError> {
        if A::IDENTITY != self.identity || A::CAPABILITIES != self.capabilities {
            return Err(VenueError::AdapterDescriptorMismatch {
                expected_identity: self.identity,
                actual_identity: A::IDENTITY,
                expected_capabilities: self.capabilities,
                actual_capabilities: A::CAPABILITIES,
            });
        }
        Ok(())
    }

    fn require_capability(
        &self,
        required: VenueCapabilities,
        output: &mut [u8],
    ) -> Result<(), VenueError> {
        if !self.capabilities.contains(required) {
            clear_bytes(output);
            return Err(VenueError::MissingCapability { required });
        }
        Ok(())
    }

    fn require_capability_without_buffer(
        &self,
        required: VenueCapabilities,
    ) -> Result<(), VenueError> {
        if !self.capabilities.contains(required) {
            return Err(VenueError::MissingCapability { required });
        }
        Ok(())
    }

    fn validate_outbound_timestamp(
        &self,
        now: TimestampNs,
        output: &mut [u8],
    ) -> Result<(), VenueError> {
        if let Err(error) = validate_timestamp(now) {
            clear_bytes(output);
            return Err(error);
        }
        if self.last_outbound != TimestampNs::ZERO && now < self.last_outbound {
            clear_bytes(output);
            return Err(VenueError::TimestampRegression {
                previous: self.last_outbound,
                received: now,
            });
        }
        Ok(())
    }

    fn preflight_outbound_sequence(&self, output: &mut [u8]) -> Result<Sequence, VenueError> {
        let Some(next) = self.next_outbound.0.checked_add(1) else {
            clear_bytes(output);
            return Err(VenueError::OutboundSequenceExhausted);
        };
        Ok(Sequence(next))
    }
}

/// Direct-feed sequence gate. A discontinuity requires a newly applied snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MarketDataFeed {
    identity: VenueIdentity,
    capabilities: VenueCapabilities,
    phase: FeedPhase,
    expected_sequence: Sequence,
    last_receive_timestamp: TimestampNs,
    snapshot_id: Option<u64>,
    snapshot_last_sequence: Option<Sequence>,
    snapshot_ready: Option<SnapshotApplyToken>,
}

impl MarketDataFeed {
    /// Construct a feed gate from a concrete native decoder descriptor.
    ///
    /// # Errors
    ///
    /// Returns [`VenueError`] for invalid identity, capability, or initial sequence.
    pub fn new<A: VenueDescriptor>(first_sequence: Sequence) -> Result<Self, VenueError> {
        if !A::IDENTITY.is_valid() {
            return Err(VenueError::InvalidIdentity);
        }
        if !A::CAPABILITIES.contains(VenueCapabilities::MARKET_DATA_L3) {
            return Err(VenueError::MissingCapability {
                required: VenueCapabilities::MARKET_DATA_L3,
            });
        }
        if first_sequence.0 == 0 {
            return Err(VenueError::InvalidSnapshotSequence {
                current_expected: first_sequence,
                snapshot_last: first_sequence,
            });
        }
        Ok(Self {
            identity: A::IDENTITY,
            capabilities: A::CAPABILITIES,
            phase: FeedPhase::Disconnected,
            expected_sequence: first_sequence,
            last_receive_timestamp: TimestampNs::ZERO,
            snapshot_id: None,
            snapshot_last_sequence: None,
            snapshot_ready: None,
        })
    }

    #[must_use]
    pub const fn identity(self) -> VenueIdentity {
        self.identity
    }

    #[must_use]
    pub const fn phase(self) -> FeedPhase {
        self.phase
    }

    #[must_use]
    pub const fn expected_sequence(self) -> Sequence {
        self.expected_sequence
    }

    /// A feed connection always requires a fresh snapshot before incrementals.
    ///
    /// # Errors
    ///
    /// Returns [`VenueError`] unless the feed is disconnected.
    pub fn connect(&mut self) -> Result<(), VenueError> {
        if self.phase != FeedPhase::Disconnected {
            return Err(VenueError::InvalidFeedState(self.phase));
        }
        self.reset_snapshot_state();
        self.phase = FeedPhase::SnapshotRequired;
        Ok(())
    }

    pub fn disconnect(&mut self) {
        self.phase = FeedPhase::Disconnected;
        self.reset_snapshot_state();
    }

    /// Begin decoding a venue snapshot after connection or a sequence fault.
    ///
    /// # Errors
    ///
    /// Returns [`VenueError`] unless a snapshot is required and supported.
    pub fn begin_snapshot(&mut self) -> Result<(), VenueError> {
        if self.phase != FeedPhase::SnapshotRequired {
            return Err(VenueError::InvalidFeedState(self.phase));
        }
        if !self
            .capabilities
            .contains(VenueCapabilities::SNAPSHOT_RECOVERY)
        {
            return Err(VenueError::MissingCapability {
                required: VenueCapabilities::SNAPSHOT_RECOVERY,
            });
        }
        self.reset_snapshot_state();
        self.phase = FeedPhase::ApplyingSnapshot;
        Ok(())
    }

    /// Return the apply token after a matching snapshot end was decoded.
    #[must_use]
    pub const fn snapshot_apply_token(self) -> Option<SnapshotApplyToken> {
        self.snapshot_ready
    }

    /// Decode native snapshot data while keeping application as an explicit caller step.
    ///
    /// The returned slots remain caller-owned. Codec and feed state are rolled back
    /// together if any decoded snapshot message fails core validation.
    ///
    /// # Errors
    ///
    /// Returns [`VenueError`] on state, descriptor, time, wire, or snapshot faults.
    pub fn decode_snapshot<A: DirectMarketDataDecoder>(
        &mut self,
        adapter: &mut A,
        packet: &[u8],
        hardware_receive_timestamp: TimestampNs,
        output: &mut [Option<SnapshotMessage>],
    ) -> Result<DecodeResult, VenueError> {
        clear_slots(output);
        self.verify_adapter::<A>()?;
        if self.phase != FeedPhase::ApplyingSnapshot {
            return Err(VenueError::InvalidFeedState(self.phase));
        }
        validate_timestamp(hardware_receive_timestamp)?;
        let checkpoint = adapter.checkpoint();
        let decoded = match adapter.decode_snapshot(packet, hardware_receive_timestamp, output) {
            Ok(result) => result,
            Err(error) => {
                adapter.restore(checkpoint);
                clear_slots(output);
                return Err(error.into());
            }
        };
        if let Err(error) = validate_decode_output(decoded, output, packet.len()) {
            adapter.restore(checkpoint);
            clear_slots(output);
            return Err(error);
        }
        if let Err(error) =
            self.commit_snapshot_batch(&output[..decoded.messages], hardware_receive_timestamp)
        {
            adapter.restore(checkpoint);
            clear_slots(output);
            return Err(error);
        }
        adapter.commit(checkpoint);
        Ok(decoded)
    }

    /// Commit a decoded snapshot after the caller has applied every snapshot order.
    ///
    /// # Errors
    ///
    /// Returns [`VenueError`] for invalid state, sequence rollback/overflow, or time.
    pub fn complete_snapshot(
        &mut self,
        token: SnapshotApplyToken,
        applied_at: TimestampNs,
    ) -> Result<(), VenueError> {
        if self.phase != FeedPhase::ApplyingSnapshot {
            return Err(VenueError::InvalidFeedState(self.phase));
        }
        if self.snapshot_ready != Some(token) {
            return Err(VenueError::SnapshotNotReady);
        }
        validate_timestamp(applied_at)?;
        if applied_at < self.last_receive_timestamp {
            return Err(VenueError::TimestampRegression {
                previous: self.last_receive_timestamp,
                received: applied_at,
            });
        }
        self.expected_sequence = Sequence(
            token
                .last_incremental_sequence
                .0
                .checked_add(1)
                .ok_or(VenueError::InboundSequenceExhausted)?,
        );
        self.last_receive_timestamp = applied_at;
        self.reset_snapshot_state();
        self.phase = FeedPhase::Live;
        Ok(())
    }

    /// Decode and atomically sequence-check one native incremental packet.
    ///
    /// # Errors
    ///
    /// Returns [`VenueError`] on state, adapter, timestamp, capacity, duplicate, or gap.
    pub fn decode_incrementals<A: DirectMarketDataDecoder>(
        &mut self,
        adapter: &mut A,
        packet: &[u8],
        hardware_receive_timestamp: TimestampNs,
        output: &mut [Option<MarketDataMessage>],
    ) -> Result<DecodeResult, VenueError> {
        clear_slots(output);
        self.verify_adapter::<A>()?;
        if self.phase != FeedPhase::Live {
            return Err(VenueError::InvalidFeedState(self.phase));
        }
        validate_timestamp(hardware_receive_timestamp)?;
        let checkpoint = adapter.checkpoint();
        let decoded = match adapter.decode_market_data(packet, hardware_receive_timestamp, output) {
            Ok(result) => result,
            Err(error) => {
                adapter.restore(checkpoint);
                clear_slots(output);
                return Err(error.into());
            }
        };
        if let Err(error) = validate_decode_output(decoded, output, packet.len()) {
            adapter.restore(checkpoint);
            clear_slots(output);
            return Err(error);
        }
        let next = match self
            .preflight_incremental_batch(&output[..decoded.messages], hardware_receive_timestamp)
        {
            Ok(next) => next,
            Err(error) => {
                adapter.restore(checkpoint);
                clear_slots(output);
                return Err(error);
            }
        };
        self.expected_sequence = next;
        if decoded.messages > 0 {
            self.last_receive_timestamp = hardware_receive_timestamp;
        }
        adapter.commit(checkpoint);
        Ok(decoded)
    }

    fn preflight_incremental_batch(
        &mut self,
        messages: &[Option<MarketDataMessage>],
        hardware_receive_timestamp: TimestampNs,
    ) -> Result<Sequence, VenueError> {
        let mut next = self.expected_sequence;
        for (index, slot) in messages.iter().enumerate() {
            let Some(message) = slot.as_ref() else {
                return Err(VenueError::EmptyDecodedSlot { index });
            };
            validate_market_timestamp(
                message.exchange_timestamp,
                message.hardware_receive_timestamp,
                hardware_receive_timestamp,
                self.last_receive_timestamp,
            )?;
            if !valid_market_data_message(*message) {
                return Err(VenueError::InvalidMarketDataMessage);
            }
            if message.sequence < next {
                return Err(VenueError::DuplicateSequence {
                    expected: self.expected_sequence,
                    received: message.sequence,
                });
            }
            if message.sequence > next {
                let received = message.sequence;
                self.phase = FeedPhase::SnapshotRequired;
                self.reset_snapshot_state();
                return Err(VenueError::SequenceGap {
                    expected: self.expected_sequence,
                    received,
                });
            }
            next = Sequence(
                next.0
                    .checked_add(1)
                    .ok_or(VenueError::InboundSequenceExhausted)?,
            );
        }
        Ok(next)
    }

    fn commit_snapshot_batch(
        &mut self,
        messages: &[Option<SnapshotMessage>],
        hardware_receive_timestamp: TimestampNs,
    ) -> Result<(), VenueError> {
        let mut candidate = *self;
        for (index, slot) in messages.iter().enumerate() {
            let Some(message) = slot.as_ref() else {
                return Err(VenueError::EmptyDecodedSlot { index });
            };
            validate_market_timestamp(
                message.exchange_timestamp,
                message.hardware_receive_timestamp,
                hardware_receive_timestamp,
                self.last_receive_timestamp,
            )?;
            candidate.apply_snapshot_message(*message)?;
        }
        if !messages.is_empty() {
            candidate.last_receive_timestamp = hardware_receive_timestamp;
        }
        *self = candidate;
        Ok(())
    }

    fn apply_snapshot_message(&mut self, message: SnapshotMessage) -> Result<(), VenueError> {
        match message.payload {
            SnapshotPayload::Begin {
                snapshot_id,
                last_incremental_sequence,
            } => {
                if self.snapshot_id.is_some()
                    || self.snapshot_ready.is_some()
                    || !valid_snapshot_boundary(
                        snapshot_id,
                        last_incremental_sequence,
                        self.expected_sequence,
                    )
                {
                    return Err(VenueError::InvalidSnapshotMessage);
                }
                self.snapshot_id = Some(snapshot_id);
                self.snapshot_last_sequence = Some(last_incremental_sequence);
            }
            SnapshotPayload::Order(order) => {
                if self.snapshot_id.is_none()
                    || self.snapshot_ready.is_some()
                    || !valid_snapshot_order(order)
                {
                    return Err(VenueError::InvalidSnapshotMessage);
                }
            }
            SnapshotPayload::End {
                snapshot_id,
                last_incremental_sequence,
            } => {
                if self.snapshot_id != Some(snapshot_id)
                    || self.snapshot_last_sequence != Some(last_incremental_sequence)
                    || self.snapshot_ready.is_some()
                {
                    return Err(VenueError::InvalidSnapshotMessage);
                }
                self.snapshot_ready = Some(SnapshotApplyToken {
                    snapshot_id,
                    last_incremental_sequence,
                });
            }
        }
        Ok(())
    }

    fn verify_adapter<A: VenueDescriptor>(&self) -> Result<(), VenueError> {
        if A::IDENTITY != self.identity || A::CAPABILITIES != self.capabilities {
            return Err(VenueError::AdapterDescriptorMismatch {
                expected_identity: self.identity,
                actual_identity: A::IDENTITY,
                expected_capabilities: self.capabilities,
                actual_capabilities: A::CAPABILITIES,
            });
        }
        Ok(())
    }

    fn reset_snapshot_state(&mut self) {
        self.snapshot_id = None;
        self.snapshot_last_sequence = None;
        self.snapshot_ready = None;
    }
}

fn validate_timestamp(timestamp: TimestampNs) -> Result<(), VenueError> {
    if timestamp == TimestampNs::ZERO {
        Err(VenueError::InvalidTimestamp(timestamp))
    } else {
        Ok(())
    }
}

fn validate_inbound_timestamp(
    exchange: TimestampNs,
    decoded_receive: TimestampNs,
    packet_receive: TimestampNs,
    previous_receive: TimestampNs,
) -> Result<(), VenueError> {
    validate_timestamp(exchange)?;
    validate_timestamp(decoded_receive)?;
    if decoded_receive != packet_receive || decoded_receive < exchange {
        return Err(VenueError::InvalidTimestamp(decoded_receive));
    }
    if previous_receive != TimestampNs::ZERO && decoded_receive < previous_receive {
        return Err(VenueError::TimestampRegression {
            previous: previous_receive,
            received: decoded_receive,
        });
    }
    Ok(())
}

fn validate_market_timestamp(
    exchange: TimestampNs,
    decoded_receive: TimestampNs,
    packet_receive: TimestampNs,
    previous_receive: TimestampNs,
) -> Result<(), VenueError> {
    validate_inbound_timestamp(exchange, decoded_receive, packet_receive, previous_receive)
}

const fn valid_snapshot_boundary(
    snapshot_id: u64,
    last_incremental_sequence: Sequence,
    current_expected: Sequence,
) -> bool {
    if snapshot_id == 0 {
        return false;
    }
    match last_incremental_sequence.0.checked_add(1) {
        Some(next) => next >= current_expected.0,
        None => false,
    }
}

const fn valid_snapshot_order(order: SnapshotOrder) -> bool {
    order.instrument.0 != 0 && order.order_id.0 != 0 && order.price.0 > 0 && order.quantity.0 > 0
}

const fn valid_inbound_payload(payload: InboundPayload) -> bool {
    match payload {
        InboundPayload::Session(_) => true,
        InboundPayload::Order(event) => match event {
            OrderEvent::Accepted(accepted) => {
                accepted.client_order_id.0 != 0
                    && accepted.venue_order_id.0 != 0
                    && accepted.price.0 > 0
                    && accepted.quantity.0 > 0
            }
            OrderEvent::Rejected(rejected) => rejected.client_order_id.0 != 0,
            OrderEvent::Canceled(canceled) => {
                canceled.client_order_id.0 != 0
                    && canceled.venue_order_id.0 != 0
                    && canceled.canceled_quantity.0 >= 0
                    && canceled.leaves_quantity.0 >= 0
            }
            OrderEvent::Fill(fill) => {
                fill.client_order_id.0 != 0
                    && fill.venue_order_id.0 != 0
                    && fill.trade_id.0 != 0
                    && fill.price.0 > 0
                    && fill.quantity.0 > 0
                    && fill.leaves_quantity.0 >= 0
            }
            OrderEvent::LifecycleCorrectionObserved(correction) => correction.is_valid(),
        },
    }
}

const fn valid_market_data_message(message: MarketDataMessage) -> bool {
    if message.instrument.0 == 0 {
        return false;
    }
    match message.payload {
        MarketDataPayload::Book(delta) => match delta {
            BookDelta::Add {
                order_id,
                price,
                quantity,
                ..
            }
            | BookDelta::Modify {
                order_id,
                price,
                quantity,
            }
            | BookDelta::Execute {
                order_id,
                price,
                quantity,
            } => order_id.0 != 0 && price.0 > 0 && quantity.0 > 0,
            BookDelta::Cancel { order_id } => order_id.0 != 0,
            BookDelta::Clear => true,
        },
        MarketDataPayload::Trade {
            trade_id,
            price,
            quantity,
            ..
        } => trade_id.0 != 0 && price.0 > 0 && quantity.0 > 0,
        MarketDataPayload::TradingStatus { .. } => true,
    }
}

fn validate_decode_output<T>(
    result: DecodeResult,
    output: &[Option<T>],
    packet_bytes: usize,
) -> Result<(), VenueError> {
    let slots = output.len();
    if result.messages > slots
        || result.consumed_bytes > packet_bytes
        || (result.consumed_bytes == 0 && (packet_bytes > 0 || result.messages > 0))
    {
        return Err(VenueError::DecoderContractViolation {
            messages: result.messages,
            slots,
            consumed_bytes: result.consumed_bytes,
            packet_bytes,
        });
    }
    if let Some(index) = output[..result.messages].iter().position(Option::is_none) {
        return Err(VenueError::EmptyDecodedSlot { index });
    }
    if let Some(relative) = output[result.messages..].iter().position(Option::is_some) {
        return Err(VenueError::NonEmptyDecodedTail {
            index: result.messages + relative,
            reported_messages: result.messages,
        });
    }
    Ok(())
}

fn clear_bytes(output: &mut [u8]) {
    output.fill(0);
}

fn clear_slots<T>(output: &mut [Option<T>]) {
    output.fill_with(|| None);
}
