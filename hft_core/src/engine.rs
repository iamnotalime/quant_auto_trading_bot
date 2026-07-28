//! Bounded single-instrument execution coordinator.
//!
//! This module is a deterministic hot-path state machine, not a live venue adapter.
//! A concrete certified adapter and [`crate::venue::MarketDataFeed`] /
//! [`crate::venue::VenueSession`] must authenticate, decode, and sequence native wire
//! messages before they enter this engine. The configured market-data sequence is an
//! exclusive, single-instrument normalized stream. Trade and status messages may be
//! interleaved with book deltas; the L3 book therefore receives a separate local,
//! contiguous mutation sequence rather than raw venue sequence numbers.
//!
//! Every event method uses only caller-owned output slices and fixed-capacity state.
//! It performs no socket, filesystem, logging, Python, or heap operation. Commands are
//! never assumed sent merely because they were written to an output slice: callers
//! must report the exact command to [`ExecutionEngine::on_transmission`]. Repricing is
//! strictly cancel-then-new per side; this engine never emits venue replace commands.

use crate::adverse::{AdverseConfig, AdverseError, AdverseMarkOutcome, AdverseMonitor};
use crate::book::{ApplyOutcome, BookError, BookEvent, L3Book, PriceLevel};
use crate::clock::{ClockDiscipline, ClockError, ClockSample, DisciplinedTimestamp};
use crate::control::{
    ControlDecision, ControlDecisionOrigin, ControlKillReason, EngineControlAction,
};
use crate::drop_copy::{DropCopyConfig, DropCopyError, DropCopyGate, DropCopyStatus};
use crate::kill::{KillCode, KillLatch, KillSnapshot};
use crate::orders::{
    CancelApplyOutcome, CancelConfirmed, CancelReason, CancelRejected, FillApplyOutcome,
    FillReport, ManagedOrderSnapshot, ManagedOrderState, NewAccepted, NewOrderRequest, NewRejected,
    OrderEconomics, OrderError, OrderManager, VenueOrderIdentity,
};
use crate::ownership::{OwnedMboRegistry, OwnershipBindOutcome, OwnershipError};
use crate::queue::{ExactQueuePosition, QueueError, QueueStatus};
use crate::reference_data::{
    InstrumentDefinition, InstrumentDefinitionError, InstrumentRuleViolation,
};
use crate::risk::{
    InstrumentRiskDefinition, InstrumentValuation, MarkOutcome, RiskEngine, RiskError, RiskLimits,
    RiskSessionId,
};
use crate::strategy::{
    InventoryAwareQuoter, MarketFeatures, QuoteDecision, QuoteLeg, QuotePolicyConfig, StrategyError,
};
use crate::types::{
    InstrumentId, MonotonicTimestampNs, OrderId, PriceTicks, Quantity, Sequence, Side, TimestampNs,
    VenueId,
};
use crate::venue::{
    Accepted, BookDelta, CancelOrder, Canceled, ClientOrderId, Fill, InboundMessage,
    InboundPayload, LifecycleCorrectionObserved, MarketByOrderId, MarketDataMessage,
    MarketDataPayload, NewOrder, OrderCommand, OrderEvent, OwnedMboBinding, RejectCode, Rejected,
    SessionEvent, SnapshotMessage, SnapshotOrder, SnapshotPayload, TimeInForce, VenueOrderId,
};

const MAX_COMMANDS_PER_EVENT: usize = 2;

/// Static configuration for one exclusive instrument stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EngineConfig {
    pub venue: VenueId,
    pub instrument: InstrumentId,
    pub first_market_sequence: Sequence,
    pub first_order_sequence: Sequence,
    pub first_client_order_id: ClientOrderId,
    pub first_risk_order_id: OrderId,
    /// Authenticated, effective-dated venue product economics. This exact value must
    /// also be bound into the native order-entry session and recovery checkpoint.
    pub instrument_definition: InstrumentDefinition,
    pub max_clock_uncertainty_ns: u64,
    pub max_clock_offset_step_ns: u64,
    pub max_clock_holdover_ns: u64,
    pub clock_drift_parts_per_billion: u64,
    pub risk_session: RiskSessionId,
    pub risk_definition: InstrumentRiskDefinition,
    pub risk: RiskLimits,
    pub adverse: AdverseConfig,
    pub quote: QuotePolicyConfig,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransmissionStatus {
    Sent,
    /// The transport proves that no byte belonging to this command was sent.
    ProvenUnsent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutputBatch {
    pub commands: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MarketEventOutcome {
    pub book: Option<ApplyOutcome>,
    pub mark: Option<PriceTicks>,
    pub risk: Option<MarkOutcome>,
    pub adverse: Option<AdverseMarkOutcome>,
    pub quote: Option<QuoteDecision>,
    pub output: OutputBatch,
}

/// Engine-side snapshot/recovery state. The native feed gate remains responsible
/// for packet decoding, buffering, and its matching [`crate::venue::SnapshotApplyToken`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EngineMarketState {
    SnapshotRequired,
    ApplyingSnapshot {
        snapshot_id: u64,
        last_incremental_sequence: Sequence,
    },
    Live,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SnapshotEventOutcome {
    pub book: Option<ApplyOutcome>,
    pub completed: bool,
    pub output: OutputBatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OrderApplication {
    Accepted(Option<ManagedOrderSnapshot>),
    NewRejected {
        client_order_id: ClientOrderId,
        code: RejectCode,
    },
    CancelRejected {
        order: Option<ManagedOrderSnapshot>,
        code: RejectCode,
    },
    Canceled(CancelApplyOutcome),
    Fill(FillApplyOutcome),
    /// The fact was consumed and the engine quarantined; no financial correction
    /// was inferred or applied.
    LifecycleCorrectionQuarantined(LifecycleCorrectionObserved),
    Session(SessionEvent),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OrderEventOutcome {
    pub application: OrderApplication,
    pub output: OutputBatch,
}

/// Compact evidence from an [`OrderError`] whose authoritative fact was already
/// reconciled. The exact execution-price violation and independent component-fault
/// presence survive a later route or instrument-rule failure. Risk and adverse error
/// payloads are intentionally omitted from composite errors; ordinary
/// [`EngineError::Order`] values still retain those payloads when no composite fault
/// supersedes them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReconciledOrderFaultSummary {
    pub risk_fault: bool,
    pub adverse_fault: bool,
    pub execution_price: Option<crate::orders::ExecutionPriceViolation>,
}

impl ReconciledOrderFaultSummary {
    #[must_use]
    pub const fn from_order_error(error: OrderError) -> Option<Self> {
        match error {
            OrderError::RiskAfterReconciled(_) => Some(Self {
                risk_fault: true,
                adverse_fault: false,
                execution_price: None,
            }),
            OrderError::AdverseAfterReconciled(_) => Some(Self {
                risk_fault: false,
                adverse_fault: true,
                execution_price: None,
            }),
            OrderError::RiskAndAdverseAfterReconciled { .. } => Some(Self {
                risk_fault: true,
                adverse_fault: true,
                execution_price: None,
            }),
            OrderError::ExecutionPriceAfterReconciled {
                violation,
                risk,
                adverse,
            } => Some(Self {
                risk_fault: risk.is_some(),
                adverse_fault: adverse.is_some(),
                execution_price: Some(violation),
            }),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EngineError {
    InvalidConfiguration,
    InstrumentDefinition(InstrumentDefinitionError),
    InstrumentRule(InstrumentRuleViolation),
    /// An authoritative fill was financially applied before its normalized venue
    /// economics violated the immutable instrument definition. `order_fault` retains
    /// a compact summary of an additional reconciled lifecycle/protocol fault from
    /// the same report without duplicating bulky risk/adverse payloads.
    OrderInstrumentRuleAfterReconciled {
        violation: InstrumentRuleViolation,
        order_fault: Option<ReconciledOrderFaultSummary>,
    },
    /// The authoritative private-order fact was applied before engine route
    /// synchronization failed. Optional fields preserve every independent order or
    /// instrument fault already observed for the same consumed report.
    OrderRouteAfterReconciled {
        client_order_id: ClientOrderId,
        order_fault: Option<ReconciledOrderFaultSummary>,
        instrument_rule_violation: Option<InstrumentRuleViolation>,
    },
    RiskCurrencyBindingMismatch,
    RiskValuationBindingMismatch,
    Clock(ClockError),
    MarketSequenceMismatch {
        expected: Sequence,
        received: Sequence,
    },
    OrderSequenceMismatch {
        expected: Sequence,
        received: Sequence,
    },
    SequenceExhausted,
    InstrumentMismatch {
        expected: InstrumentId,
        received: InstrumentId,
    },
    InvalidEventTimestamp,
    EventTimestampRegression {
        prior: TimestampNs,
        received: TimestampNs,
    },
    InvalidMarketPayload,
    SnapshotRequired,
    InvalidSnapshotState(EngineMarketState),
    InvalidSnapshotMessage,
    SnapshotBoundaryMismatch,
    BookExecutionPriceMismatch {
        order_id: MarketByOrderId,
        expected: PriceTicks,
        received: PriceTicks,
    },
    Book(BookError),
    Risk(RiskError),
    Adverse(AdverseError),
    Strategy(StrategyError),
    Order(OrderError),
    Ownership(OwnershipError),
    Queue(QueueError),
    DropCopy(DropCopyError),
    OwnedMboBindingMismatch(ClientOrderId),
    UnknownManagedOrder(ClientOrderId),
    OrderRouteMismatch(ClientOrderId),
    OrderReportMismatch(ClientOrderId),
    OutputCapacity {
        required: usize,
        provided: usize,
    },
    CommandMismatch,
    ReplaceForbidden,
    VenueUnavailable(SessionEvent),
    ControlProvenance,
    InvalidControlLease {
        accepted_at: TimestampNs,
        deadline: TimestampNs,
    },
    ControlLeaseRollback {
        current: TimestampNs,
        received: TimestampNs,
    },
    ControlLeaseExpired {
        deadline: TimestampNs,
        observed: TimestampNs,
    },
    IdentifierExhausted,
    InternalInvariant,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct SideState {
    client_order_id: Option<ClientOrderId>,
    pending_command: Option<OrderCommand>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SourceTimestampCursor {
    exchange: TimestampNs,
    received: TimestampNs,
}

impl SourceTimestampCursor {
    const EMPTY: Self = Self {
        exchange: TimestampNs::ZERO,
        received: TimestampNs::ZERO,
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PlannedAction {
    New {
        side: Side,
        leg: QuoteLeg,
    },
    Cancel {
        side: Side,
        client_order_id: ClientOrderId,
        venue_order_id: VenueOrderId,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PreparedAction {
    New {
        side: Side,
        client_order_id: ClientOrderId,
    },
    Cancel {
        side: Side,
        client_order_id: ClientOrderId,
    },
}

/// Fixed-capacity, single-writer coordinator for one instrument and venue route.
#[derive(Debug)]
pub struct ExecutionEngine<
    const MAX_BOOK_ORDERS: usize,
    const MAX_BOOK_LEVELS: usize,
    const MAX_ORDERS: usize,
    const MAX_RECENT_TRADES: usize,
    const MAX_FILLS: usize,
> {
    config: EngineConfig,
    clock: ClockDiscipline,
    kill: KillLatch,
    book: L3Book<MAX_BOOK_ORDERS, MAX_BOOK_LEVELS>,
    risk: RiskEngine<1, MAX_ORDERS>,
    adverse: AdverseMonitor<1, MAX_FILLS>,
    quoter: InventoryAwareQuoter,
    orders: OrderManager<MAX_ORDERS, MAX_RECENT_TRADES>,
    owned_mbo: OwnedMboRegistry<MAX_ORDERS>,
    bid_exact_queue: Option<ExactQueuePosition<MAX_BOOK_ORDERS>>,
    ask_exact_queue: Option<ExactQueuePosition<MAX_BOOK_ORDERS>>,
    drop_copy: Option<DropCopyGate<MAX_FILLS>>,
    expected_market_sequence: Sequence,
    expected_order_sequence: Sequence,
    next_client_order_id: ClientOrderId,
    next_risk_order_id: OrderId,
    market_timestamps: SourceTimestampCursor,
    order_timestamps: SourceTimestampCursor,
    drop_copy_timestamps: SourceTimestampCursor,
    /// Monotonic time of the latest engine input after causal application-order
    /// clamping. Raw capture timestamps remain unchanged in the journal.
    last_applied_monotonic: Option<MonotonicTimestampNs>,
    last_safe_now: Option<TimestampNs>,
    last_mark: Option<PriceTicks>,
    market_state: EngineMarketState,
    control_armed: bool,
    control_lease_deadline: Option<TimestampNs>,
    venue_trading_open: bool,
    order_session_live: bool,
    desired_bid: Option<QuoteLeg>,
    desired_ask: Option<QuoteLeg>,
    bid: SideState,
    ask: SideState,
}

impl<
    const MAX_BOOK_ORDERS: usize,
    const MAX_BOOK_LEVELS: usize,
    const MAX_ORDERS: usize,
    const MAX_RECENT_TRADES: usize,
    const MAX_FILLS: usize,
> ExecutionEngine<MAX_BOOK_ORDERS, MAX_BOOK_LEVELS, MAX_ORDERS, MAX_RECENT_TRADES, MAX_FILLS>
{
    /// Construct an empty engine. Clock synchronization must be observed before events.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid identifiers, sequences, capacities, or component
    /// configuration. Two managed-order slots are required for a two-sided quoter.
    pub fn new(config: EngineConfig) -> Result<Self, EngineError> {
        Self::new_configured(&config, None)
    }

    /// Construct an engine whose execution state is independently reconciled against
    /// drop copy. Until that session is live and every report is paired, the engine
    /// remains trading-ineligible. A later market/reconciliation event can prepare
    /// cancel-first output, while a definite mismatch does so immediately.
    ///
    /// # Errors
    ///
    /// Returns an error for either the ordinary engine configuration or an invalid
    /// nonzero drop-copy sequence cursor/capacity.
    pub fn new_with_drop_copy(
        config: EngineConfig,
        drop_copy: DropCopyConfig,
    ) -> Result<Self, EngineError> {
        let gate = DropCopyGate::new(drop_copy).map_err(EngineError::DropCopy)?;
        Self::new_configured(&config, Some(gate))
    }

    fn new_configured(
        config: &EngineConfig,
        drop_copy: Option<DropCopyGate<MAX_FILLS>>,
    ) -> Result<Self, EngineError> {
        config
            .instrument_definition
            .validate()
            .map_err(EngineError::InstrumentDefinition)?;
        if config.venue.0 == 0
            || config.instrument.0 == 0
            || config.first_market_sequence.0 == 0
            || config.first_order_sequence.0 == 0
            || config.first_client_order_id.0 == 0
            || config.first_risk_order_id.0 == 0
            || config.risk_session.0 == 0
            || config.risk_definition.instrument != config.instrument
            || config.instrument_definition.venue != config.venue
            || config.instrument_definition.instrument != config.instrument
            || config.max_clock_uncertainty_ns == 0
            || config.max_clock_holdover_ns == 0
            || MAX_BOOK_ORDERS == 0
            || MAX_BOOK_LEVELS == 0
            || MAX_ORDERS < 2
            || MAX_RECENT_TRADES == 0
            || MAX_FILLS == 0
        {
            return Err(EngineError::InvalidConfiguration);
        }
        if config.risk_definition.base_currency
            != config.instrument_definition.fixed_value.settlement_currency
        {
            return Err(EngineError::RiskCurrencyBindingMismatch);
        }
        let InstrumentValuation::Fixed {
            base_units_per_price_tick,
            contract_multiplier,
        } = config.risk_definition.valuation
        else {
            return Err(EngineError::RiskValuationBindingMismatch);
        };
        if base_units_per_price_tick
            != config
                .instrument_definition
                .fixed_value
                .settlement_units_per_price_tick
            || contract_multiplier != config.instrument_definition.fixed_value.contract_multiplier
        {
            return Err(EngineError::RiskValuationBindingMismatch);
        }
        config
            .instrument_definition
            .validate_normalized_economics(
                config.instrument,
                config.instrument_definition.minimum_price,
                config.quote.base_quantity,
            )
            .map_err(EngineError::InstrumentRule)?;
        let mut risk =
            RiskEngine::new(config.risk, config.risk_session).map_err(EngineError::Risk)?;
        risk.register_instrument(config.risk_definition)
            .map_err(EngineError::Risk)?;
        let adverse = AdverseMonitor::new(config.adverse).map_err(EngineError::Adverse)?;
        let quoter = InventoryAwareQuoter::new(config.quote).map_err(EngineError::Strategy)?;
        let orders = OrderManager::new().map_err(EngineError::Order)?;
        Ok(Self {
            config: *config,
            clock: ClockDiscipline::new(
                config.max_clock_uncertainty_ns,
                config.max_clock_offset_step_ns,
                config.max_clock_holdover_ns,
                config.clock_drift_parts_per_billion,
            ),
            kill: KillLatch::new(),
            book: L3Book::new(Sequence(1)),
            risk,
            adverse,
            quoter,
            orders,
            owned_mbo: OwnedMboRegistry::new(),
            bid_exact_queue: None,
            ask_exact_queue: None,
            drop_copy,
            expected_market_sequence: config.first_market_sequence,
            expected_order_sequence: config.first_order_sequence,
            next_client_order_id: config.first_client_order_id,
            next_risk_order_id: config.first_risk_order_id,
            market_timestamps: SourceTimestampCursor::EMPTY,
            order_timestamps: SourceTimestampCursor::EMPTY,
            drop_copy_timestamps: SourceTimestampCursor::EMPTY,
            last_applied_monotonic: None,
            last_safe_now: None,
            last_mark: None,
            market_state: EngineMarketState::SnapshotRequired,
            control_armed: false,
            control_lease_deadline: None,
            venue_trading_open: false,
            order_session_live: false,
            desired_bid: None,
            desired_ask: None,
            bid: SideState::default(),
            ask: SideState::default(),
        })
    }

    #[must_use]
    pub const fn config(&self) -> EngineConfig {
        self.config
    }

    #[must_use]
    pub const fn expected_market_sequence(&self) -> Sequence {
        self.expected_market_sequence
    }

    #[must_use]
    pub const fn expected_order_sequence(&self) -> Sequence {
        self.expected_order_sequence
    }

    #[must_use]
    pub const fn drop_copy_status(&self) -> Option<DropCopyStatus> {
        match &self.drop_copy {
            Some(gate) => Some(gate.status()),
            None => None,
        }
    }

    #[must_use]
    pub const fn drop_copy_enabled(&self) -> bool {
        self.drop_copy.is_some()
    }

    #[must_use]
    pub const fn control_armed(&self) -> bool {
        self.control_armed
    }

    #[must_use]
    pub const fn control_lease_deadline(&self) -> Option<TimestampNs> {
        self.control_lease_deadline
    }

    #[must_use]
    pub const fn venue_trading_open(&self) -> bool {
        self.venue_trading_open
    }

    #[must_use]
    pub const fn order_session_live(&self) -> bool {
        self.order_session_live
    }

    #[must_use]
    pub const fn market_state(&self) -> EngineMarketState {
        self.market_state
    }

    #[must_use]
    pub fn trading_eligible(&self) -> bool {
        self.control_armed
            && self.control_lease_deadline.is_some_and(|deadline| {
                self.last_safe_now
                    .is_some_and(|observed| observed <= deadline)
            })
            && self
                .last_safe_now
                .is_some_and(|observed| self.config.instrument_definition.is_effective_at(observed))
            && self.venue_trading_open
            && self.order_session_live
            && match &self.drop_copy {
                Some(gate) => gate.synchronized(),
                None => true,
            }
            && matches!(self.market_state, EngineMarketState::Live)
            && !self.kill.is_triggered()
    }

    #[must_use]
    pub fn kill_snapshot(&self) -> Option<KillSnapshot> {
        self.kill.snapshot()
    }

    /// Latest monotonic timestamp actually applied by an engine operation that uses
    /// the disciplined clock. Queued raw events may carry an earlier capture time;
    /// [`Self::disciplined_now`] applies them at this causal floor instead.
    ///
    /// This value belongs to the current monotonic-clock/boot epoch. Recovery across
    /// an epoch change must rebuild it by deterministic replay under the new clock
    /// discipline; persisting and blindly restoring the numeric value is invalid.
    #[must_use]
    pub const fn last_applied_monotonic(&self) -> Option<MonotonicTimestampNs> {
        self.last_applied_monotonic
    }

    /// Causal UTC floor used for lifecycle, risk, and kill timestamps. Authenticated
    /// control UTC advances this value even though control messages carry no
    /// monotonic timestamp.
    #[must_use]
    pub const fn last_applied_utc(&self) -> Option<TimestampNs> {
        self.last_safe_now
    }

    #[must_use]
    pub const fn book(&self) -> &L3Book<MAX_BOOK_ORDERS, MAX_BOOK_LEVELS> {
        &self.book
    }

    #[must_use]
    pub const fn risk(&self) -> &RiskEngine<1, MAX_ORDERS> {
        &self.risk
    }

    #[must_use]
    pub const fn adverse(&self) -> &AdverseMonitor<1, MAX_FILLS> {
        &self.adverse
    }

    #[must_use]
    pub const fn orders(&self) -> &OrderManager<MAX_ORDERS, MAX_RECENT_TRADES> {
        &self.orders
    }

    #[must_use]
    pub const fn owned_mbo_registry(&self) -> &OwnedMboRegistry<MAX_ORDERS> {
        &self.owned_mbo
    }

    #[must_use]
    pub fn exact_queue(&self, side: Side) -> Option<&ExactQueuePosition<MAX_BOOK_ORDERS>> {
        match side {
            Side::Buy => self.bid_exact_queue.as_ref(),
            Side::Sell => self.ask_exact_queue.as_ref(),
        }
    }

    /// Exact in-memory equivalence check for deterministic replay certification.
    ///
    /// This compares every execution-relevant component and cursor, including the
    /// fixed-capacity book, lifecycle, risk, adverse-selection, ownership, and queue
    /// states. It is an equality predicate, not a cryptographic attestation.
    #[must_use]
    pub fn deterministic_state_eq(&self, other: &Self) -> bool {
        self.config == other.config
            && self.clock == other.clock
            && self.kill.state() == other.kill.state()
            && self.book == other.book
            && self.risk == other.risk
            && self.adverse == other.adverse
            && self.quoter == other.quoter
            && self.orders == other.orders
            && self.owned_mbo == other.owned_mbo
            && self.bid_exact_queue == other.bid_exact_queue
            && self.ask_exact_queue == other.ask_exact_queue
            && self.drop_copy == other.drop_copy
            && self.expected_market_sequence == other.expected_market_sequence
            && self.expected_order_sequence == other.expected_order_sequence
            && self.next_client_order_id == other.next_client_order_id
            && self.next_risk_order_id == other.next_risk_order_id
            && self.market_timestamps == other.market_timestamps
            && self.order_timestamps == other.order_timestamps
            && self.drop_copy_timestamps == other.drop_copy_timestamps
            && self.last_applied_monotonic == other.last_applied_monotonic
            && self.last_safe_now == other.last_safe_now
            && self.last_mark == other.last_mark
            && self.market_state == other.market_state
            && self.control_armed == other.control_armed
            && self.control_lease_deadline == other.control_lease_deadline
            && self.venue_trading_open == other.venue_trading_open
            && self.order_session_live == other.order_session_live
            && self.desired_bid == other.desired_bid
            && self.desired_ask == other.desired_ask
            && self.bid == other.bid
            && self.ask == other.ask
    }

    /// Accept one clock synchronization sample.
    ///
    /// # Errors
    ///
    /// Any rejected sample latches [`KillCode::ClockUnsafe`].
    pub fn observe_clock(&mut self, sample: ClockSample) -> Result<(), EngineError> {
        match self.clock.observe(sample) {
            Ok(()) => {
                let effective_monotonic = self
                    .last_applied_monotonic
                    .map_or(sample.monotonic, |prior| prior.max(sample.monotonic));
                self.last_applied_monotonic = Some(effective_monotonic);
                let prior_safe = self.last_safe_now;
                let now = self.clock.timestamp(effective_monotonic).map_err(|error| {
                    self.kill
                        .trigger(KillCode::ClockUnsafe, prior_safe.unwrap_or(sample.utc));
                    EngineError::Clock(error)
                })?;
                if let Some(prior) = self.last_safe_now
                    && now.utc < prior
                {
                    self.kill.trigger(KillCode::ClockUnsafe, prior);
                    return Err(EngineError::EventTimestampRegression {
                        prior,
                        received: now.utc,
                    });
                }
                self.last_safe_now = Some(now.utc);
                Ok(())
            }
            Err(error) => {
                // A rejected synchronization sample is not an admissible source of
                // audit time. Preserve the last causally accepted UTC floor when one
                // exists, including for zero or regressing sample timestamps.
                let trigger_at = self.last_safe_now.unwrap_or(sample.utc);
                self.kill.trigger(KillCode::ClockUnsafe, trigger_at);
                Err(EngineError::Clock(error))
            }
        }
    }

    /// Bind a managed private order to its explicitly correlated public MBO identity
    /// and initialize exact price-time queue tracking.
    ///
    /// The binding must come from a certified adapter rule. Numeric equality between
    /// private and public IDs is never consulted. If the public add is already visible,
    /// the tracker reconstructs its exact prefix; otherwise it conservatively records
    /// all current same-level orders until the owned add echo arrives.
    ///
    /// # Errors
    ///
    /// Any identity, lifecycle, sequence, book, capacity, or queue mismatch fails
    /// closed and latches the first-fault kill state.
    pub fn on_owned_mbo_binding(
        &mut self,
        binding: OwnedMboBinding,
        monotonic_now: MonotonicTimestampNs,
    ) -> Result<OwnershipBindOutcome, EngineError> {
        let now = self.disciplined_now(monotonic_now)?.utc;
        if !binding.is_valid() || binding.venue != self.config.venue {
            return self.internal_error(
                now,
                EngineError::OwnedMboBindingMismatch(binding.client_order_id),
            );
        }
        let snapshot = self.managed_order(binding.client_order_id, now)?;
        if snapshot.venue_order_id != Some(binding.venue_order_id)
            || snapshot.acceptance_sequence != Some(binding.order_entry_sequence)
            || !snapshot.remaining_quantity.is_positive()
        {
            return self.internal_error(
                now,
                EngineError::OwnedMboBindingMismatch(binding.client_order_id),
            );
        }

        let mut registry = self.owned_mbo.clone();
        let outcome = match registry.bind(binding) {
            Ok(outcome) => outcome,
            Err(error) => return self.internal_error(now, EngineError::Ownership(error)),
        };
        if outcome == OwnershipBindOutcome::Duplicate {
            let valid_queue = self.exact_queue(snapshot.side).is_some_and(|queue| {
                queue.order_id() == OrderId(binding.market_by_order_id.0)
                    && queue.side() == snapshot.side
                    && queue.price() == snapshot.limit_price
            });
            return if valid_queue {
                Ok(outcome)
            } else {
                self.internal_error(
                    now,
                    EngineError::OwnedMboBindingMismatch(binding.client_order_id),
                )
            };
        }
        if self.exact_queue(snapshot.side).is_some() {
            return self.internal_error(
                now,
                EngineError::OwnedMboBindingMismatch(binding.client_order_id),
            );
        }

        let market_order_id = OrderId(binding.market_by_order_id.0);
        let tracker = if self.book.order(market_order_id).is_some() {
            ExactQueuePosition::from_visible_order(&self.book, market_order_id)
        } else {
            ExactQueuePosition::join_behind_book(
                &self.book,
                market_order_id,
                snapshot.side,
                snapshot.limit_price,
                snapshot.remaining_quantity,
            )
        };
        let tracker = match tracker {
            Ok(tracker) => tracker,
            Err(error) => return self.queue_failure(error, now),
        };
        if tracker.side() != snapshot.side
            || tracker.price() != snapshot.limit_price
            || tracker.remaining_quantity() != snapshot.remaining_quantity
        {
            return self.internal_error(
                now,
                EngineError::OwnedMboBindingMismatch(binding.client_order_id),
            );
        }

        self.owned_mbo = registry;
        *self.exact_queue_mut(snapshot.side) = Some(tracker);
        Ok(outcome)
    }

    /// Apply one decoded native snapshot boundary or order.
    ///
    /// Snapshot traffic is deliberately separate from incrementals. Begin clears the
    /// local image and disables venue eligibility; orders rebuild the L3 image using
    /// local contiguous mutation ordinals; a matching end advances the incremental
    /// cursor to `last_incremental_sequence + 1`. Trading remains venue-closed until
    /// a later normalized trading-status event explicitly opens it.
    ///
    /// # Errors
    ///
    /// Timestamp, state, boundary, instrument, book, arithmetic, and output faults
    /// fail closed. A malformed or partial image is discarded and a fresh snapshot
    /// remains required. `output` must provide two slots; this is checked before the
    /// clock or snapshot state advances.
    pub fn on_snapshot(
        &mut self,
        message: SnapshotMessage,
        monotonic_now: MonotonicTimestampNs,
        output: &mut [Option<OrderCommand>],
    ) -> Result<SnapshotEventOutcome, EngineError> {
        self.preflight_event_output_capacity(output)?;
        let now = self.disciplined_now(monotonic_now)?;
        self.expire_control_lease(now.utc);
        self.enforce_drop_copy_liveness(now.utc, output)?;
        if let Err(error) = self.validate_timestamps(
            message.exchange_timestamp,
            message.hardware_receive_timestamp,
            now.utc,
            self.market_timestamps.exchange,
            self.market_timestamps.received,
        ) {
            self.require_new_snapshot();
            return Err(error);
        }

        let mut book_outcome = None;
        let mut completed = false;
        let apply_result = match message.payload {
            SnapshotPayload::Begin {
                snapshot_id,
                last_incremental_sequence,
            } => self.begin_snapshot(snapshot_id, last_incremental_sequence, now.utc),
            SnapshotPayload::Order(order) => {
                self.apply_snapshot_order(order, now.utc).map(|outcome| {
                    book_outcome = Some(outcome);
                })
            }
            SnapshotPayload::End {
                snapshot_id,
                last_incremental_sequence,
            } => self
                .complete_snapshot(snapshot_id, last_incremental_sequence, now.utc)
                .map(|()| {
                    completed = true;
                }),
        };
        if let Err(error) = apply_result {
            self.require_new_snapshot();
            self.kill.trigger(KillCode::MarketDataGap, now.utc);
            return Err(error);
        }
        self.market_timestamps = SourceTimestampCursor {
            exchange: message.exchange_timestamp,
            received: message.hardware_receive_timestamp,
        };
        let output_batch = self.reconcile_quotes(now.utc, output)?;
        Ok(SnapshotEventOutcome {
            book: book_outcome,
            completed,
            output: output_batch,
        })
    }

    /// Apply one already decoded and upstream-sequenced market-data message.
    ///
    /// Commands are written to the initialized prefix of `output`; all slots are
    /// cleared first. A trade between book deltas advances only the normalized stream
    /// sequence, not the book's local mutation sequence.
    ///
    /// # Errors
    ///
    /// Every clock, routing, sequence, book, risk, adverse, strategy, order-state, or
    /// output-contract fault fails closed and latches the corresponding kill reason.
    /// `output` must provide two slots; this is checked before the clock or market
    /// source advances.
    pub fn on_market_data(
        &mut self,
        message: MarketDataMessage,
        monotonic_now: MonotonicTimestampNs,
        output: &mut [Option<OrderCommand>],
    ) -> Result<MarketEventOutcome, EngineError> {
        self.preflight_event_output_capacity(output)?;
        let now = self.disciplined_now(monotonic_now)?;
        self.expire_control_lease(now.utc);
        self.enforce_drop_copy_liveness(now.utc, output)?;
        if self.market_state != EngineMarketState::Live {
            self.venue_trading_open = false;
            self.desired_bid = None;
            self.desired_ask = None;
            self.kill.trigger(KillCode::MarketDataGap, now.utc);
            return Err(EngineError::SnapshotRequired);
        }
        self.validate_market_envelope(message, now)?;
        self.validate_market_payload(message.payload, now.utc)?;
        let next_sequence = next_sequence(message.sequence).ok_or_else(|| {
            self.require_new_snapshot();
            self.kill.trigger(KillCode::MarketDataGap, now.utc);
            EngineError::SequenceExhausted
        })?;

        let book_outcome = match message.payload {
            MarketDataPayload::Book(delta) => Some(self.apply_book_delta(delta, now.utc)?),
            MarketDataPayload::Trade {
                trade_id,
                price,
                quantity,
                ..
            } => {
                if trade_id.0 == 0 || !price.is_positive() || !quantity.is_positive() {
                    return self.internal_error(now.utc, EngineError::InvalidMarketPayload);
                }
                None
            }
            MarketDataPayload::TradingStatus { status_code } => {
                self.venue_trading_open = self
                    .config
                    .instrument_definition
                    .is_continuous_trading(status_code);
                None
            }
        };
        self.expected_market_sequence = next_sequence;
        self.market_timestamps = SourceTimestampCursor {
            exchange: message.exchange_timestamp,
            received: message.hardware_receive_timestamp,
        };

        let mut mark = None;
        let mut risk_outcome = None;
        let mut adverse_outcome = None;
        let mut quote = None;
        if let Some((bid, ask, current_mark)) = self.top_of_book(now.utc)? {
            let risk_result = self.risk.on_mark(
                self.config.instrument,
                current_mark,
                message.exchange_timestamp,
                now.utc,
                true,
                &self.kill,
            );
            let risk_mark = match risk_result {
                Ok(outcome) => outcome,
                Err(error) => return Err(EngineError::Risk(error)),
            };
            let adverse_mark = match self.adverse.on_mark(
                self.config.instrument,
                current_mark,
                message.exchange_timestamp,
                now.utc,
                &self.kill,
            ) {
                Ok(outcome) => outcome,
                Err(error) => return Err(EngineError::Adverse(error)),
            };
            let decision = self.quote_from_top(bid, ask, current_mark, now.utc)?;
            self.desired_bid = decision.bid;
            self.desired_ask = decision.ask;
            self.last_mark = Some(current_mark);
            mark = Some(current_mark);
            risk_outcome = Some(risk_mark);
            adverse_outcome = Some(adverse_mark);
            quote = Some(decision);
        } else {
            self.desired_bid = None;
            self.desired_ask = None;
        }
        if !self.trading_eligible() {
            self.desired_bid = None;
            self.desired_ask = None;
        }
        let output_batch = self.reconcile_quotes(now.utc, output)?;
        Ok(MarketEventOutcome {
            book: book_outcome,
            mark,
            risk: risk_outcome,
            adverse: adverse_outcome,
            quote,
            output: output_batch,
        })
    }

    /// Apply one authenticated, already session-sequenced order-entry message.
    ///
    /// Venue reports are enriched only from the exact local managed-order record.
    /// Side, instrument, original economics, and risk identity are never taken from
    /// unauthenticated or absent wire fields.
    ///
    /// # Errors
    ///
    /// Unknown orders, report mismatches, sequence/clock faults, invalid lifecycle
    /// transitions, and component failures latch a kill and return a typed error.
    /// A fatal [`SessionEvent`] or [`OrderError::RiskAfterReconciled`],
    /// [`OrderError::AdverseAfterReconciled`], or
    /// [`OrderError::RiskAndAdverseAfterReconciled`] means the authoritative fact and
    /// source cursor were committed before the downstream fault. The same applies to
    /// [`OrderError::ExecutionPriceAfterReconciled`], which additionally identifies a
    /// venue execution outside the authenticated limit. In those cases the initialized
    /// output prefix may contain cancel-first safety commands; callers must publish or
    /// otherwise resolve that output even though this method returns an error. The
    /// caller-owned output slice must contain at least two slots (the fixed maximum
    /// command batch); this contract is checked before the clock or source fact advances.
    pub fn on_order_entry(
        &mut self,
        message: InboundMessage,
        monotonic_now: MonotonicTimestampNs,
        output: &mut [Option<OrderCommand>],
    ) -> Result<OrderEventOutcome, EngineError> {
        self.preflight_event_output_capacity(output)?;
        let now = self.disciplined_now(monotonic_now)?;
        self.expire_control_lease(now.utc);
        self.enforce_drop_copy_liveness(now.utc, output)?;
        self.validate_order_envelope(message, now)?;
        let next = next_sequence(message.sequence).ok_or_else(|| {
            self.venue_trading_open = false;
            self.order_session_live = false;
            self.kill.trigger(KillCode::VenueDisconnect, now.utc);
            EngineError::SequenceExhausted
        })?;
        if let InboundPayload::Order(OrderEvent::LifecycleCorrectionObserved(correction)) =
            message.payload
        {
            self.quarantine_lifecycle_correction(correction, now.utc)?;
        }
        let (application, may_reconcile) = match message.payload {
            InboundPayload::Session(event) => match self.apply_session(event, now.utc) {
                Ok(application) => (application, false),
                Err(error @ EngineError::VenueUnavailable(_)) => {
                    return self
                        .finish_consumed_order_source_error(error, next, message, now.utc, output);
                }
                Err(error) => return Err(error),
            },
            InboundPayload::Order(event) => {
                let drop_copy_before = self.drop_copy;
                let drop_copy_pending = if let Some(gate) = &mut self.drop_copy {
                    if let Err(error) = gate.observe_order_entry(event, now.utc) {
                        return self.drop_copy_failure(error, output);
                    }
                    !gate.synchronized()
                } else {
                    false
                };
                let applied = self.apply_order_event(
                    event,
                    message.sequence,
                    message.exchange_timestamp,
                    now.utc,
                );
                let (application, lifecycle_reconcile) = match applied {
                    Ok(applied) => applied,
                    Err(error) if Self::is_reconciled_engine_order_error(error) => {
                        return self.finish_consumed_order_source_error(
                            error, next, message, now.utc, output,
                        );
                    }
                    Err(error) => {
                        // The local application rejected this report without committing
                        // its authoritative lifecycle or accounting fact. Restore the
                        // independent reconciliation gate as part of the same retryable
                        // transaction; otherwise an exact retry becomes a false duplicate.
                        self.drop_copy = drop_copy_before;
                        return Err(error);
                    }
                };
                // Do not originate or cancel from an order-entry-only state. A later
                // market event sees trading ineligibility and may cancel conservatively;
                // the exact matching drop-copy report can instead arrive first.
                (application, lifecycle_reconcile && !drop_copy_pending)
            }
        };
        self.commit_order_source_progress(next, message);
        self.validate_managed_routes(now.utc)?;
        if self.kill.is_triggered() {
            self.desired_bid = None;
            self.desired_ask = None;
        }
        let output_batch = if may_reconcile || self.kill.is_triggered() {
            self.reconcile_quotes(now.utc, output)?
        } else {
            OutputBatch { commands: 0 }
        };
        Ok(OrderEventOutcome {
            application,
            output: output_batch,
        })
    }

    /// Reconcile one report from an independently authenticated drop-copy session.
    ///
    /// Drop-copy reports never mutate lifecycle or risk a second time. They only pair
    /// against the exact primary order-entry fact. While either side is unpaired the
    /// engine cannot originate new risk; the next market reconciliation cancels stale
    /// exposure if the peer has not arrived. A sequence, session, duplicate, capacity,
    /// or economic mismatch latches `DropCopyMismatch` and prepares cancels immediately
    /// before the typed error is returned.
    ///
    /// # Errors
    ///
    /// Returns a clock/timestamp fault or a fixed drop-copy reconciliation fault after
    /// fail-closed state has already been applied. The caller-owned output slice must
    /// contain at least two slots (the fixed maximum command batch); this contract is
    /// checked before the clock or drop-copy sequence advances.
    pub fn on_drop_copy(
        &mut self,
        message: InboundMessage,
        monotonic_now: MonotonicTimestampNs,
        output: &mut [Option<OrderCommand>],
    ) -> Result<OutputBatch, EngineError> {
        self.preflight_event_output_capacity(output)?;
        let now = self.disciplined_now(monotonic_now)?;
        self.expire_control_lease(now.utc);
        self.enforce_drop_copy_liveness(now.utc, output)?;
        self.validate_timestamps(
            message.exchange_timestamp,
            message.hardware_receive_timestamp,
            now.utc,
            self.drop_copy_timestamps.exchange,
            self.drop_copy_timestamps.received,
        )?;
        let correction = match message.payload {
            InboundPayload::Order(OrderEvent::LifecycleCorrectionObserved(correction)) => {
                self.quarantine_lifecycle_correction(correction, now.utc)?;
                true
            }
            InboundPayload::Session(_) | InboundPayload::Order(_) => false,
        };
        let Some(gate) = &mut self.drop_copy else {
            return self.drop_copy_failure(DropCopyError::InvalidConfiguration, output);
        };
        let result = match message.payload {
            InboundPayload::Session(event) => {
                gate.observe_session(message.sequence, event, now.utc)
            }
            InboundPayload::Order(event) => {
                gate.observe_drop_copy(message.sequence, event, now.utc)
            }
        };
        if let Err(error) = result {
            if matches!(
                error,
                DropCopyError::SessionUnavailable(_) | DropCopyError::SessionNotLive
            ) {
                // Both faults are returned only after the gate has accepted this
                // sequence. Advance the matching timestamp cursor with it so the
                // next sequenced report cannot bypass temporal ordering checks.
                self.drop_copy_timestamps = SourceTimestampCursor {
                    exchange: message.exchange_timestamp,
                    received: message.hardware_receive_timestamp,
                };
            }
            return self.drop_copy_failure(error, output);
        }
        self.drop_copy_timestamps = SourceTimestampCursor {
            exchange: message.exchange_timestamp,
            received: message.hardware_receive_timestamp,
        };
        if correction {
            self.reconcile_quotes(now.utc, output)
        } else {
            Ok(OutputBatch { commands: 0 })
        }
    }

    /// Apply one immutable decision emitted by the external authenticated control gate.
    ///
    /// A decision reconstructed from a journal is replay-only and is rejected here;
    /// its private origin cannot be changed by callers. Disarm and kill clear quote
    /// intent before the bounded cancel-first reconciliation pass. Arm records the
    /// authenticated lease deadline as well as changing the control flag; venue
    /// trading status remains independently closed until a market-data status event
    /// opens it.
    ///
    /// # Errors
    ///
    /// Returns a typed clock, output-capacity, or managed-order reconciliation fault.
    /// Authenticated decisions require a two-slot output slice, checked before their
    /// timestamp or control state advances.
    pub fn apply_control_decision(
        &mut self,
        decision: ControlDecision,
        output: &mut [Option<OrderCommand>],
    ) -> Result<OutputBatch, EngineError> {
        self.preflight_event_output_capacity(output)?;
        if decision.origin() != ControlDecisionOrigin::AuthenticatedGate {
            return self.reject_control_provenance(output);
        }
        self.apply_control_action_preflighted(decision.action(), decision.accepted_at(), output)
    }

    pub(crate) fn apply_replayed_control_decision(
        &mut self,
        decision: ControlDecision,
        output: &mut [Option<OrderCommand>],
    ) -> Result<OutputBatch, EngineError> {
        self.preflight_event_output_capacity(output)?;
        if decision.origin() != ControlDecisionOrigin::JournalReplay {
            return self.reject_control_provenance(output);
        }
        self.apply_control_action_preflighted(decision.action(), decision.accepted_at(), output)
    }

    fn apply_control_action_preflighted(
        &mut self,
        action: EngineControlAction,
        now: TimestampNs,
        output: &mut [Option<OrderCommand>],
    ) -> Result<OutputBatch, EngineError> {
        self.validate_control_timestamp(now)?;
        // Control inputs carry authenticated UTC rather than a monotonic timestamp.
        // Once accepted, their application time is part of the same causal floor as
        // feed and transmission inputs.
        self.last_safe_now = Some(now);
        match action {
            EngineControlAction::Arm { lease_deadline, .. } => {
                if self.kill.is_triggered() {
                    self.control_armed = false;
                    self.control_lease_deadline = None;
                    return Err(EngineError::InternalInvariant);
                }
                if self.control_armed || lease_deadline <= now {
                    self.control_armed = false;
                    self.control_lease_deadline = None;
                    return self.internal_error(
                        now,
                        EngineError::InvalidControlLease {
                            accepted_at: now,
                            deadline: lease_deadline,
                        },
                    );
                }
                self.control_armed = true;
                self.control_lease_deadline = Some(lease_deadline);
                Ok(OutputBatch { commands: 0 })
            }
            EngineControlAction::Heartbeat { lease_deadline } => {
                let Some(current) = self.control_lease_deadline else {
                    self.control_armed = false;
                    return self.internal_error(now, EngineError::InternalInvariant);
                };
                if !self.control_armed || now > current {
                    self.expire_control_lease(now);
                    return Err(EngineError::ControlLeaseExpired {
                        deadline: current,
                        observed: now,
                    });
                }
                if lease_deadline <= now {
                    self.control_armed = false;
                    self.control_lease_deadline = None;
                    return self.internal_error(
                        now,
                        EngineError::InvalidControlLease {
                            accepted_at: now,
                            deadline: lease_deadline,
                        },
                    );
                }
                if lease_deadline < current {
                    self.control_armed = false;
                    self.control_lease_deadline = None;
                    return self.internal_error(
                        now,
                        EngineError::ControlLeaseRollback {
                            current,
                            received: lease_deadline,
                        },
                    );
                }
                self.control_lease_deadline = Some(lease_deadline);
                if !self.trading_eligible() {
                    self.desired_bid = None;
                    self.desired_ask = None;
                    return self.reconcile_quotes(now, output);
                }
                Ok(OutputBatch { commands: 0 })
            }
            EngineControlAction::Disarm => {
                self.control_armed = false;
                self.control_lease_deadline = None;
                self.desired_bid = None;
                self.desired_ask = None;
                self.reconcile_quotes(now, output)
            }
            EngineControlAction::Kill(request) => {
                self.control_armed = false;
                self.control_lease_deadline = None;
                self.desired_bid = None;
                self.desired_ask = None;
                self.kill.trigger(control_kill_code(request.reason), now);
                self.reconcile_quotes(now, output)
            }
        }
    }

    /// Check the authenticated control lease and reference-data validity from a
    /// replayable monotonic timer.
    /// A firing exactly at the deadline remains valid; the first later observation
    /// latches a venue-disconnect kill and prepares cancel-first reconciliation.
    ///
    /// # Errors
    ///
    /// Returns a clock or bounded reconciliation failure after fail-closed state has
    /// already been applied. `output` must provide two slots; this is checked before
    /// the timer advances the clock or lease state.
    pub fn check_control_liveness(
        &mut self,
        monotonic_now: MonotonicTimestampNs,
        output: &mut [Option<OrderCommand>],
    ) -> Result<OutputBatch, EngineError> {
        self.preflight_event_output_capacity(output)?;
        let now = self.disciplined_now(monotonic_now)?;
        if self.expire_control_lease(now.utc) || !self.trading_eligible() {
            self.desired_bid = None;
            self.desired_ask = None;
            return self.reconcile_quotes(now.utc, output);
        }
        Ok(OutputBatch { commands: 0 })
    }

    /// Check the oldest unresolved drop-copy reconciliation deadline from a distinct,
    /// replayable monotonic timer. A firing exactly at the deadline remains valid.
    /// The first later observation latches `DropCopyMismatch` and prepares only
    /// cancel commands for every live managed order.
    ///
    /// # Errors
    ///
    /// Returns a clock or pending-reconciliation expiry after fail-closed state and
    /// cancel-first output have already been applied. `output` must provide two slots;
    /// this is checked before the timer advances the clock or drop-copy liveness state.
    pub fn check_drop_copy_liveness(
        &mut self,
        monotonic_now: MonotonicTimestampNs,
        output: &mut [Option<OrderCommand>],
    ) -> Result<OutputBatch, EngineError> {
        self.preflight_event_output_capacity(output)?;
        let now = self.disciplined_now(monotonic_now)?;
        let control_expired = self.expire_control_lease(now.utc);
        self.enforce_drop_copy_liveness(now.utc, output)?;
        if control_expired {
            self.desired_bid = None;
            self.desired_ask = None;
            return self.reconcile_quotes(now.utc, output);
        }
        Ok(OutputBatch { commands: 0 })
    }

    /// Confirm whether the exact prepared command crossed the transport boundary.
    ///
    /// # Errors
    ///
    /// A different command, a replace command, an invalid lifecycle transition, or
    /// an unsafe clock fails closed. Proven-unsent new orders release risk exactly;
    /// proven-unsent cancels return their order to `Live` without changing risk.
    pub fn on_transmission(
        &mut self,
        command: OrderCommand,
        status: TransmissionStatus,
        monotonic_now: MonotonicTimestampNs,
    ) -> Result<(), EngineError> {
        let now = self.disciplined_now(monotonic_now)?.utc;
        let (side, client_order_id) = match command {
            OrderCommand::New(order) => (order.side, order.client_order_id),
            OrderCommand::Cancel(cancel) => {
                let snapshot = self.managed_order(cancel.client_order_id, now)?;
                (snapshot.side, cancel.client_order_id)
            }
            OrderCommand::Replace(_) => {
                return self.internal_error(now, EngineError::ReplaceForbidden);
            }
            OrderCommand::CancelAll(_) => {
                return self.internal_error(now, EngineError::CommandMismatch);
            }
        };
        let state = self.side_state(side);
        if state.client_order_id != Some(client_order_id)
            || state.pending_command != Some(command)
            || !self.command_matches_record(command, now)?
        {
            return self.internal_error(now, EngineError::CommandMismatch);
        }

        let result = match (command, status) {
            (OrderCommand::New(_), TransmissionStatus::Sent) => {
                self.orders
                    .mark_new_transmitted(client_order_id, now, &self.kill)
            }
            (OrderCommand::New(_), TransmissionStatus::ProvenUnsent) => self
                .orders
                .rollback_unsent_new(client_order_id, now, &mut self.risk, &self.kill)
                .map(|_| ()),
            (OrderCommand::Cancel(_), TransmissionStatus::Sent) => self
                .orders
                .mark_cancel_transmitted(client_order_id, now, &self.kill),
            (OrderCommand::Cancel(_), TransmissionStatus::ProvenUnsent) => self
                .orders
                .rollback_unsent_cancel(client_order_id, now, &self.kill)
                .map(|_| ()),
            (OrderCommand::Replace(_), _) => unreachable!("replace rejected above"),
            (OrderCommand::CancelAll(_), _) => unreachable!("cancel-all rejected above"),
        };
        if let Err(error) = result {
            self.kill.trigger(KillCode::InternalInvariant, now);
            return Err(EngineError::Order(error));
        }
        self.side_state_mut(side).pending_command = None;
        if status == TransmissionStatus::ProvenUnsent && matches!(command, OrderCommand::New(_)) {
            self.side_state_mut(side).client_order_id = None;
        }
        self.validate_managed_routes(now)
    }

    /// Prepare cancellation of every currently live quote after a kill.
    ///
    /// This uses the last disciplined timestamp because the initiating fault may make
    /// a fresh clock conversion unavailable. Pending wire outcomes remain untouched.
    ///
    /// # Errors
    ///
    /// Returns an error when no prior safe timestamp exists, output is undersized, or
    /// managed-order state is inconsistent.
    pub fn prepare_kill_cancels(
        &mut self,
        output: &mut [Option<OrderCommand>],
    ) -> Result<OutputBatch, EngineError> {
        clear_output(output);
        let now = self
            .last_safe_now
            .ok_or(EngineError::Clock(ClockError::Uninitialized))?;
        self.desired_bid = None;
        self.desired_ask = None;
        self.reconcile_quotes(now, output)
    }

    /// Latch an internal hot-path fault and prepare every currently live cancel.
    ///
    /// This is the reactor's fail-closed escape hatch for faults that occur before a
    /// new input can safely enter the engine, such as exhausted egress capacity. It
    /// uses the last accepted disciplined timestamp. Before clock initialization no
    /// order can have been prepared, so the kill is latched at zero and no cancel is
    /// emitted.
    ///
    /// # Errors
    ///
    /// Returns a reconciliation or output-capacity error after the kill has already
    /// been latched. The initiating fault can never be undone by this return value.
    pub fn fail_closed(
        &mut self,
        code: KillCode,
        output: &mut [Option<OrderCommand>],
    ) -> Result<OutputBatch, EngineError> {
        clear_output(output);
        let now = self.last_safe_now.unwrap_or(TimestampNs::ZERO);
        self.control_armed = false;
        self.control_lease_deadline = None;
        self.desired_bid = None;
        self.desired_ask = None;
        self.kill.trigger(code, now);
        if self.last_safe_now.is_none() {
            return Ok(OutputBatch { commands: 0 });
        }
        self.reconcile_quotes(now, output)
    }

    fn expire_control_lease(&mut self, now: TimestampNs) -> bool {
        if !self.control_armed {
            return false;
        }
        let Some(deadline) = self.control_lease_deadline else {
            self.control_armed = false;
            self.desired_bid = None;
            self.desired_ask = None;
            self.kill.trigger(KillCode::InternalInvariant, now);
            return true;
        };
        if now <= deadline {
            return false;
        }
        self.control_armed = false;
        self.control_lease_deadline = None;
        self.desired_bid = None;
        self.desired_ask = None;
        self.kill.trigger(KillCode::VenueDisconnect, now);
        true
    }

    fn reject_control_provenance(
        &mut self,
        output: &mut [Option<OrderCommand>],
    ) -> Result<OutputBatch, EngineError> {
        self.fail_closed(KillCode::InternalInvariant, output)?;
        Err(EngineError::ControlProvenance)
    }

    fn drop_copy_failure<T>(
        &mut self,
        error: DropCopyError,
        output: &mut [Option<OrderCommand>],
    ) -> Result<T, EngineError> {
        self.fail_closed(KillCode::DropCopyMismatch, output)?;
        Err(EngineError::DropCopy(error))
    }

    fn quarantine_lifecycle_correction(
        &mut self,
        correction: LifecycleCorrectionObserved,
        now: TimestampNs,
    ) -> Result<(), EngineError> {
        if !correction.is_valid() {
            return self.internal_error(now, EngineError::InternalInvariant);
        }
        self.control_armed = false;
        self.control_lease_deadline = None;
        self.desired_bid = None;
        self.desired_ask = None;
        self.kill.trigger(KillCode::LifecycleCorrection, now);
        Ok(())
    }

    fn enforce_drop_copy_liveness(
        &mut self,
        observed: TimestampNs,
        output: &mut [Option<OrderCommand>],
    ) -> Result<(), EngineError> {
        let result = self
            .drop_copy
            .as_ref()
            .map_or(Ok(()), |gate| gate.check_pending_liveness(observed));
        match result {
            Ok(()) => Ok(()),
            Err(error) => self.drop_copy_failure(error, output),
        }
    }

    fn disciplined_now(
        &mut self,
        monotonic_now: MonotonicTimestampNs,
    ) -> Result<DisciplinedTimestamp, EngineError> {
        // Inputs are journaled with their raw capture/transport timestamp, but the
        // priority feedback lane may overtake an already captured normal-lane event.
        // Apply in reactor order without allowing engine time to move backwards.
        // Zero remains invalid and is never hidden by the causal floor.
        let effective_monotonic = if monotonic_now == MonotonicTimestampNs::ZERO {
            monotonic_now
        } else {
            self.last_applied_monotonic
                .map_or(monotonic_now, |prior| prior.max(monotonic_now))
        };
        match self.clock.timestamp(effective_monotonic) {
            Ok(now) => {
                self.last_applied_monotonic = Some(effective_monotonic);
                if let Some(prior) = self.last_safe_now
                    && now.utc < prior
                {
                    self.kill.trigger(KillCode::ClockUnsafe, prior);
                    return Err(EngineError::EventTimestampRegression {
                        prior,
                        received: now.utc,
                    });
                }
                self.last_safe_now = Some(now.utc);
                Ok(now)
            }
            Err(error) => {
                let trigger_at = self.last_safe_now.unwrap_or(TimestampNs::ZERO);
                self.kill.trigger(KillCode::ClockUnsafe, trigger_at);
                Err(EngineError::Clock(error))
            }
        }
    }

    fn begin_snapshot(
        &mut self,
        snapshot_id: u64,
        last_incremental_sequence: Sequence,
        now: TimestampNs,
    ) -> Result<(), EngineError> {
        if self.market_state != EngineMarketState::SnapshotRequired {
            return Err(EngineError::InvalidSnapshotState(self.market_state));
        }
        let next =
            next_sequence(last_incremental_sequence).ok_or(EngineError::InvalidSnapshotMessage)?;
        if snapshot_id == 0 || next < self.expected_market_sequence {
            return Err(EngineError::InvalidSnapshotMessage);
        }
        if self.orders.order_count() != 0 {
            self.kill.trigger(KillCode::MarketDataGap, now);
        }
        self.book.reset_from_snapshot(Sequence(1));
        self.owned_mbo.clear();
        self.bid_exact_queue = None;
        self.ask_exact_queue = None;
        self.last_mark = None;
        self.venue_trading_open = false;
        self.desired_bid = None;
        self.desired_ask = None;
        self.market_state = EngineMarketState::ApplyingSnapshot {
            snapshot_id,
            last_incremental_sequence,
        };
        Ok(())
    }

    fn apply_snapshot_order(
        &mut self,
        order: SnapshotOrder,
        now: TimestampNs,
    ) -> Result<ApplyOutcome, EngineError> {
        if !matches!(
            self.market_state,
            EngineMarketState::ApplyingSnapshot { .. }
        ) {
            return Err(EngineError::InvalidSnapshotState(self.market_state));
        }
        self.validate_normalized_market_economics(
            order.instrument,
            order.price,
            order.quantity,
            now,
        )?;
        if order.instrument != self.config.instrument
            || order.order_id.0 == 0
            || !order.price.is_positive()
            || !order.quantity.is_positive()
        {
            return Err(EngineError::InvalidSnapshotMessage);
        }
        let sequence = self.book.expected_sequence();
        self.book
            .apply(
                sequence,
                BookEvent::Add {
                    order_id: OrderId(order.order_id.0),
                    side: order.side,
                    price: order.price,
                    quantity: order.quantity,
                },
            )
            .map_err(|error| {
                self.kill.trigger(KillCode::MarketDataGap, now);
                EngineError::Book(error)
            })
    }

    fn complete_snapshot(
        &mut self,
        snapshot_id: u64,
        last_incremental_sequence: Sequence,
        _now: TimestampNs,
    ) -> Result<(), EngineError> {
        let EngineMarketState::ApplyingSnapshot {
            snapshot_id: expected_id,
            last_incremental_sequence: expected_last,
        } = self.market_state
        else {
            return Err(EngineError::InvalidSnapshotState(self.market_state));
        };
        if snapshot_id != expected_id || last_incremental_sequence != expected_last {
            return Err(EngineError::SnapshotBoundaryMismatch);
        }
        self.expected_market_sequence =
            next_sequence(last_incremental_sequence).ok_or(EngineError::SequenceExhausted)?;
        self.market_state = EngineMarketState::Live;
        Ok(())
    }

    fn require_new_snapshot(&mut self) {
        self.market_state = EngineMarketState::SnapshotRequired;
        self.venue_trading_open = false;
        self.desired_bid = None;
        self.desired_ask = None;
        self.last_mark = None;
        self.book.reset_from_snapshot(Sequence(1));
        self.owned_mbo.clear();
        self.bid_exact_queue = None;
        self.ask_exact_queue = None;
    }

    fn validate_market_envelope(
        &mut self,
        message: MarketDataMessage,
        now: DisciplinedTimestamp,
    ) -> Result<(), EngineError> {
        if message.instrument != self.config.instrument {
            return self.internal_error(
                now.utc,
                EngineError::InstrumentMismatch {
                    expected: self.config.instrument,
                    received: message.instrument,
                },
            );
        }
        if message.sequence != self.expected_market_sequence {
            self.require_new_snapshot();
            self.kill.trigger(KillCode::MarketDataGap, now.utc);
            return Err(EngineError::MarketSequenceMismatch {
                expected: self.expected_market_sequence,
                received: message.sequence,
            });
        }
        self.validate_timestamps(
            message.exchange_timestamp,
            message.hardware_receive_timestamp,
            now.utc,
            self.market_timestamps.exchange,
            self.market_timestamps.received,
        )
    }

    fn validate_market_payload(
        &mut self,
        payload: MarketDataPayload,
        now: TimestampNs,
    ) -> Result<(), EngineError> {
        let economics = match payload {
            MarketDataPayload::Book(
                BookDelta::Add {
                    price, quantity, ..
                }
                | BookDelta::Modify {
                    price, quantity, ..
                }
                | BookDelta::Execute {
                    price, quantity, ..
                },
            )
            | MarketDataPayload::Trade {
                price, quantity, ..
            } => Some((price, quantity)),
            MarketDataPayload::Book(BookDelta::Cancel { .. } | BookDelta::Clear)
            | MarketDataPayload::TradingStatus { .. } => None,
        };
        if let Some((price, quantity)) = economics {
            self.validate_normalized_market_economics(
                self.config.instrument,
                price,
                quantity,
                now,
            )?;
        }
        Ok(())
    }

    fn validate_normalized_market_economics(
        &mut self,
        instrument: InstrumentId,
        price: PriceTicks,
        quantity: Quantity,
        now: TimestampNs,
    ) -> Result<(), EngineError> {
        if let Err(error) = self
            .config
            .instrument_definition
            .validate_normalized_economics(instrument, price, quantity)
        {
            self.require_new_snapshot();
            self.kill.trigger(KillCode::MarketDataGap, now);
            return Err(EngineError::InstrumentRule(error));
        }
        Ok(())
    }

    fn validate_order_envelope(
        &mut self,
        message: InboundMessage,
        now: DisciplinedTimestamp,
    ) -> Result<(), EngineError> {
        if message.sequence != self.expected_order_sequence {
            self.venue_trading_open = false;
            self.order_session_live = false;
            self.kill.trigger(KillCode::VenueDisconnect, now.utc);
            return Err(EngineError::OrderSequenceMismatch {
                expected: self.expected_order_sequence,
                received: message.sequence,
            });
        }
        self.validate_timestamps(
            message.exchange_timestamp,
            message.hardware_receive_timestamp,
            now.utc,
            self.order_timestamps.exchange,
            self.order_timestamps.received,
        )
    }

    fn validate_control_timestamp(&mut self, now: TimestampNs) -> Result<(), EngineError> {
        if now == TimestampNs::ZERO {
            let trigger_at = self.last_safe_now.unwrap_or(now);
            self.kill.trigger(KillCode::ClockUnsafe, trigger_at);
            return Err(EngineError::InvalidEventTimestamp);
        }
        if let Some(prior) = self.last_safe_now
            && now < prior
        {
            self.kill.trigger(KillCode::ClockUnsafe, prior);
            return Err(EngineError::EventTimestampRegression {
                prior,
                received: now,
            });
        }
        Ok(())
    }

    fn commit_order_source_progress(&mut self, next: Sequence, message: InboundMessage) {
        self.expected_order_sequence = next;
        self.order_timestamps = SourceTimestampCursor {
            exchange: message.exchange_timestamp,
            received: message.hardware_receive_timestamp,
        };
    }

    fn preflight_event_output_capacity(
        &mut self,
        output: &mut [Option<OrderCommand>],
    ) -> Result<(), EngineError> {
        clear_output(output);
        if output.len() >= MAX_COMMANDS_PER_EVENT {
            return Ok(());
        }
        self.kill.trigger(
            KillCode::InternalInvariant,
            self.last_safe_now.unwrap_or(TimestampNs::ZERO),
        );
        Err(EngineError::OutputCapacity {
            required: MAX_COMMANDS_PER_EVENT,
            provided: output.len(),
        })
    }

    fn finish_consumed_order_source_error(
        &mut self,
        error: EngineError,
        next: Sequence,
        message: InboundMessage,
        now: TimestampNs,
        output: &mut [Option<OrderCommand>],
    ) -> Result<OrderEventOutcome, EngineError> {
        // A valid fatal session event and an AfterReconciled lifecycle error are
        // authoritative consumed facts even though application returns a fault. Keep
        // the source cursor aligned with the state mutation so a retry cannot apply
        // the same fact twice and the next sequenced reconciliation remains visible.
        self.commit_order_source_progress(next, message);
        self.desired_bid = None;
        self.desired_ask = None;
        // `HotPathReactor` publishes this populated cancel-first prefix before it
        // returns the original typed failure. Defensive cleanup must not replace that
        // consumed-fact error: discard an invalid/partial batch and keep the kill
        // latched if route validation or cancel preparation itself fails.
        if self
            .validate_managed_routes(now)
            .and_then(|()| self.reconcile_quotes(now, output).map(|_| ()))
            .is_err()
        {
            clear_output(output);
            self.kill.trigger(KillCode::InternalInvariant, now);
        }
        Err(error)
    }

    fn validate_timestamps(
        &mut self,
        exchange: TimestampNs,
        received: TimestampNs,
        now: TimestampNs,
        prior_exchange: TimestampNs,
        prior_received: TimestampNs,
    ) -> Result<(), EngineError> {
        if exchange == TimestampNs::ZERO
            || received == TimestampNs::ZERO
            || exchange > received
            || received > now
        {
            self.kill.trigger(KillCode::ClockUnsafe, now);
            return Err(EngineError::InvalidEventTimestamp);
        }
        if prior_exchange != TimestampNs::ZERO && exchange < prior_exchange {
            self.kill.trigger(KillCode::ClockUnsafe, now);
            return Err(EngineError::EventTimestampRegression {
                prior: prior_exchange,
                received: exchange,
            });
        }
        if prior_received != TimestampNs::ZERO && received < prior_received {
            self.kill.trigger(KillCode::ClockUnsafe, now);
            return Err(EngineError::EventTimestampRegression {
                prior: prior_received,
                received,
            });
        }
        Ok(())
    }

    fn apply_book_delta(
        &mut self,
        delta: BookDelta,
        now: TimestampNs,
    ) -> Result<ApplyOutcome, EngineError> {
        let event = match delta {
            BookDelta::Add {
                order_id,
                side,
                price,
                quantity,
            } => BookEvent::Add {
                order_id: OrderId(order_id.0),
                side,
                price,
                quantity,
            },
            BookDelta::Modify {
                order_id,
                price,
                quantity,
            } => BookEvent::Modify {
                order_id: OrderId(order_id.0),
                price,
                quantity,
            },
            BookDelta::Cancel { order_id } => BookEvent::Cancel {
                order_id: OrderId(order_id.0),
            },
            BookDelta::Execute {
                order_id,
                price,
                quantity,
            } => {
                if let Some(order) = self.book.order(OrderId(order_id.0))
                    && order.price != price
                {
                    self.require_new_snapshot();
                    self.kill.trigger(KillCode::MarketDataGap, now);
                    return Err(EngineError::BookExecutionPriceMismatch {
                        order_id,
                        expected: order.price,
                        received: price,
                    });
                }
                BookEvent::Execute {
                    order_id: OrderId(order_id.0),
                    quantity,
                }
            }
            BookDelta::Clear => BookEvent::Clear,
        };
        let local_sequence = self.book.expected_sequence();
        match self.book.apply(local_sequence, event) {
            Ok(outcome) => {
                self.update_exact_queues(outcome, now)?;
                Ok(outcome)
            }
            Err(error) => {
                let code = match error {
                    BookError::Desynchronized | BookError::SequenceMismatch { .. } => {
                        KillCode::MarketDataGap
                    }
                    _ => KillCode::InternalInvariant,
                };
                self.require_new_snapshot();
                self.kill.trigger(code, now);
                Err(EngineError::Book(error))
            }
        }
    }

    fn top_of_book(
        &mut self,
        now: TimestampNs,
    ) -> Result<Option<(PriceLevel, PriceLevel, PriceTicks)>, EngineError> {
        let (Some(bid), Some(ask)) = (self.book.best_bid(), self.book.best_ask()) else {
            return Ok(None);
        };
        if !bid.total_quantity.is_positive()
            || !ask.total_quantity.is_positive()
            || bid.price >= ask.price
        {
            return self.internal_error(now, EngineError::InternalInvariant);
        }
        let midpoint = i128::from(bid.price.0)
            .checked_add(i128::from(ask.price.0))
            .and_then(|sum| sum.checked_div(2))
            .and_then(|value| i64::try_from(value).ok())
            .filter(|value| *value > 0)
            .map(PriceTicks)
            .ok_or_else(|| {
                self.kill.trigger(KillCode::InternalInvariant, now);
                EngineError::InternalInvariant
            })?;
        Ok(Some((bid, ask, midpoint)))
    }

    fn quote_from_top(
        &mut self,
        bid: PriceLevel,
        ask: PriceLevel,
        mark: PriceTicks,
        now: TimestampNs,
    ) -> Result<QuoteDecision, EngineError> {
        let inventory = self
            .risk
            .instrument(self.config.instrument)
            .ok_or_else(|| {
                self.kill.trigger(KillCode::InternalInvariant, now);
                EngineError::InternalInvariant
            })?
            .position;
        let quote_config = self.quoter.config();
        let alpha_unit = quote_config.max_abs_alpha_ticks.min(1);
        let alpha = match bid.total_quantity.cmp(&ask.total_quantity) {
            core::cmp::Ordering::Less => -alpha_unit,
            core::cmp::Ordering::Equal => 0,
            core::cmp::Ordering::Greater => alpha_unit,
        };
        let volatility = if let Some(prior) = self.last_mark {
            let volatility_limit = u64::try_from(quote_config.max_volatility_spread_ticks)
                .map_err(|_| EngineError::InternalInvariant)?;
            let bounded = prior.0.abs_diff(mark.0).min(volatility_limit);
            i64::try_from(bounded).map_err(|_| EngineError::InternalInvariant)?
        } else {
            0
        };
        let features = MarketFeatures {
            best_bid: bid.price,
            best_bid_quantity: bid.total_quantity,
            best_ask: ask.price,
            best_ask_quantity: ask.total_quantity,
            short_horizon_alpha_ticks: alpha,
            volatility_spread_ticks: volatility,
            inventory,
            instrument_halted: self.adverse.is_halted(self.config.instrument)
                || !self.trading_eligible(),
        };
        match self.quoter.decide(features) {
            Ok(decision) => Ok(decision),
            Err(error) => {
                self.kill.trigger(KillCode::InternalInvariant, now);
                Err(EngineError::Strategy(error))
            }
        }
    }

    fn apply_session(
        &mut self,
        event: SessionEvent,
        now: TimestampNs,
    ) -> Result<OrderApplication, EngineError> {
        match event {
            SessionEvent::LogonAccepted | SessionEvent::ReplayComplete { .. } => {
                self.order_session_live = true;
                Ok(OrderApplication::Session(event))
            }
            SessionEvent::Heartbeat => Ok(OrderApplication::Session(event)),
            SessionEvent::LogonRejected { .. }
            | SessionEvent::SnapshotRequired
            | SessionEvent::Logout { .. } => {
                self.venue_trading_open = false;
                self.order_session_live = false;
                self.kill.trigger(KillCode::VenueDisconnect, now);
                Err(EngineError::VenueUnavailable(event))
            }
        }
    }

    fn apply_order_event(
        &mut self,
        event: OrderEvent,
        sequence: Sequence,
        exchange_timestamp: TimestampNs,
        now: TimestampNs,
    ) -> Result<(OrderApplication, bool), EngineError> {
        match event {
            OrderEvent::Accepted(accepted) => self.apply_accepted(accepted, sequence, now),
            OrderEvent::Rejected(rejected) => self.apply_rejected(rejected, sequence, now),
            OrderEvent::Canceled(canceled) => self.apply_canceled(canceled, sequence, now),
            OrderEvent::Fill(fill) => self.apply_fill(fill, sequence, exchange_timestamp, now),
            OrderEvent::LifecycleCorrectionObserved(correction) => Ok((
                OrderApplication::LifecycleCorrectionQuarantined(correction),
                true,
            )),
        }
    }

    fn apply_accepted(
        &mut self,
        event: Accepted,
        sequence: Sequence,
        now: TimestampNs,
    ) -> Result<(OrderApplication, bool), EngineError> {
        let snapshot = self.managed_order(event.client_order_id, now)?;
        if snapshot.state != ManagedOrderState::PendingNew
            || event.price != snapshot.limit_price
            || event.quantity != snapshot.original_quantity
        {
            return self
                .internal_error(now, EngineError::OrderReportMismatch(event.client_order_id));
        }
        let report = NewAccepted {
            order: VenueOrderIdentity {
                economics: economics(snapshot),
                venue_order_id: event.venue_order_id,
            },
            sequence,
            leaves_quantity: snapshot.remaining_quantity,
            received_at: now,
        };
        let result = self.orders.on_new_accepted(report, &self.risk, &self.kill);
        let applied = self.order_result(result, now)?;
        self.sync_side_after_reconciled(snapshot.side, event.client_order_id, None, None, now)?;
        Ok((OrderApplication::Accepted(applied), true))
    }

    fn apply_rejected(
        &mut self,
        event: Rejected,
        sequence: Sequence,
        now: TimestampNs,
    ) -> Result<(OrderApplication, bool), EngineError> {
        let snapshot = self.managed_order(event.client_order_id, now)?;
        match snapshot.state {
            ManagedOrderState::PendingNew => {
                let report = NewRejected {
                    order: economics(snapshot),
                    sequence,
                    leaves_quantity: snapshot.remaining_quantity,
                    received_at: now,
                };
                let result = self
                    .orders
                    .on_new_rejected(report, &mut self.risk, &self.kill);
                self.order_result(result, now)?;
                self.sync_side_after_reconciled(
                    snapshot.side,
                    event.client_order_id,
                    None,
                    None,
                    now,
                )?;
                Ok((
                    OrderApplication::NewRejected {
                        client_order_id: event.client_order_id,
                        code: event.code,
                    },
                    false,
                ))
            }
            ManagedOrderState::PendingCancel => {
                let venue_order_id = snapshot.venue_order_id.ok_or_else(|| {
                    self.kill.trigger(KillCode::InternalInvariant, now);
                    EngineError::OrderReportMismatch(event.client_order_id)
                })?;
                let report = CancelRejected {
                    order: VenueOrderIdentity {
                        economics: economics(snapshot),
                        venue_order_id,
                    },
                    sequence,
                    leaves_quantity: snapshot.remaining_quantity,
                    received_at: now,
                };
                let result = self
                    .orders
                    .on_cancel_rejected(report, &self.risk, &self.kill);
                let applied = self.order_result(result, now)?;
                self.sync_side_after_reconciled(
                    snapshot.side,
                    event.client_order_id,
                    None,
                    None,
                    now,
                )?;
                Ok((
                    OrderApplication::CancelRejected {
                        order: applied,
                        code: event.code,
                    },
                    false,
                ))
            }
            ManagedOrderState::Live => {
                self.internal_error(now, EngineError::OrderReportMismatch(event.client_order_id))
            }
        }
    }

    fn apply_canceled(
        &mut self,
        event: Canceled,
        sequence: Sequence,
        now: TimestampNs,
    ) -> Result<(OrderApplication, bool), EngineError> {
        let snapshot = self.managed_order(event.client_order_id, now)?;
        if snapshot
            .venue_order_id
            .is_some_and(|id| id != event.venue_order_id)
        {
            return self
                .internal_error(now, EngineError::OrderReportMismatch(event.client_order_id));
        }
        let reason = if snapshot.state == ManagedOrderState::PendingCancel {
            CancelReason::Requested
        } else {
            CancelReason::Unsolicited
        };
        let report = CancelConfirmed {
            order: VenueOrderIdentity {
                economics: economics(snapshot),
                venue_order_id: event.venue_order_id,
            },
            sequence,
            canceled_quantity: event.canceled_quantity,
            leaves_quantity: event.leaves_quantity,
            reason,
            received_at: now,
        };
        let result = self
            .orders
            .on_cancel_confirmed(report, &mut self.risk, &self.kill);
        let applied = match result {
            Ok(applied) => applied,
            Err(error) => {
                let Some(order_fault) = ReconciledOrderFaultSummary::from_order_error(error) else {
                    return self.order_result(Err(error), now);
                };
                self.sync_side_after_reconciled(
                    snapshot.side,
                    event.client_order_id,
                    Some(order_fault),
                    None,
                    now,
                )?;
                return Err(EngineError::Order(error));
            }
        };
        self.sync_side_after_reconciled(snapshot.side, event.client_order_id, None, None, now)?;
        let may_reconcile = applied.terminal;
        Ok((OrderApplication::Canceled(applied), may_reconcile))
    }

    fn apply_fill(
        &mut self,
        event: Fill,
        sequence: Sequence,
        exchange_timestamp: TimestampNs,
        now: TimestampNs,
    ) -> Result<(OrderApplication, bool), EngineError> {
        let snapshot = self.managed_order(event.client_order_id, now)?;
        if snapshot
            .venue_order_id
            .is_some_and(|id| id != event.venue_order_id)
        {
            return self
                .internal_error(now, EngineError::OrderReportMismatch(event.client_order_id));
        }
        let report = FillReport {
            order: VenueOrderIdentity {
                economics: economics(snapshot),
                venue_order_id: event.venue_order_id,
            },
            sequence,
            trade_id: event.trade_id,
            fill_price: event.price,
            fill_quantity: event.quantity,
            leaves_quantity: event.leaves_quantity,
            fill_timestamp: exchange_timestamp,
            received_at: now,
        };
        let instrument_rule_violation = self
            .config
            .instrument_definition
            .validate_normalized_economics(snapshot.instrument, event.price, event.quantity)
            .err();
        let result = self
            .orders
            .on_fill(report, &mut self.risk, &mut self.adverse, &self.kill);
        let applied = match result {
            Ok(applied) => {
                self.sync_side_after_reconciled(
                    snapshot.side,
                    event.client_order_id,
                    None,
                    instrument_rule_violation,
                    now,
                )?;
                if let Some(violation) = instrument_rule_violation {
                    self.kill.trigger(KillCode::InternalInvariant, now);
                    return Err(EngineError::OrderInstrumentRuleAfterReconciled {
                        violation,
                        order_fault: None,
                    });
                }
                applied
            }
            Err(error) => {
                let Some(order_fault) = ReconciledOrderFaultSummary::from_order_error(error) else {
                    return self.order_result(Err(error), now);
                };
                // `OrderManager` has already reconciled the authoritative financial
                // fact. Route state must converge before the engine reports the typed
                // downstream safety failure to its source-cursor owner.
                self.sync_side_after_reconciled(
                    snapshot.side,
                    event.client_order_id,
                    Some(order_fault),
                    instrument_rule_violation,
                    now,
                )?;
                if let Some(violation) = instrument_rule_violation {
                    self.kill.trigger(KillCode::InternalInvariant, now);
                    return Err(EngineError::OrderInstrumentRuleAfterReconciled {
                        violation,
                        order_fault: Some(order_fault),
                    });
                }
                return Err(EngineError::Order(error));
            }
        };
        let may_reconcile = applied.remaining_quantity == Quantity::ZERO
            && !applied.retained_for_protocol_resolution;
        Ok((OrderApplication::Fill(applied), may_reconcile))
    }

    fn managed_order(
        &mut self,
        client_order_id: ClientOrderId,
        now: TimestampNs,
    ) -> Result<ManagedOrderSnapshot, EngineError> {
        let snapshot = self.orders.order(client_order_id).ok_or_else(|| {
            self.kill.trigger(KillCode::InternalInvariant, now);
            EngineError::UnknownManagedOrder(client_order_id)
        })?;
        if snapshot.instrument != self.config.instrument
            || self.side_state(snapshot.side).client_order_id != Some(client_order_id)
        {
            return self.internal_error(now, EngineError::OrderRouteMismatch(client_order_id));
        }
        Ok(snapshot)
    }

    fn command_matches_record(
        &mut self,
        command: OrderCommand,
        now: TimestampNs,
    ) -> Result<bool, EngineError> {
        match command {
            OrderCommand::New(order) => {
                let snapshot = self.managed_order(order.client_order_id, now)?;
                Ok(snapshot.state == ManagedOrderState::PendingNew
                    && !snapshot.new_transmitted
                    && order.instrument == snapshot.instrument
                    && order.side == snapshot.side
                    && order.price == snapshot.limit_price
                    && order.quantity == snapshot.original_quantity
                    && order.time_in_force == TimeInForce::PostOnly)
            }
            OrderCommand::Cancel(cancel) => {
                let snapshot = self.managed_order(cancel.client_order_id, now)?;
                Ok(snapshot.state == ManagedOrderState::PendingCancel
                    && !snapshot.cancel_transmitted
                    && snapshot.venue_order_id == Some(cancel.venue_order_id))
            }
            OrderCommand::Replace(_) | OrderCommand::CancelAll(_) => Ok(false),
        }
    }

    fn sync_side(
        &mut self,
        side: Side,
        client_order_id: ClientOrderId,
        now: TimestampNs,
    ) -> Result<(), EngineError> {
        let present = self.orders.order(client_order_id).is_some();
        {
            let state = self.side_state_mut(side);
            if state.client_order_id != Some(client_order_id) || state.pending_command.is_some() {
                return self.internal_error(now, EngineError::OrderRouteMismatch(client_order_id));
            }
            if !present {
                state.client_order_id = None;
            }
        }
        if !present {
            self.cleanup_exact_queue(side, now)?;
        }
        Ok(())
    }

    fn sync_side_after_reconciled(
        &mut self,
        side: Side,
        client_order_id: ClientOrderId,
        order_fault: Option<ReconciledOrderFaultSummary>,
        instrument_rule_violation: Option<InstrumentRuleViolation>,
        now: TimestampNs,
    ) -> Result<(), EngineError> {
        match self.sync_side(side, client_order_id, now) {
            Ok(()) => Ok(()),
            Err(_) => Err(EngineError::OrderRouteAfterReconciled {
                client_order_id,
                order_fault,
                instrument_rule_violation,
            }),
        }
    }

    fn validate_managed_routes(&mut self, now: TimestampNs) -> Result<(), EngineError> {
        let mut routed = 0;
        for side in [Side::Buy, Side::Sell] {
            let state = self.side_state(side);
            if let Some(client_order_id) = state.client_order_id {
                routed += 1;
                let Some(snapshot) = self.orders.order(client_order_id) else {
                    return self
                        .internal_error(now, EngineError::OrderRouteMismatch(client_order_id));
                };
                if snapshot.side != side || snapshot.instrument != self.config.instrument {
                    return self
                        .internal_error(now, EngineError::OrderRouteMismatch(client_order_id));
                }
                let command_expected = match snapshot.state {
                    ManagedOrderState::PendingNew => !snapshot.new_transmitted,
                    ManagedOrderState::Live => false,
                    ManagedOrderState::PendingCancel => !snapshot.cancel_transmitted,
                };
                if state.pending_command.is_some() != command_expected {
                    return self.internal_error(now, EngineError::InternalInvariant);
                }
            } else if state.pending_command.is_some() {
                return self.internal_error(now, EngineError::InternalInvariant);
            }
        }
        if routed != self.orders.order_count() {
            return self.internal_error(now, EngineError::InternalInvariant);
        }
        Ok(())
    }

    fn reconcile_quotes(
        &mut self,
        now: TimestampNs,
        output: &mut [Option<OrderCommand>],
    ) -> Result<OutputBatch, EngineError> {
        self.validate_managed_routes(now)?;
        if !self.trading_eligible() {
            self.desired_bid = None;
            self.desired_ask = None;
        }
        let mut plans = [None; MAX_COMMANDS_PER_EVENT];
        let mut plan_count = 0;
        // Cancellations are always prepared before any unrelated new quote.
        for side in [Side::Buy, Side::Sell] {
            if let Some(plan) = self.plan_cancel(side, now)? {
                plans[plan_count] = Some(plan);
                plan_count += 1;
            }
        }
        for side in [Side::Buy, Side::Sell] {
            if let Some(plan) = self.plan_new(side) {
                plans[plan_count] = Some(plan);
                plan_count += 1;
            }
        }
        if output.len() < plan_count {
            self.kill.trigger(KillCode::InternalInvariant, now);
            return Err(EngineError::OutputCapacity {
                required: plan_count,
                provided: output.len(),
            });
        }

        let mut commands = [None; MAX_COMMANDS_PER_EVENT];
        let mut prepared = [None; MAX_COMMANDS_PER_EVENT];
        for index in 0..plan_count {
            let plan = plans[index].ok_or_else(|| {
                self.kill.trigger(KillCode::InternalInvariant, now);
                EngineError::InternalInvariant
            })?;
            match self.prepare_action(plan, now) {
                Ok((command, action)) => {
                    commands[index] = Some(command);
                    prepared[index] = Some(action);
                }
                Err(error) => {
                    self.rollback_prepared(&prepared, index, now);
                    clear_output(output);
                    return Err(error);
                }
            }
        }
        output[..plan_count].copy_from_slice(&commands[..plan_count]);
        Ok(OutputBatch {
            commands: plan_count,
        })
    }

    fn plan_cancel(
        &mut self,
        side: Side,
        now: TimestampNs,
    ) -> Result<Option<PlannedAction>, EngineError> {
        if self
            .exact_queue(side)
            .is_some_and(|queue| queue.status() != QueueStatus::Active)
        {
            // Public MBO has already resolved the owned order. Await the matching
            // private lifecycle fact instead of emitting a stale cancel.
            return Ok(None);
        }
        let state = self.side_state(side);
        let Some(client_order_id) = state.client_order_id else {
            return Ok(None);
        };
        let snapshot = self.managed_order(client_order_id, now)?;
        if snapshot.state != ManagedOrderState::Live || state.pending_command.is_some() {
            return Ok(None);
        }
        let desired = self.desired(side);
        let matches = desired.is_some_and(|leg| {
            leg.side == side
                && leg.price == snapshot.limit_price
                && leg.quantity == snapshot.remaining_quantity
        });
        if matches {
            return Ok(None);
        }
        let venue_order_id = snapshot.venue_order_id.ok_or_else(|| {
            self.kill.trigger(KillCode::InternalInvariant, now);
            EngineError::InternalInvariant
        })?;
        Ok(Some(PlannedAction::Cancel {
            side,
            client_order_id,
            venue_order_id,
        }))
    }

    fn plan_new(&self, side: Side) -> Option<PlannedAction> {
        let state = self.side_state(side);
        if state.client_order_id.is_some()
            || state.pending_command.is_some()
            || self.exact_queue(side).is_some()
        {
            return None;
        }
        self.desired(side)
            .map(|leg| PlannedAction::New { side, leg })
    }

    fn prepare_action(
        &mut self,
        plan: PlannedAction,
        now: TimestampNs,
    ) -> Result<(OrderCommand, PreparedAction), EngineError> {
        match plan {
            PlannedAction::New { side, leg } => {
                if leg.side != side || !self.trading_eligible() {
                    return self.internal_error(now, EngineError::InternalInvariant);
                }
                if let Err(error) = self.config.instrument_definition.validate_order_economics(
                    self.config.venue,
                    self.config.instrument,
                    leg.price,
                    leg.quantity,
                    now,
                ) {
                    self.kill.trigger(KillCode::InternalInvariant, now);
                    return Err(EngineError::InstrumentRule(error));
                }
                let (client_order_id, risk_order_id) = self.take_identifiers(now)?;
                let request = NewOrderRequest {
                    client_order_id,
                    risk_order_id,
                    instrument: self.config.instrument,
                    side,
                    limit_price: leg.price,
                    quantity: leg.quantity,
                    now,
                    clock_healthy: true,
                };
                let result =
                    self.orders
                        .prepare_new(request, &mut self.risk, &self.adverse, &self.kill);
                if let Err(error) = result {
                    if !self.kill.is_triggered() {
                        self.kill.trigger(KillCode::InternalInvariant, now);
                    }
                    return Err(EngineError::Order(error));
                }
                let command = OrderCommand::New(NewOrder {
                    client_order_id,
                    instrument: self.config.instrument,
                    side,
                    price: leg.price,
                    quantity: leg.quantity,
                    time_in_force: TimeInForce::PostOnly,
                    created_at: now,
                });
                let state = self.side_state_mut(side);
                state.client_order_id = Some(client_order_id);
                state.pending_command = Some(command);
                Ok((
                    command,
                    PreparedAction::New {
                        side,
                        client_order_id,
                    },
                ))
            }
            PlannedAction::Cancel {
                side,
                client_order_id,
                venue_order_id,
            } => {
                let result = self.orders.prepare_cancel(client_order_id, now, &self.kill);
                if let Err(error) = result {
                    self.kill.trigger(KillCode::InternalInvariant, now);
                    return Err(EngineError::Order(error));
                }
                let command = OrderCommand::Cancel(CancelOrder {
                    client_order_id,
                    venue_order_id,
                    created_at: now,
                });
                self.side_state_mut(side).pending_command = Some(command);
                Ok((
                    command,
                    PreparedAction::Cancel {
                        side,
                        client_order_id,
                    },
                ))
            }
        }
    }

    fn rollback_prepared(
        &mut self,
        prepared: &[Option<PreparedAction>; MAX_COMMANDS_PER_EVENT],
        count: usize,
        now: TimestampNs,
    ) {
        for index in (0..count).rev() {
            let Some(action) = prepared[index] else {
                continue;
            };
            let result = match action {
                PreparedAction::New {
                    side,
                    client_order_id,
                } => {
                    let outcome = self.orders.rollback_unsent_new(
                        client_order_id,
                        now,
                        &mut self.risk,
                        &self.kill,
                    );
                    self.side_state_mut(side).client_order_id = None;
                    self.side_state_mut(side).pending_command = None;
                    outcome.map(|_| ())
                }
                PreparedAction::Cancel {
                    side,
                    client_order_id,
                } => {
                    let outcome =
                        self.orders
                            .rollback_unsent_cancel(client_order_id, now, &self.kill);
                    self.side_state_mut(side).pending_command = None;
                    outcome.map(|_| ())
                }
            };
            if result.is_err() {
                self.kill.trigger(KillCode::InternalInvariant, now);
            }
        }
    }

    fn take_identifiers(
        &mut self,
        now: TimestampNs,
    ) -> Result<(ClientOrderId, OrderId), EngineError> {
        let client = self.next_client_order_id;
        let risk = self.next_risk_order_id;
        let next_client = client.0.checked_add(1).map(ClientOrderId);
        let next_risk = risk.0.checked_add(1).map(OrderId);
        let (Some(next_client), Some(next_risk)) = (next_client, next_risk) else {
            self.kill.trigger(KillCode::InternalInvariant, now);
            return Err(EngineError::IdentifierExhausted);
        };
        if next_client.0 == 0 || next_risk.0 == 0 {
            self.kill.trigger(KillCode::InternalInvariant, now);
            return Err(EngineError::IdentifierExhausted);
        }
        self.next_client_order_id = next_client;
        self.next_risk_order_id = next_risk;
        Ok((client, risk))
    }

    fn order_result<T>(
        &mut self,
        result: Result<T, OrderError>,
        now: TimestampNs,
    ) -> Result<T, EngineError> {
        match result {
            Ok(value) => Ok(value),
            Err(error) => {
                if !self.kill.is_triggered() {
                    self.kill.trigger(KillCode::InternalInvariant, now);
                }
                Err(EngineError::Order(error))
            }
        }
    }

    const fn is_reconciled_engine_order_error(error: EngineError) -> bool {
        matches!(
            error,
            EngineError::Order(
                OrderError::RiskAfterReconciled(_)
                    | OrderError::AdverseAfterReconciled(_)
                    | OrderError::RiskAndAdverseAfterReconciled { .. }
                    | OrderError::ExecutionPriceAfterReconciled { .. }
            ) | EngineError::OrderInstrumentRuleAfterReconciled { .. }
                | EngineError::OrderRouteAfterReconciled { .. }
        )
    }

    fn update_exact_queues(
        &mut self,
        outcome: ApplyOutcome,
        now: TimestampNs,
    ) -> Result<(), EngineError> {
        self.update_exact_queue(Side::Buy, outcome, now)?;
        self.update_exact_queue(Side::Sell, outcome, now)
    }

    fn update_exact_queue(
        &mut self,
        side: Side,
        outcome: ApplyOutcome,
        now: TimestampNs,
    ) -> Result<(), EngineError> {
        let active = self
            .exact_queue(side)
            .is_some_and(|queue| queue.status() == QueueStatus::Active);
        if !active {
            return Ok(());
        }
        let result = match side {
            Side::Buy => self
                .bid_exact_queue
                .as_mut()
                .expect("active bid exact queue must exist")
                .on_book_outcome(&self.book, outcome),
            Side::Sell => self
                .ask_exact_queue
                .as_mut()
                .expect("active ask exact queue must exist")
                .on_book_outcome(&self.book, outcome),
        };
        if let Err(error) = result {
            return self.queue_failure(error, now);
        }
        self.cleanup_exact_queue(side, now)
    }

    fn cleanup_exact_queue(&mut self, side: Side, now: TimestampNs) -> Result<(), EngineError> {
        let Some(queue) = self.exact_queue(side) else {
            return Ok(());
        };
        if queue.status() == QueueStatus::Active {
            return Ok(());
        }
        let market_by_order_id = MarketByOrderId(queue.order_id().0);
        let Some(binding) = self.owned_mbo.by_market_order(market_by_order_id) else {
            return self.internal_error(now, EngineError::InternalInvariant);
        };
        if self.orders.order(binding.client_order_id).is_some() {
            return Ok(());
        }
        match self.owned_mbo.remove_by_client(binding.client_order_id) {
            Ok(Some(removed)) if removed == binding => {
                *self.exact_queue_mut(side) = None;
                Ok(())
            }
            Ok(Some(_) | None) => self.internal_error(now, EngineError::InternalInvariant),
            Err(error) => self.internal_error(now, EngineError::Ownership(error)),
        }
    }

    fn queue_failure<T>(&mut self, error: QueueError, now: TimestampNs) -> Result<T, EngineError> {
        self.require_new_snapshot();
        self.kill.trigger(KillCode::InternalInvariant, now);
        Err(EngineError::Queue(error))
    }

    fn side_state(&self, side: Side) -> SideState {
        match side {
            Side::Buy => self.bid,
            Side::Sell => self.ask,
        }
    }

    fn side_state_mut(&mut self, side: Side) -> &mut SideState {
        match side {
            Side::Buy => &mut self.bid,
            Side::Sell => &mut self.ask,
        }
    }

    fn exact_queue_mut(&mut self, side: Side) -> &mut Option<ExactQueuePosition<MAX_BOOK_ORDERS>> {
        match side {
            Side::Buy => &mut self.bid_exact_queue,
            Side::Sell => &mut self.ask_exact_queue,
        }
    }

    const fn desired(&self, side: Side) -> Option<QuoteLeg> {
        match side {
            Side::Buy => self.desired_bid,
            Side::Sell => self.desired_ask,
        }
    }

    fn internal_error<T>(
        &mut self,
        now: TimestampNs,
        error: EngineError,
    ) -> Result<T, EngineError> {
        self.kill.trigger(KillCode::InternalInvariant, now);
        Err(error)
    }
}

const fn economics(snapshot: ManagedOrderSnapshot) -> OrderEconomics {
    OrderEconomics {
        client_order_id: snapshot.client_order_id,
        instrument: snapshot.instrument,
        side: snapshot.side,
        limit_price: snapshot.limit_price,
        original_quantity: snapshot.original_quantity,
    }
}

const fn next_sequence(sequence: Sequence) -> Option<Sequence> {
    match sequence.0.checked_add(1) {
        Some(value) => Some(Sequence(value)),
        None => None,
    }
}

fn clear_output(output: &mut [Option<OrderCommand>]) {
    output.fill(None);
}

const fn control_kill_code(reason: ControlKillReason) -> KillCode {
    match reason {
        ControlKillReason::Manual => KillCode::Manual,
        ControlKillReason::LivenessExpired => KillCode::VenueDisconnect,
        ControlKillReason::AuthenticationFailure
        | ControlKillReason::ProtocolViolation
        | ControlKillReason::SequenceViolation
        | ControlKillReason::TimeViolation
        | ControlKillReason::ConfigurationViolation
        | ControlKillReason::InvalidState => KillCode::InternalInvariant,
    }
}
