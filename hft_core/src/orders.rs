//! Fixed-capacity managed-order lifecycle for the single-writer execution hot path.
//!
//! Venue reports are never trusted to supply risk identity. They must exactly match
//! the authenticated local record before this module applies inventory or reservation
//! facts. Fills are applied to risk first and adverse-selection surveillance second;
//! if surveillance fails, the inventory and order state remain reconciled and the
//! returned error explicitly reports that the fill was already committed. A venue
//! execution outside the authenticated limit is likewise accounted first and then
//! returned as a typed reconciled protocol violation.

use crate::adverse::{AdverseError, AdverseFill, AdverseMonitor, FillTrackOutcome};
use crate::fixed::{FixedIndexMap, FixedKey};
use crate::kill::{KillCode, KillLatch};
use crate::risk::{
    CancelOutcome, FillOutcome, PreTradeRequest, RiskApproval, RiskEngine, RiskError,
};
use crate::types::{InstrumentId, OrderId, PriceTicks, Quantity, Sequence, Side, TimestampNs};
use crate::venue::{ClientOrderId, TradeId, VenueOrderId};

impl FixedKey for ClientOrderId {
    fn fixed_hash(self) -> u64 {
        self.0.fixed_hash()
    }
}

impl FixedKey for VenueOrderId {
    fn fixed_hash(self) -> u64 {
        self.0.fixed_hash()
    }
}

impl FixedKey for TradeId {
    fn fixed_hash(self) -> u64 {
        self.0.fixed_hash()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ManagedOrderState {
    PendingNew = 1,
    Live = 2,
    PendingCancel = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum CancelReason {
    Requested = 1,
    Unsolicited = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum LifecycleEvent {
    MarkNewTransmitted = 1,
    RollbackNew = 2,
    NewAccepted = 3,
    NewRejected = 4,
    PrepareCancel = 5,
    MarkCancelTransmitted = 6,
    RollbackCancel = 7,
    CancelConfirmed = 8,
    CancelRejected = 9,
    Fill = 10,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NewOrderRequest {
    pub client_order_id: ClientOrderId,
    pub risk_order_id: OrderId,
    pub instrument: InstrumentId,
    pub side: Side,
    pub limit_price: PriceTicks,
    pub quantity: Quantity,
    pub now: TimestampNs,
    pub clock_healthy: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OrderEconomics {
    pub client_order_id: ClientOrderId,
    pub instrument: InstrumentId,
    pub side: Side,
    pub limit_price: PriceTicks,
    pub original_quantity: Quantity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VenueOrderIdentity {
    pub economics: OrderEconomics,
    pub venue_order_id: VenueOrderId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NewAccepted {
    pub order: VenueOrderIdentity,
    pub sequence: Sequence,
    pub leaves_quantity: Quantity,
    pub received_at: TimestampNs,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NewRejected {
    pub order: OrderEconomics,
    pub sequence: Sequence,
    pub leaves_quantity: Quantity,
    pub received_at: TimestampNs,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CancelConfirmed {
    pub order: VenueOrderIdentity,
    pub sequence: Sequence,
    pub canceled_quantity: Quantity,
    pub leaves_quantity: Quantity,
    pub reason: CancelReason,
    pub received_at: TimestampNs,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CancelRejected {
    pub order: VenueOrderIdentity,
    pub sequence: Sequence,
    pub leaves_quantity: Quantity,
    pub received_at: TimestampNs,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FillReport {
    pub order: VenueOrderIdentity,
    pub sequence: Sequence,
    pub trade_id: TradeId,
    pub fill_price: PriceTicks,
    pub fill_quantity: Quantity,
    pub leaves_quantity: Quantity,
    pub fill_timestamp: TimestampNs,
    pub received_at: TimestampNs,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManagedOrderSnapshot {
    pub client_order_id: ClientOrderId,
    pub venue_order_id: Option<VenueOrderId>,
    pub risk_order_id: OrderId,
    pub instrument: InstrumentId,
    pub side: Side,
    pub limit_price: PriceTicks,
    pub original_quantity: Quantity,
    pub remaining_quantity: Quantity,
    pub state: ManagedOrderState,
    pub new_transmitted: bool,
    pub cancel_transmitted: bool,
    pub risk_reservation_active: bool,
    pub acceptance_sequence: Option<Sequence>,
    pub last_venue_sequence: Sequence,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FillApplyOutcome {
    pub risk: FillOutcome,
    pub adverse: FillTrackOutcome,
    pub remaining_quantity: Quantity,
    /// A zero-leaves record is retained only while a prior new/cancel request
    /// still requires its protocol response to resolve the race.
    pub retained_for_protocol_resolution: bool,
}

/// A financially applied venue execution outside its authenticated order limit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutionPriceViolation {
    pub side: Side,
    pub limit_price: PriceTicks,
    pub fill_price: PriceTicks,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CancelApplyOutcome {
    /// `None` is possible only for a zero-quantity requested-cancel resolution
    /// after a full fill already released the reservation.
    pub risk: Option<CancelOutcome>,
    pub remaining_quantity: Quantity,
    pub terminal: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OrderError {
    InvalidCapacity,
    InvalidClientOrderId,
    InvalidVenueOrderId,
    InvalidTradeId,
    InvalidSequence(Sequence),
    InvalidQuantity(Quantity),
    InvalidPrice(PriceTicks),
    OrderCapacity {
        capacity: usize,
    },
    /// Exact execution-ID retention is exhausted. The engine must remain killed
    /// until authoritative venue reconciliation/recovery replaces local state.
    TradeHistoryCapacity {
        capacity: usize,
    },
    DuplicateClientOrder(ClientOrderId),
    DuplicateTrade(TradeId),
    UnknownClientOrder(ClientOrderId),
    UnknownVenueOrder(VenueOrderId),
    VenueOrderCollision(VenueOrderId),
    IdentityMismatch,
    EconomicsMismatch,
    SequenceRegression {
        prior: Sequence,
        received: Sequence,
    },
    LeavesMismatch {
        prior: Quantity,
        event_quantity: Quantity,
        leaves: Quantity,
    },
    InvalidTransition {
        state: ManagedOrderState,
        event: LifecycleEvent,
    },
    NotProvenUnsent(LifecycleEvent),
    Risk(RiskError),
    RiskAfterReconciled(RiskError),
    AdverseAfterReconciled(AdverseError),
    RiskAndAdverseAfterReconciled {
        risk: RiskError,
        adverse: AdverseError,
    },
    /// The execution is authoritative and was fully applied before this venue
    /// limit-price violation was reported. Optional component faults retain every
    /// downstream failure observed while reconciling the same fact.
    ExecutionPriceAfterReconciled {
        violation: ExecutionPriceViolation,
        risk: Option<RiskError>,
        adverse: Option<AdverseError>,
    },
    ReservationRollbackFailed(RiskError),
    InternalInvariant,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ManagedOrder {
    client_order_id: ClientOrderId,
    venue_order_id: Option<VenueOrderId>,
    risk_order_id: OrderId,
    instrument: InstrumentId,
    side: Side,
    limit_price: PriceTicks,
    original_quantity: Quantity,
    remaining_quantity: Quantity,
    state: ManagedOrderState,
    new_transmitted: bool,
    cancel_transmitted: bool,
    risk_reservation_active: bool,
    acceptance_sequence: Option<Sequence>,
    last_venue_sequence: Sequence,
}

impl ManagedOrder {
    const fn snapshot(self) -> ManagedOrderSnapshot {
        ManagedOrderSnapshot {
            client_order_id: self.client_order_id,
            venue_order_id: self.venue_order_id,
            risk_order_id: self.risk_order_id,
            instrument: self.instrument,
            side: self.side,
            limit_price: self.limit_price,
            original_quantity: self.original_quantity,
            remaining_quantity: self.remaining_quantity,
            state: self.state,
            new_transmitted: self.new_transmitted,
            cancel_transmitted: self.cancel_transmitted,
            risk_reservation_active: self.risk_reservation_active,
            acceptance_sequence: self.acceptance_sequence,
            last_venue_sequence: self.last_venue_sequence,
        }
    }
}

/// Single-writer, allocation-free managed-order state.
///
/// Despite the legacy `MAX_RECENT_TRADES` const-generic name, execution-ID history
/// is exact and non-evicting for this manager's lifetime. Exhausting that capacity
/// is a fail-closed quarantine boundary: authoritative venue reconciliation/recovery
/// must replace local state before execution processing can safely resume.
#[derive(Debug, Eq, PartialEq)]
pub struct OrderManager<const MAX_ORDERS: usize, const MAX_RECENT_TRADES: usize> {
    by_client: FixedIndexMap<ClientOrderId, ManagedOrder, MAX_ORDERS>,
    by_venue: FixedIndexMap<VenueOrderId, ClientOrderId, MAX_ORDERS>,
    // Execution IDs are never evicted or reused locally. Silently forgetting one
    // would let a later re-sequenced duplicate mutate inventory a second time.
    recent_trades: FixedIndexMap<TradeId, (), MAX_RECENT_TRADES>,
}

impl<const MAX_ORDERS: usize, const MAX_RECENT_TRADES: usize>
    OrderManager<MAX_ORDERS, MAX_RECENT_TRADES>
{
    /// Construct empty fixed-capacity order state.
    ///
    /// # Errors
    ///
    /// Returns [`OrderError::InvalidCapacity`] if either compile-time capacity is zero.
    pub const fn new() -> Result<Self, OrderError> {
        if MAX_ORDERS == 0 || MAX_RECENT_TRADES == 0 {
            return Err(OrderError::InvalidCapacity);
        }
        Ok(Self {
            by_client: FixedIndexMap::new(),
            by_venue: FixedIndexMap::new(),
            recent_trades: FixedIndexMap::new(),
        })
    }

    #[must_use]
    pub const fn order_count(&self) -> usize {
        self.by_client.len()
    }

    #[must_use]
    pub fn order(&self, client_order_id: ClientOrderId) -> Option<ManagedOrderSnapshot> {
        self.by_client
            .get(client_order_id)
            .copied()
            .map(ManagedOrder::snapshot)
    }

    #[must_use]
    pub fn order_by_venue(&self, venue_order_id: VenueOrderId) -> Option<ManagedOrderSnapshot> {
        self.by_venue
            .get(venue_order_id)
            .and_then(|client_order_id| self.by_client.get(*client_order_id))
            .copied()
            .map(ManagedOrder::snapshot)
    }

    #[must_use]
    pub fn has_recent_trade(&self, trade_id: TradeId) -> bool {
        self.recent_trades.get(trade_id).is_some()
    }

    /// Validate and reserve a new order before any bytes are handed to a transport.
    /// The instrument halt bit is sourced directly from `adverse`.
    ///
    /// # Errors
    ///
    /// Returns a lifecycle, capacity, or pre-trade risk failure. A successful call
    /// creates a rollback-eligible `PendingNew` record.
    pub fn prepare_new<
        const MAX_INSTRUMENTS: usize,
        const MAX_RISK_ORDERS: usize,
        const MAX_ADVERSE_INSTRUMENTS: usize,
        const MAX_FILLS: usize,
    >(
        &mut self,
        request: NewOrderRequest,
        risk: &mut RiskEngine<MAX_INSTRUMENTS, MAX_RISK_ORDERS>,
        adverse: &AdverseMonitor<MAX_ADVERSE_INSTRUMENTS, MAX_FILLS>,
        kill: &KillLatch,
    ) -> Result<RiskApproval, OrderError> {
        if request.client_order_id.0 == 0 {
            return Self::fault(kill, request.now, OrderError::InvalidClientOrderId);
        }
        if self.by_client.get(request.client_order_id).is_some() {
            return Self::fault(
                kill,
                request.now,
                OrderError::DuplicateClientOrder(request.client_order_id),
            );
        }
        if self.by_client.len() == MAX_ORDERS {
            return Self::fault(
                kill,
                request.now,
                OrderError::OrderCapacity {
                    capacity: MAX_ORDERS,
                },
            );
        }

        let approval = risk
            .authorize_order(
                PreTradeRequest {
                    order_id: request.risk_order_id,
                    instrument: request.instrument,
                    side: request.side,
                    price: request.limit_price,
                    quantity: request.quantity,
                    now: request.now,
                    clock_healthy: request.clock_healthy,
                    instrument_halted: adverse.is_halted(request.instrument),
                },
                kill,
            )
            .map_err(OrderError::Risk)?;

        let record = ManagedOrder {
            client_order_id: request.client_order_id,
            venue_order_id: None,
            risk_order_id: request.risk_order_id,
            instrument: request.instrument,
            side: request.side,
            limit_price: request.limit_price,
            original_quantity: request.quantity,
            remaining_quantity: request.quantity,
            state: ManagedOrderState::PendingNew,
            new_transmitted: false,
            cancel_transmitted: false,
            risk_reservation_active: true,
            acceptance_sequence: None,
            last_venue_sequence: Sequence(0),
        };

        if !Self::risk_matches(record, risk) {
            return match risk.on_cancel(request.risk_order_id, request.quantity, request.now, kill)
            {
                Ok(_) => Self::fault(kill, request.now, OrderError::InternalInvariant),
                Err(error) => {
                    kill.trigger(KillCode::InternalInvariant, request.now);
                    Err(OrderError::ReservationRollbackFailed(error))
                }
            };
        }

        match self.by_client.insert(request.client_order_id, record) {
            Ok(None) => Ok(approval),
            Ok(Some(_)) | Err(_) => {
                match risk.on_cancel(request.risk_order_id, request.quantity, request.now, kill) {
                    Ok(_) => Self::fault(kill, request.now, OrderError::InternalInvariant),
                    Err(error) => {
                        kill.trigger(KillCode::InternalInvariant, request.now);
                        Err(OrderError::ReservationRollbackFailed(error))
                    }
                }
            }
        }
    }

    /// Mark the new request as irrevocably handed to the transport.
    ///
    /// # Errors
    ///
    /// Unknown orders and repeated/out-of-state transitions latch an invariant kill.
    pub fn mark_new_transmitted(
        &mut self,
        client_order_id: ClientOrderId,
        now: TimestampNs,
        kill: &KillLatch,
    ) -> Result<(), OrderError> {
        let mut record = self.get_record(client_order_id, now, kill)?;
        if record.state != ManagedOrderState::PendingNew || record.new_transmitted {
            return Self::transition_fault(
                kill,
                now,
                record.state,
                LifecycleEvent::MarkNewTransmitted,
            );
        }
        record.new_transmitted = true;
        self.store_record(record, now, kill)
    }

    /// Release a reservation only when the transport has provably sent no bytes.
    ///
    /// # Errors
    ///
    /// Returns [`OrderError::NotProvenUnsent`] once transmission was marked, or a
    /// risk/invariant error if reservation release cannot be proved exact.
    pub fn rollback_unsent_new<const MAX_INSTRUMENTS: usize, const MAX_RISK_ORDERS: usize>(
        &mut self,
        client_order_id: ClientOrderId,
        now: TimestampNs,
        risk: &mut RiskEngine<MAX_INSTRUMENTS, MAX_RISK_ORDERS>,
        kill: &KillLatch,
    ) -> Result<CancelOutcome, OrderError> {
        let record = self.get_record(client_order_id, now, kill)?;
        if record.state != ManagedOrderState::PendingNew {
            return Self::transition_fault(kill, now, record.state, LifecycleEvent::RollbackNew);
        }
        if record.new_transmitted {
            return Err(OrderError::NotProvenUnsent(LifecycleEvent::RollbackNew));
        }
        if !record.risk_reservation_active || record.remaining_quantity != record.original_quantity
        {
            return Self::fault(kill, now, OrderError::InternalInvariant);
        }
        let outcome = risk
            .on_cancel(record.risk_order_id, record.remaining_quantity, now, kill)
            .map_err(OrderError::Risk)?;
        if outcome.remaining_order_quantity != Quantity::ZERO {
            return Self::fault(kill, now, OrderError::InternalInvariant);
        }
        self.remove_record(record, now, kill)?;
        Ok(outcome)
    }

    /// Apply a venue new-order acceptance, including an acceptance after partial
    /// or full execution while the order was still `PendingNew`.
    ///
    /// # Errors
    ///
    /// Any identity, economics, sequence, state, or risk-reservation mismatch
    /// latches [`KillCode::InternalInvariant`].
    pub fn on_new_accepted<const MAX_INSTRUMENTS: usize, const MAX_RISK_ORDERS: usize>(
        &mut self,
        event: NewAccepted,
        risk: &RiskEngine<MAX_INSTRUMENTS, MAX_RISK_ORDERS>,
        kill: &KillLatch,
    ) -> Result<Option<ManagedOrderSnapshot>, OrderError> {
        let mut record = self.get_record(
            event.order.economics.client_order_id,
            event.received_at,
            kill,
        )?;
        if record.state != ManagedOrderState::PendingNew || !record.new_transmitted {
            return Self::transition_fault(
                kill,
                event.received_at,
                record.state,
                LifecycleEvent::NewAccepted,
            );
        }
        Self::validate_economics(record, event.order.economics, event.received_at, kill)?;
        Self::validate_sequence(record, event.sequence, event.received_at, kill)?;
        if event.leaves_quantity != record.remaining_quantity {
            return Self::fault(kill, event.received_at, OrderError::EconomicsMismatch);
        }
        if !Self::risk_matches(record, risk) {
            return Self::fault(kill, event.received_at, OrderError::InternalInvariant);
        }
        self.bind_venue(
            &mut record,
            event.order.venue_order_id,
            event.received_at,
            kill,
        )?;
        record.acceptance_sequence = Some(event.sequence);
        record.last_venue_sequence = event.sequence;
        if record.remaining_quantity == Quantity::ZERO {
            self.remove_record(record, event.received_at, kill)?;
            return Ok(None);
        }
        record.state = ManagedOrderState::Live;
        self.store_record(record, event.received_at, kill)?;
        Ok(Some(record.snapshot()))
    }

    /// Apply a total new-order rejection and release its reservation exactly once.
    ///
    /// # Errors
    ///
    /// A rejection after any execution/binding or an economics/sequence mismatch
    /// is an invariant fault; risk release errors are propagated.
    pub fn on_new_rejected<const MAX_INSTRUMENTS: usize, const MAX_RISK_ORDERS: usize>(
        &mut self,
        event: NewRejected,
        risk: &mut RiskEngine<MAX_INSTRUMENTS, MAX_RISK_ORDERS>,
        kill: &KillLatch,
    ) -> Result<CancelOutcome, OrderError> {
        let record = self.get_record(event.order.client_order_id, event.received_at, kill)?;
        if record.state != ManagedOrderState::PendingNew || !record.new_transmitted {
            return Self::transition_fault(
                kill,
                event.received_at,
                record.state,
                LifecycleEvent::NewRejected,
            );
        }
        Self::validate_economics(record, event.order, event.received_at, kill)?;
        Self::validate_sequence(record, event.sequence, event.received_at, kill)?;
        if record.venue_order_id.is_some()
            || record.remaining_quantity != record.original_quantity
            || event.leaves_quantity != record.remaining_quantity
            || !record.risk_reservation_active
        {
            return Self::fault(kill, event.received_at, OrderError::EconomicsMismatch);
        }
        let outcome = risk
            .on_cancel(
                record.risk_order_id,
                record.remaining_quantity,
                event.received_at,
                kill,
            )
            .map_err(OrderError::Risk)?;
        if outcome.remaining_order_quantity != Quantity::ZERO {
            return Self::fault(kill, event.received_at, OrderError::InternalInvariant);
        }
        self.remove_record(record, event.received_at, kill)?;
        Ok(outcome)
    }

    /// Enter `PendingCancel` without changing risk reservation.
    ///
    /// # Errors
    ///
    /// Only a positive-leaves, venue-bound `Live` order may enter this state.
    pub fn prepare_cancel(
        &mut self,
        client_order_id: ClientOrderId,
        now: TimestampNs,
        kill: &KillLatch,
    ) -> Result<ManagedOrderSnapshot, OrderError> {
        let mut record = self.get_record(client_order_id, now, kill)?;
        if record.state != ManagedOrderState::Live {
            return Self::transition_fault(kill, now, record.state, LifecycleEvent::PrepareCancel);
        }
        if record.venue_order_id.is_none()
            || !record.remaining_quantity.is_positive()
            || !record.risk_reservation_active
        {
            return Self::fault(kill, now, OrderError::InternalInvariant);
        }
        record.state = ManagedOrderState::PendingCancel;
        record.cancel_transmitted = false;
        self.store_record(record, now, kill)?;
        Ok(record.snapshot())
    }

    /// Mark a prepared cancel as irrevocably handed to the transport.
    ///
    /// # Errors
    ///
    /// Unknown, repeated, or out-of-state transitions latch an invariant kill.
    pub fn mark_cancel_transmitted(
        &mut self,
        client_order_id: ClientOrderId,
        now: TimestampNs,
        kill: &KillLatch,
    ) -> Result<(), OrderError> {
        let mut record = self.get_record(client_order_id, now, kill)?;
        if record.state != ManagedOrderState::PendingCancel || record.cancel_transmitted {
            return Self::transition_fault(
                kill,
                now,
                record.state,
                LifecycleEvent::MarkCancelTransmitted,
            );
        }
        record.cancel_transmitted = true;
        self.store_record(record, now, kill)
    }

    /// Return an unsent cancel to `Live`; no risk state changes because the original
    /// order reservation remains active throughout cancel transmission.
    ///
    /// # Errors
    ///
    /// Returns [`OrderError::NotProvenUnsent`] after transmission was marked.
    pub fn rollback_unsent_cancel(
        &mut self,
        client_order_id: ClientOrderId,
        now: TimestampNs,
        kill: &KillLatch,
    ) -> Result<ManagedOrderSnapshot, OrderError> {
        let mut record = self.get_record(client_order_id, now, kill)?;
        if record.state != ManagedOrderState::PendingCancel {
            return Self::transition_fault(kill, now, record.state, LifecycleEvent::RollbackCancel);
        }
        if record.cancel_transmitted {
            return Err(OrderError::NotProvenUnsent(LifecycleEvent::RollbackCancel));
        }
        record.state = ManagedOrderState::Live;
        self.store_record(record, now, kill)?;
        Ok(record.snapshot())
    }

    /// Apply a requested or unsolicited cancel fact. Risk release occurs even while
    /// globally killed. A zero canceled quantity is accepted only to resolve a
    /// requested-cancel/full-fill race whose reservation is already gone.
    ///
    /// # Errors
    ///
    /// Identity, sequence, leaves algebra, state, and reservation mismatches fail closed.
    #[allow(clippy::too_many_lines)]
    pub fn on_cancel_confirmed<const MAX_INSTRUMENTS: usize, const MAX_RISK_ORDERS: usize>(
        &mut self,
        event: CancelConfirmed,
        risk: &mut RiskEngine<MAX_INSTRUMENTS, MAX_RISK_ORDERS>,
        kill: &KillLatch,
    ) -> Result<CancelApplyOutcome, OrderError> {
        let mut record = self.get_record(
            event.order.economics.client_order_id,
            event.received_at,
            kill,
        )?;
        Self::validate_economics(record, event.order.economics, event.received_at, kill)?;
        Self::validate_sequence(record, event.sequence, event.received_at, kill)?;
        Self::validate_cancel_state(record, event.reason, event.received_at, kill)?;
        self.validate_or_bind_venue(
            &mut record,
            event.order.venue_order_id,
            event.received_at,
            kill,
        )?;
        if event.canceled_quantity == Quantity::ZERO {
            if record.remaining_quantity != Quantity::ZERO
                || event.leaves_quantity != Quantity::ZERO
            {
                return Self::fault(
                    kill,
                    event.received_at,
                    OrderError::LeavesMismatch {
                        prior: record.remaining_quantity,
                        event_quantity: event.canceled_quantity,
                        leaves: event.leaves_quantity,
                    },
                );
            }
        } else {
            Self::validate_leaves(
                record.remaining_quantity,
                event.canceled_quantity,
                event.leaves_quantity,
                event.received_at,
                kill,
            )?;
        }

        let risk_outcome = if event.canceled_quantity == Quantity::ZERO {
            if record.remaining_quantity != Quantity::ZERO
                || record.risk_reservation_active
                || event.reason != CancelReason::Requested
            {
                return Self::fault(
                    kill,
                    event.received_at,
                    OrderError::InvalidQuantity(event.canceled_quantity),
                );
            }
            None
        } else {
            if !record.risk_reservation_active || !Self::risk_matches(record, risk) {
                return Self::fault(kill, event.received_at, OrderError::InternalInvariant);
            }
            match risk.on_cancel(
                record.risk_order_id,
                event.canceled_quantity,
                event.received_at,
                kill,
            ) {
                Ok(outcome) => {
                    if outcome.remaining_order_quantity != event.leaves_quantity {
                        kill.trigger(KillCode::InternalInvariant, event.received_at);
                        if self
                            .commit_cancel_lifecycle(
                                record,
                                outcome.remaining_order_quantity,
                                event.sequence,
                                event.received_at,
                                kill,
                            )
                            .is_err()
                        {
                            return Err(OrderError::RiskAfterReconciled(
                                RiskError::InternalInvariant,
                            ));
                        }
                        return Err(OrderError::RiskAfterReconciled(
                            RiskError::InternalInvariant,
                        ));
                    }
                    Some(outcome)
                }
                Err(error) => {
                    if Self::risk_matches_expected(record, event.leaves_quantity, risk) {
                        if self
                            .commit_cancel_lifecycle(
                                record,
                                event.leaves_quantity,
                                event.sequence,
                                event.received_at,
                                kill,
                            )
                            .is_err()
                        {
                            return Err(OrderError::RiskAfterReconciled(
                                RiskError::InternalInvariant,
                            ));
                        }
                        return Err(OrderError::RiskAfterReconciled(error));
                    }
                    return Err(OrderError::Risk(error));
                }
            }
        };

        let terminal = match self.commit_cancel_lifecycle(
            record,
            event.leaves_quantity,
            event.sequence,
            event.received_at,
            kill,
        ) {
            Ok(terminal) => terminal,
            Err(_) if risk_outcome.is_some() => {
                return Err(OrderError::RiskAfterReconciled(
                    RiskError::InternalInvariant,
                ));
            }
            Err(error) => return Err(error),
        };
        Ok(CancelApplyOutcome {
            risk: risk_outcome,
            remaining_quantity: event.leaves_quantity,
            terminal,
        })
    }

    /// Apply a cancel rejection. A rejection received after a full fill resolves the
    /// retained `PendingCancel` record without touching the already-released risk order.
    ///
    /// # Errors
    ///
    /// Only a transmitted `PendingCancel` with exact identity, sequence, and leaves is valid.
    pub fn on_cancel_rejected<const MAX_INSTRUMENTS: usize, const MAX_RISK_ORDERS: usize>(
        &mut self,
        event: CancelRejected,
        risk: &RiskEngine<MAX_INSTRUMENTS, MAX_RISK_ORDERS>,
        kill: &KillLatch,
    ) -> Result<Option<ManagedOrderSnapshot>, OrderError> {
        let mut record = self.get_record(
            event.order.economics.client_order_id,
            event.received_at,
            kill,
        )?;
        if record.state != ManagedOrderState::PendingCancel || !record.cancel_transmitted {
            return Self::transition_fault(
                kill,
                event.received_at,
                record.state,
                LifecycleEvent::CancelRejected,
            );
        }
        Self::validate_economics(record, event.order.economics, event.received_at, kill)?;
        Self::validate_sequence(record, event.sequence, event.received_at, kill)?;
        self.validate_bound_venue(record, event.order.venue_order_id, event.received_at, kill)?;
        if event.leaves_quantity != record.remaining_quantity || !Self::risk_matches(record, risk) {
            return Self::fault(kill, event.received_at, OrderError::EconomicsMismatch);
        }
        record.last_venue_sequence = event.sequence;
        if record.remaining_quantity == Quantity::ZERO {
            self.remove_record(record, event.received_at, kill)?;
            return Ok(None);
        }
        record.state = ManagedOrderState::Live;
        record.cancel_transmitted = false;
        self.store_record(record, event.received_at, kill)?;
        Ok(Some(record.snapshot()))
    }

    /// Apply a partial or full fill in any protocol state. The local authenticated
    /// side/instrument drive both risk and adverse controls; venue copies are only
    /// equality-checked. Fills remain applicable while the global kill is latched.
    ///
    /// # Errors
    ///
    /// Invalid/duplicate reports fail before inventory mutation. Exact execution-ID
    /// history is non-evicting; capacity exhaustion also fails before a first-fill
    /// venue binding or accounting mutation and requires authoritative reconciliation/
    /// recovery. Errors carrying `AfterReconciled` mean the inventory fact, local
    /// leaves, sequence, and trade ID were committed before the downstream fault was
    /// observed.
    #[allow(clippy::too_many_lines)]
    pub fn on_fill<
        const MAX_INSTRUMENTS: usize,
        const MAX_RISK_ORDERS: usize,
        const MAX_ADVERSE_INSTRUMENTS: usize,
        const MAX_FILLS: usize,
    >(
        &mut self,
        event: FillReport,
        risk: &mut RiskEngine<MAX_INSTRUMENTS, MAX_RISK_ORDERS>,
        adverse: &mut AdverseMonitor<MAX_ADVERSE_INSTRUMENTS, MAX_FILLS>,
        kill: &KillLatch,
    ) -> Result<FillApplyOutcome, OrderError> {
        let mut record = self.get_record(
            event.order.economics.client_order_id,
            event.received_at,
            kill,
        )?;
        if record.state == ManagedOrderState::PendingNew && !record.new_transmitted {
            return Self::transition_fault(
                kill,
                event.received_at,
                record.state,
                LifecycleEvent::Fill,
            );
        }
        Self::validate_economics(record, event.order.economics, event.received_at, kill)?;
        Self::validate_sequence(record, event.sequence, event.received_at, kill)?;
        if event.trade_id.0 == 0 {
            return Self::fault(kill, event.received_at, OrderError::InvalidTradeId);
        }
        if !event.fill_price.is_positive() {
            return Self::fault(
                kill,
                event.received_at,
                OrderError::InvalidPrice(event.fill_price),
            );
        }
        Self::validate_leaves(
            record.remaining_quantity,
            event.fill_quantity,
            event.leaves_quantity,
            event.received_at,
            kill,
        )?;
        if !record.risk_reservation_active || !Self::risk_matches(record, risk) {
            return Self::fault(kill, event.received_at, OrderError::InternalInvariant);
        }
        // Capacity/duplicate preflight must precede a first-fill venue binding:
        // otherwise a rejected fill could leave a reverse-index mutation behind.
        self.preflight_trade(event.trade_id, event.received_at, kill)?;
        let bind_venue =
            self.preflight_fill_venue(record, event.order.venue_order_id, event.received_at, kill)?;
        let execution_price_violation = match record.side {
            Side::Buy if event.fill_price.0 > record.limit_price.0 => {
                Some(ExecutionPriceViolation {
                    side: record.side,
                    limit_price: record.limit_price,
                    fill_price: event.fill_price,
                })
            }
            Side::Sell if event.fill_price.0 < record.limit_price.0 => {
                Some(ExecutionPriceViolation {
                    side: record.side,
                    limit_price: record.limit_price,
                    fill_price: event.fill_price,
                })
            }
            Side::Buy | Side::Sell => None,
        };
        let original_record = record;
        self.remember_trade(event.trade_id, event.received_at, kill)?;
        if bind_venue {
            let original = record;
            if let Err(error) = self.bind_venue(
                &mut record,
                event.order.venue_order_id,
                event.received_at,
                kill,
            ) {
                self.rollback_remembered_trade(event.trade_id, event.received_at, kill)?;
                return Err(error);
            }
            if let Err(error) = self.store_record(record, event.received_at, kill) {
                let reverse_restored = self.by_venue.remove(event.order.venue_order_id)
                    == Some(record.client_order_id);
                let client_restored = matches!(
                    self.by_client.insert(original.client_order_id, original),
                    Ok(Some(_))
                );
                let trade_restored = self.recent_trades.remove(event.trade_id) == Some(());
                if !reverse_restored || !client_restored || !trade_restored {
                    return Self::fault(kill, event.received_at, OrderError::InternalInvariant);
                }
                return Err(error);
            }
        }

        let risk_result = risk.on_fill(
            record.risk_order_id,
            event.fill_price,
            event.fill_quantity,
            event.received_at,
            kill,
        );
        let mut risk_fault = None;
        let risk_outcome = match risk_result {
            Ok(outcome) => {
                if outcome.remaining_order_quantity != event.leaves_quantity {
                    kill.trigger(KillCode::InternalInvariant, event.received_at);
                    risk_fault = Some(RiskError::InternalInvariant);
                }
                Some(outcome)
            }
            Err(error) => {
                if Self::risk_matches_expected(record, event.leaves_quantity, risk) {
                    risk_fault = Some(error);
                    None
                } else {
                    // `RiskEngine::on_fill` is atomic on every returned error. The
                    // execution ID and optional first-fill venue binding were staged
                    // only to make the later accounting commit non-fallible; restore
                    // both before returning a non-reconciled risk rejection so an
                    // authoritative retry is not misclassified as a duplicate.
                    self.rollback_unreconciled_fill_identity(
                        original_record,
                        record,
                        event.trade_id,
                        bind_venue,
                        event.received_at,
                        kill,
                    )?;
                    return Err(OrderError::Risk(error));
                }
            }
        };

        record.remaining_quantity = event.leaves_quantity;
        record.risk_reservation_active = event.leaves_quantity.is_positive();
        record.last_venue_sequence = event.sequence;
        let retained = event.leaves_quantity == Quantity::ZERO
            && matches!(
                record.state,
                ManagedOrderState::PendingNew | ManagedOrderState::PendingCancel
            );
        if event.leaves_quantity == Quantity::ZERO && !retained {
            self.remove_record(record, event.received_at, kill)?;
        } else {
            self.store_record(record, event.received_at, kill)?;
        }

        let adverse_result = adverse.on_fill(
            AdverseFill {
                execution_id: event.trade_id.0,
                instrument: record.instrument,
                side: record.side,
                fill_price: event.fill_price,
                quantity: event.fill_quantity,
                fill_timestamp: event.fill_timestamp,
            },
            event.received_at,
            kill,
        );

        if let Some(violation) = execution_price_violation {
            kill.trigger(KillCode::InternalInvariant, event.received_at);
            return Err(OrderError::ExecutionPriceAfterReconciled {
                violation,
                risk: risk_fault,
                adverse: adverse_result.err(),
            });
        }

        match (risk_fault, adverse_result, risk_outcome) {
            (None, Ok(adverse_outcome), Some(risk_outcome)) => Ok(FillApplyOutcome {
                risk: risk_outcome,
                adverse: adverse_outcome,
                remaining_quantity: event.leaves_quantity,
                retained_for_protocol_resolution: retained,
            }),
            (Some(risk_error), Ok(_), _) => Err(OrderError::RiskAfterReconciled(risk_error)),
            (None, Err(adverse_error), _) => Err(OrderError::AdverseAfterReconciled(adverse_error)),
            (Some(risk_error), Err(adverse_error), _) => {
                Err(OrderError::RiskAndAdverseAfterReconciled {
                    risk: risk_error,
                    adverse: adverse_error,
                })
            }
            (None, Ok(_), None) => {
                kill.trigger(KillCode::InternalInvariant, event.received_at);
                Err(OrderError::RiskAfterReconciled(
                    RiskError::InternalInvariant,
                ))
            }
        }
    }

    fn get_record(
        &self,
        client_order_id: ClientOrderId,
        now: TimestampNs,
        kill: &KillLatch,
    ) -> Result<ManagedOrder, OrderError> {
        self.by_client.get(client_order_id).copied().ok_or_else(|| {
            kill.trigger(KillCode::InternalInvariant, now);
            OrderError::UnknownClientOrder(client_order_id)
        })
    }

    fn store_record(
        &mut self,
        record: ManagedOrder,
        now: TimestampNs,
        kill: &KillLatch,
    ) -> Result<(), OrderError> {
        match self.by_client.insert(record.client_order_id, record) {
            Ok(Some(_)) => Ok(()),
            Ok(None) | Err(_) => Self::fault(kill, now, OrderError::InternalInvariant),
        }
    }

    fn commit_cancel_lifecycle(
        &mut self,
        record: ManagedOrder,
        remaining_quantity: Quantity,
        sequence: Sequence,
        now: TimestampNs,
        kill: &KillLatch,
    ) -> Result<bool, OrderError> {
        let (record, terminal) =
            Self::reconciled_cancel_record(record, remaining_quantity, sequence);
        if terminal {
            self.remove_record(record, now, kill)?;
        } else {
            self.store_record(record, now, kill)?;
        }
        Ok(terminal)
    }

    fn reconciled_cancel_record(
        mut record: ManagedOrder,
        remaining_quantity: Quantity,
        sequence: Sequence,
    ) -> (ManagedOrder, bool) {
        record.remaining_quantity = remaining_quantity;
        record.risk_reservation_active = remaining_quantity.is_positive();
        record.last_venue_sequence = sequence;
        let terminal = remaining_quantity == Quantity::ZERO;
        if !terminal {
            record.state = ManagedOrderState::Live;
            record.cancel_transmitted = false;
        }
        (record, terminal)
    }

    fn remove_record(
        &mut self,
        record: ManagedOrder,
        now: TimestampNs,
        kill: &KillLatch,
    ) -> Result<(), OrderError> {
        let Some(removed) = self.by_client.remove(record.client_order_id) else {
            return Self::fault(kill, now, OrderError::InternalInvariant);
        };
        // The caller may have already reconciled leaves, sequence, and protocol
        // state in its local copy. Immutable authenticated identity/economics must
        // still match the indexed record being retired.
        if removed.client_order_id != record.client_order_id
            || removed.venue_order_id != record.venue_order_id
            || removed.risk_order_id != record.risk_order_id
            || removed.instrument != record.instrument
            || removed.side != record.side
            || removed.limit_price != record.limit_price
            || removed.original_quantity != record.original_quantity
        {
            return Self::fault(kill, now, OrderError::InternalInvariant);
        }
        if let Some(venue_order_id) = record.venue_order_id
            && self.by_venue.remove(venue_order_id) != Some(record.client_order_id)
        {
            return Self::fault(kill, now, OrderError::InternalInvariant);
        }
        Ok(())
    }

    fn bind_venue(
        &mut self,
        record: &mut ManagedOrder,
        venue_order_id: VenueOrderId,
        now: TimestampNs,
        kill: &KillLatch,
    ) -> Result<(), OrderError> {
        if venue_order_id.0 == 0 {
            return Self::fault(kill, now, OrderError::InvalidVenueOrderId);
        }
        if let Some(bound) = record.venue_order_id {
            if bound != venue_order_id {
                return Self::fault(kill, now, OrderError::IdentityMismatch);
            }
            return self.validate_bound_venue(*record, venue_order_id, now, kill);
        }
        if let Some(existing) = self.by_venue.get(venue_order_id) {
            if *existing != record.client_order_id {
                return Self::fault(kill, now, OrderError::VenueOrderCollision(venue_order_id));
            }
            return Self::fault(kill, now, OrderError::InternalInvariant);
        }
        match self.by_venue.insert(venue_order_id, record.client_order_id) {
            Ok(None) => {
                record.venue_order_id = Some(venue_order_id);
                Ok(())
            }
            Ok(Some(_)) | Err(_) => Self::fault(kill, now, OrderError::InternalInvariant),
        }
    }

    fn validate_or_bind_venue(
        &mut self,
        record: &mut ManagedOrder,
        venue_order_id: VenueOrderId,
        now: TimestampNs,
        kill: &KillLatch,
    ) -> Result<(), OrderError> {
        if record.venue_order_id.is_some() {
            self.validate_bound_venue(*record, venue_order_id, now, kill)
        } else if record.state == ManagedOrderState::PendingNew {
            self.bind_venue(record, venue_order_id, now, kill)?;
            // Persist the newly authenticated venue identity immediately so a
            // later duplicate/risk fault cannot leave the reverse index orphaned.
            self.store_record(*record, now, kill)
        } else {
            Self::fault(kill, now, OrderError::UnknownVenueOrder(venue_order_id))
        }
    }

    /// Validate an existing venue binding or plan a first-fill binding without
    /// mutating either index. `true` means the caller must commit the new binding.
    fn preflight_fill_venue(
        &self,
        record: ManagedOrder,
        venue_order_id: VenueOrderId,
        now: TimestampNs,
        kill: &KillLatch,
    ) -> Result<bool, OrderError> {
        if record.venue_order_id.is_some() {
            self.validate_bound_venue(record, venue_order_id, now, kill)?;
            return Ok(false);
        }
        if record.state != ManagedOrderState::PendingNew {
            return Self::fault(kill, now, OrderError::UnknownVenueOrder(venue_order_id));
        }
        if venue_order_id.0 == 0 {
            return Self::fault(kill, now, OrderError::InvalidVenueOrderId);
        }
        if let Some(existing) = self.by_venue.get(venue_order_id) {
            if *existing != record.client_order_id {
                return Self::fault(kill, now, OrderError::VenueOrderCollision(venue_order_id));
            }
            return Self::fault(kill, now, OrderError::InternalInvariant);
        }
        if self.by_venue.len() == MAX_ORDERS {
            return Self::fault(kill, now, OrderError::InternalInvariant);
        }
        Ok(true)
    }

    fn validate_bound_venue(
        &self,
        record: ManagedOrder,
        venue_order_id: VenueOrderId,
        now: TimestampNs,
        kill: &KillLatch,
    ) -> Result<(), OrderError> {
        if venue_order_id.0 == 0 {
            return Self::fault(kill, now, OrderError::InvalidVenueOrderId);
        }
        if record.venue_order_id != Some(venue_order_id)
            || self.by_venue.get(venue_order_id) != Some(&record.client_order_id)
        {
            return Self::fault(kill, now, OrderError::IdentityMismatch);
        }
        Ok(())
    }

    fn validate_economics(
        record: ManagedOrder,
        economics: OrderEconomics,
        now: TimestampNs,
        kill: &KillLatch,
    ) -> Result<(), OrderError> {
        if economics.client_order_id != record.client_order_id {
            return Self::fault(kill, now, OrderError::IdentityMismatch);
        }
        if economics.instrument != record.instrument
            || economics.side != record.side
            || economics.limit_price != record.limit_price
            || economics.original_quantity != record.original_quantity
        {
            return Self::fault(kill, now, OrderError::EconomicsMismatch);
        }
        Ok(())
    }

    fn validate_sequence(
        record: ManagedOrder,
        sequence: Sequence,
        now: TimestampNs,
        kill: &KillLatch,
    ) -> Result<(), OrderError> {
        if sequence.0 == 0 {
            return Self::fault(kill, now, OrderError::InvalidSequence(sequence));
        }
        if sequence <= record.last_venue_sequence {
            return Self::fault(
                kill,
                now,
                OrderError::SequenceRegression {
                    prior: record.last_venue_sequence,
                    received: sequence,
                },
            );
        }
        Ok(())
    }

    fn validate_leaves(
        prior: Quantity,
        event_quantity: Quantity,
        leaves: Quantity,
        now: TimestampNs,
        kill: &KillLatch,
    ) -> Result<(), OrderError> {
        if !event_quantity.is_positive() || leaves.0 < 0 {
            return Self::fault(kill, now, OrderError::InvalidQuantity(event_quantity));
        }
        if event_quantity.0.checked_add(leaves.0) != Some(prior.0) {
            return Self::fault(
                kill,
                now,
                OrderError::LeavesMismatch {
                    prior,
                    event_quantity,
                    leaves,
                },
            );
        }
        Ok(())
    }

    fn validate_cancel_state(
        record: ManagedOrder,
        reason: CancelReason,
        now: TimestampNs,
        kill: &KillLatch,
    ) -> Result<(), OrderError> {
        let valid = match reason {
            CancelReason::Requested => {
                record.state == ManagedOrderState::PendingCancel && record.cancel_transmitted
            }
            CancelReason::Unsolicited => match record.state {
                ManagedOrderState::PendingNew => record.new_transmitted,
                ManagedOrderState::Live | ManagedOrderState::PendingCancel => true,
            },
        };
        if valid {
            Ok(())
        } else {
            Self::transition_fault(kill, now, record.state, LifecycleEvent::CancelConfirmed)
        }
    }

    fn risk_matches<const MAX_INSTRUMENTS: usize, const MAX_RISK_ORDERS: usize>(
        record: ManagedOrder,
        risk: &RiskEngine<MAX_INSTRUMENTS, MAX_RISK_ORDERS>,
    ) -> bool {
        Self::risk_matches_expected(record, record.remaining_quantity, risk)
    }

    fn risk_matches_expected<const MAX_INSTRUMENTS: usize, const MAX_RISK_ORDERS: usize>(
        record: ManagedOrder,
        expected_remaining: Quantity,
        risk: &RiskEngine<MAX_INSTRUMENTS, MAX_RISK_ORDERS>,
    ) -> bool {
        match risk.order(record.risk_order_id) {
            Some(order) => {
                expected_remaining.is_positive()
                    && order.instrument == record.instrument
                    && order.side == record.side
                    && order.limit_price == record.limit_price
                    && order.remaining_quantity == expected_remaining
            }
            None => expected_remaining == Quantity::ZERO,
        }
    }

    fn preflight_trade(
        &self,
        trade_id: TradeId,
        now: TimestampNs,
        kill: &KillLatch,
    ) -> Result<(), OrderError> {
        if self.recent_trades.get(trade_id).is_some() {
            return Self::fault(kill, now, OrderError::DuplicateTrade(trade_id));
        }
        if self.recent_trades.len() == MAX_RECENT_TRADES {
            return Self::fault(
                kill,
                now,
                OrderError::TradeHistoryCapacity {
                    capacity: MAX_RECENT_TRADES,
                },
            );
        }
        Ok(())
    }

    fn remember_trade(
        &mut self,
        trade_id: TradeId,
        now: TimestampNs,
        kill: &KillLatch,
    ) -> Result<(), OrderError> {
        self.preflight_trade(trade_id, now, kill)?;
        match self.recent_trades.insert(trade_id, ()) {
            Ok(None) => {}
            Ok(Some(())) | Err(_) => {
                return Self::fault(kill, now, OrderError::InternalInvariant);
            }
        }
        Ok(())
    }

    fn rollback_remembered_trade(
        &mut self,
        trade_id: TradeId,
        now: TimestampNs,
        kill: &KillLatch,
    ) -> Result<(), OrderError> {
        if self.recent_trades.remove(trade_id) != Some(()) {
            return Self::fault(kill, now, OrderError::InternalInvariant);
        }
        Ok(())
    }

    fn rollback_unreconciled_fill_identity(
        &mut self,
        original_record: ManagedOrder,
        staged_record: ManagedOrder,
        trade_id: TradeId,
        staged_venue_binding: bool,
        now: TimestampNs,
        kill: &KillLatch,
    ) -> Result<(), OrderError> {
        let trade_restored = self.recent_trades.remove(trade_id) == Some(());
        let venue_restored = if staged_venue_binding {
            let Some(venue_order_id) = staged_record.venue_order_id else {
                return Self::fault(kill, now, OrderError::InternalInvariant);
            };
            let reverse_restored =
                self.by_venue.remove(venue_order_id) == Some(staged_record.client_order_id);
            let client_restored = matches!(
                self.by_client
                    .insert(original_record.client_order_id, original_record),
                Ok(Some(replaced)) if replaced == staged_record
            );
            reverse_restored && client_restored
        } else {
            original_record == staged_record
        };
        if !trade_restored || !venue_restored {
            return Self::fault(kill, now, OrderError::InternalInvariant);
        }
        Ok(())
    }

    fn transition_fault<T>(
        kill: &KillLatch,
        now: TimestampNs,
        state: ManagedOrderState,
        event: LifecycleEvent,
    ) -> Result<T, OrderError> {
        Self::fault(kill, now, OrderError::InvalidTransition { state, event })
    }

    fn fault<T>(kill: &KillLatch, now: TimestampNs, error: OrderError) -> Result<T, OrderError> {
        kill.trigger(KillCode::InternalInvariant, now);
        Err(error)
    }
}

#[cfg(test)]
mod tests {
    use super::{ManagedOrder, ManagedOrderState, OrderManager};
    use crate::types::{InstrumentId, OrderId, PriceTicks, Quantity, Sequence, Side};
    use crate::venue::{ClientOrderId, VenueOrderId};

    fn pending_cancel() -> ManagedOrder {
        ManagedOrder {
            client_order_id: ClientOrderId(11),
            venue_order_id: Some(VenueOrderId(22)),
            risk_order_id: OrderId(33),
            instrument: InstrumentId(44),
            side: Side::Buy,
            limit_price: PriceTicks(55),
            original_quantity: Quantity(10),
            remaining_quantity: Quantity(10),
            state: ManagedOrderState::PendingCancel,
            new_transmitted: true,
            cancel_transmitted: true,
            risk_reservation_active: true,
            acceptance_sequence: Some(Sequence(7)),
            last_venue_sequence: Sequence(8),
        }
    }

    #[test]
    fn reconciled_cancel_record_uses_risk_committed_leaves_and_sequence() {
        let (partial, terminal) = OrderManager::<1, 1>::reconciled_cancel_record(
            pending_cancel(),
            Quantity(4),
            Sequence(9),
        );
        assert!(!terminal);
        assert_eq!(partial.remaining_quantity, Quantity(4));
        assert!(partial.risk_reservation_active);
        assert_eq!(partial.last_venue_sequence, Sequence(9));
        assert_eq!(partial.state, ManagedOrderState::Live);
        assert!(!partial.cancel_transmitted);

        let (full, terminal) = OrderManager::<1, 1>::reconciled_cancel_record(
            pending_cancel(),
            Quantity::ZERO,
            Sequence(10),
        );
        assert!(terminal);
        assert_eq!(full.remaining_quantity, Quantity::ZERO);
        assert!(!full.risk_reservation_active);
        assert_eq!(full.last_venue_sequence, Sequence(10));
    }
}
