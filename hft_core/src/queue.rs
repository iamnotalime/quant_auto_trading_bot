//! Deterministic passive queue-position models.

use crate::book::{ApplyOutcome, BookOrder, L3Book};
use crate::fixed::{CapacityError, FixedIndexMap};
use crate::types::{OrderId, PriceTicks, Quantity, Side};

/// Named queue-advancement policy used by governed simulations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueuePolicy {
    /// Join behind all displayed depth. Trades consume depth ahead first; anonymous
    /// cancels are assumed to occur behind us and therefore never improve position.
    Conservative,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueueStatus {
    Active,
    Filled,
    Canceled,
    Invalidated,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueueAction {
    TradeAtPrice,
    UnrelatedTrade,
    CancelAssumedBehind,
    UnrelatedCancel,
    AheadOrderJoined,
    AheadOrderExecuted,
    AheadOrderCanceled,
    AheadOrderReplacedLostPriority,
    OwnOrderBecameVisible,
    OwnOrderExecuted,
    OwnOrderReplacedLostPriority,
    BehindOrderEvent,
    BookCleared,
    ReplacedLostPriority,
    OwnOrderCanceled,
    Invalidated,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueueUpdate {
    pub action: QueueAction,
    pub queue_ahead_before: Quantity,
    pub queue_ahead_after: Quantity,
    pub filled_quantity: Quantity,
    pub remaining_quantity: Quantity,
    pub status: QueueStatus,
    pub generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueueError {
    InvalidOrderId,
    InvalidPrice(PriceTicks),
    InvalidQuantity(Quantity),
    InvalidDisplayedDepth(Quantity),
    Inactive(QueueStatus),
    GenerationExhausted,
    BookDesynchronized,
    OwnOrderMissing(OrderId),
    OwnOrderAlreadyVisible(OrderId),
    OwnOrderNotVisible(OrderId),
    OwnOrderMismatch(OrderId),
    AheadCapacity {
        capacity: usize,
    },
    DuplicateAheadOrder(OrderId),
    AheadQuantityMismatch {
        order_id: OrderId,
        expected: Quantity,
        received: Quantity,
    },
    QuantityOverflow,
}

/// One passive order's conservative queue estimate. No event method allocates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueuePosition {
    order_id: OrderId,
    side: Side,
    price: PriceTicks,
    working_quantity: Quantity,
    remaining_quantity: Quantity,
    queue_ahead: Quantity,
    policy: QueuePolicy,
    status: QueueStatus,
    generation: u64,
}

impl QueuePosition {
    /// Create a conservative estimate behind all currently displayed depth.
    ///
    /// # Errors
    ///
    /// Returns [`QueueError`] when the order identifier, price, quantity, or displayed
    /// depth is outside its valid signed range.
    pub fn new(
        order_id: OrderId,
        side: Side,
        price: PriceTicks,
        quantity: Quantity,
        displayed_depth: Quantity,
        policy: QueuePolicy,
    ) -> Result<Self, QueueError> {
        Self::validate_fields(order_id, price, quantity, displayed_depth)?;
        Ok(Self {
            order_id,
            side,
            price,
            working_quantity: quantity,
            remaining_quantity: quantity,
            queue_ahead: displayed_depth,
            policy,
            status: QueueStatus::Active,
            generation: 1,
        })
    }

    #[must_use]
    pub const fn order_id(self) -> OrderId {
        self.order_id
    }

    #[must_use]
    pub const fn side(self) -> Side {
        self.side
    }

    #[must_use]
    pub const fn price(self) -> PriceTicks {
        self.price
    }

    #[must_use]
    pub const fn working_quantity(self) -> Quantity {
        self.working_quantity
    }

    #[must_use]
    pub const fn remaining_quantity(self) -> Quantity {
        self.remaining_quantity
    }

    #[must_use]
    pub const fn queue_ahead(self) -> Quantity {
        self.queue_ahead
    }

    #[must_use]
    pub const fn policy(self) -> QueuePolicy {
        self.policy
    }

    #[must_use]
    pub const fn status(self) -> QueueStatus {
        self.status
    }

    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }

    /// Apply an aggressive trade print. Only prints at our price advance the queue.
    ///
    /// # Errors
    ///
    /// Returns [`QueueError`] for an inactive position or invalid market event.
    pub fn on_trade(
        &mut self,
        price: PriceTicks,
        quantity: Quantity,
    ) -> Result<QueueUpdate, QueueError> {
        self.require_active()?;
        Self::validate_market_event(price, quantity)?;
        let before = self.queue_ahead;
        if price != self.price {
            return Ok(self.update(QueueAction::UnrelatedTrade, before, Quantity::ZERO));
        }

        let consumed_ahead = self.queue_ahead.0.min(quantity.0);
        self.queue_ahead = Quantity(self.queue_ahead.0 - consumed_ahead);
        let available_for_fill = quantity.0 - consumed_ahead;
        let filled = Quantity(available_for_fill.min(self.remaining_quantity.0));
        self.remaining_quantity = Quantity(self.remaining_quantity.0 - filled.0);
        if self.remaining_quantity == Quantity::ZERO {
            self.status = QueueStatus::Filled;
        }
        Ok(self.update(QueueAction::TradeAtPrice, before, filled))
    }

    /// Apply an anonymous displayed cancellation under the conservative policy.
    ///
    /// # Errors
    ///
    /// Returns [`QueueError`] for an inactive position or invalid market event.
    pub fn on_cancel(
        &mut self,
        price: PriceTicks,
        quantity: Quantity,
    ) -> Result<QueueUpdate, QueueError> {
        self.require_active()?;
        Self::validate_market_event(price, quantity)?;
        let before = self.queue_ahead;
        let action = if price == self.price {
            // Identity of canceled depth is unknown. Fail conservative: it is behind
            // our order, so no quantity ahead is removed.
            QueueAction::CancelAssumedBehind
        } else {
            QueueAction::UnrelatedCancel
        };
        Ok(self.update(action, before, Quantity::ZERO))
    }

    /// Replace the passive order. Venue replace always loses time priority.
    ///
    /// # Errors
    ///
    /// Returns [`QueueError`] for inactive/invalid state or generation overflow.
    pub fn replace(
        &mut self,
        price: PriceTicks,
        quantity: Quantity,
        displayed_depth: Quantity,
    ) -> Result<QueueUpdate, QueueError> {
        self.require_active()?;
        Self::validate_fields(self.order_id, price, quantity, displayed_depth)?;
        let next_generation = self
            .generation
            .checked_add(1)
            .ok_or(QueueError::GenerationExhausted)?;
        let before = self.queue_ahead;
        self.price = price;
        self.working_quantity = quantity;
        self.remaining_quantity = quantity;
        self.queue_ahead = displayed_depth;
        self.generation = next_generation;
        Ok(self.update(QueueAction::ReplacedLostPriority, before, Quantity::ZERO))
    }

    /// Cancel the tracked order.
    ///
    /// # Errors
    ///
    /// Returns [`QueueError::Inactive`] unless the order is active.
    pub fn cancel(&mut self) -> Result<QueueUpdate, QueueError> {
        self.require_active()?;
        let before = self.queue_ahead;
        self.status = QueueStatus::Canceled;
        Ok(self.update(QueueAction::OwnOrderCanceled, before, Quantity::ZERO))
    }

    /// Invalidate the estimate after a feed or order-state discontinuity.
    ///
    /// # Errors
    ///
    /// Returns [`QueueError::Inactive`] unless the order is active.
    pub fn invalidate(&mut self) -> Result<QueueUpdate, QueueError> {
        self.require_active()?;
        let before = self.queue_ahead;
        self.status = QueueStatus::Invalidated;
        Ok(self.update(QueueAction::Invalidated, before, Quantity::ZERO))
    }

    fn update(
        self,
        action: QueueAction,
        queue_ahead_before: Quantity,
        filled_quantity: Quantity,
    ) -> QueueUpdate {
        QueueUpdate {
            action,
            queue_ahead_before,
            queue_ahead_after: self.queue_ahead,
            filled_quantity,
            remaining_quantity: self.remaining_quantity,
            status: self.status,
            generation: self.generation,
        }
    }

    fn require_active(self) -> Result<(), QueueError> {
        if self.status == QueueStatus::Active {
            Ok(())
        } else {
            Err(QueueError::Inactive(self.status))
        }
    }

    fn validate_fields(
        order_id: OrderId,
        price: PriceTicks,
        quantity: Quantity,
        displayed_depth: Quantity,
    ) -> Result<(), QueueError> {
        if order_id.0 == 0 {
            return Err(QueueError::InvalidOrderId);
        }
        if !price.is_positive() {
            return Err(QueueError::InvalidPrice(price));
        }
        if !quantity.is_positive() {
            return Err(QueueError::InvalidQuantity(quantity));
        }
        if displayed_depth.0 < 0 {
            return Err(QueueError::InvalidDisplayedDepth(displayed_depth));
        }
        Ok(())
    }

    fn validate_market_event(price: PriceTicks, quantity: Quantity) -> Result<(), QueueError> {
        if !price.is_positive() {
            return Err(QueueError::InvalidPrice(price));
        }
        if !quantity.is_positive() {
            return Err(QueueError::InvalidQuantity(quantity));
        }
        Ok(())
    }
}

/// Exact market-by-order queue position for a venue with deterministic
/// price-time priority and replace-loses-priority semantics.
///
/// Every displayed order ahead is retained by identity in a fixed-capacity hash
/// index. Adds observed before the venue publishes the owned order are ahead;
/// adds observed after it are behind. Exact executions, cancels, and replaces
/// update only the identified order. Any feed/book inconsistency invalidates the
/// tracker instead of inventing queue improvement.
///
/// This model is intentionally venue-rule-specific. A venue whose modify rules,
/// hidden-liquidity treatment, allocation algorithm, or feed/order-entry merge
/// semantics differ must provide a different governed policy adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExactQueuePosition<const MAX_AHEAD: usize> {
    order_id: OrderId,
    side: Side,
    price: PriceTicks,
    working_quantity: Quantity,
    remaining_quantity: Quantity,
    ahead: FixedIndexMap<OrderId, Quantity, MAX_AHEAD>,
    queue_ahead: Quantity,
    own_visible: bool,
    status: QueueStatus,
    generation: u64,
}

impl<const MAX_AHEAD: usize> ExactQueuePosition<MAX_AHEAD> {
    /// Create a tracker after local order submission but before its MBO add is
    /// visible. All orders currently at the level, and all same-level adds before
    /// the owned add echo, are treated as ahead.
    ///
    /// # Errors
    ///
    /// Returns [`QueueError`] for invalid owned-order fields, an unsynchronized
    /// book, an already-visible identifier, arithmetic failure, or insufficient
    /// fixed ahead-order capacity.
    pub fn join_behind_book<const MAX_ORDERS: usize, const MAX_LEVELS: usize>(
        book: &L3Book<MAX_ORDERS, MAX_LEVELS>,
        order_id: OrderId,
        side: Side,
        price: PriceTicks,
        quantity: Quantity,
    ) -> Result<Self, QueueError> {
        QueuePosition::validate_fields(order_id, price, quantity, Quantity::ZERO)?;
        if !book.is_synchronized() {
            return Err(QueueError::BookDesynchronized);
        }
        if book.order(order_id).is_some() {
            return Err(QueueError::OwnOrderAlreadyVisible(order_id));
        }
        let mut result = Self::empty(order_id, side, price, quantity, false);
        let mut cursor = book.front_order(side, price);
        while let Some(order) = cursor {
            result.insert_ahead(order)?;
            cursor = book.next_order(order.id);
        }
        Ok(result)
    }

    /// Reconstruct an exact tracker for an owned order already present in the MBO
    /// book. Only the price-time prefix before that identifier is stored.
    ///
    /// # Errors
    ///
    /// Returns [`QueueError`] for an unsynchronized book, a missing owned order,
    /// arithmetic failure, or insufficient fixed ahead-order capacity.
    pub fn from_visible_order<const MAX_ORDERS: usize, const MAX_LEVELS: usize>(
        book: &L3Book<MAX_ORDERS, MAX_LEVELS>,
        order_id: OrderId,
    ) -> Result<Self, QueueError> {
        if !book.is_synchronized() {
            return Err(QueueError::BookDesynchronized);
        }
        let own = book
            .order(order_id)
            .ok_or(QueueError::OwnOrderMissing(order_id))?;
        let mut result = Self::empty(own.id, own.side, own.price, own.quantity, true);
        result.rebuild_visible_prefix(book, own)?;
        Ok(result)
    }

    const fn empty(
        order_id: OrderId,
        side: Side,
        price: PriceTicks,
        quantity: Quantity,
        own_visible: bool,
    ) -> Self {
        Self {
            order_id,
            side,
            price,
            working_quantity: quantity,
            remaining_quantity: quantity,
            ahead: FixedIndexMap::new(),
            queue_ahead: Quantity::ZERO,
            own_visible,
            status: QueueStatus::Active,
            generation: 1,
        }
    }

    #[must_use]
    pub const fn order_id(&self) -> OrderId {
        self.order_id
    }

    #[must_use]
    pub const fn side(&self) -> Side {
        self.side
    }

    #[must_use]
    pub const fn price(&self) -> PriceTicks {
        self.price
    }

    #[must_use]
    pub const fn working_quantity(&self) -> Quantity {
        self.working_quantity
    }

    #[must_use]
    pub const fn remaining_quantity(&self) -> Quantity {
        self.remaining_quantity
    }

    #[must_use]
    pub const fn queue_ahead(&self) -> Quantity {
        self.queue_ahead
    }

    #[must_use]
    pub const fn ahead_order_count(&self) -> usize {
        self.ahead.len()
    }

    #[must_use]
    pub fn ahead_quantity(&self, order_id: OrderId) -> Option<Quantity> {
        self.ahead.get(order_id).copied()
    }

    #[must_use]
    pub const fn own_visible(&self) -> bool {
        self.own_visible
    }

    #[must_use]
    pub const fn status(&self) -> QueueStatus {
        self.status
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Apply the exact outcome after the same event has successfully mutated the
    /// supplied synchronized L3 book.
    ///
    /// # Errors
    ///
    /// Returns [`QueueError`] and permanently invalidates this tracker for any
    /// identity, quantity, capacity, arithmetic, or book synchronization fault.
    pub fn on_book_outcome<const MAX_ORDERS: usize, const MAX_LEVELS: usize>(
        &mut self,
        book: &L3Book<MAX_ORDERS, MAX_LEVELS>,
        outcome: ApplyOutcome,
    ) -> Result<QueueUpdate, QueueError> {
        self.require_active()?;
        let before = self.queue_ahead;
        if !book.is_synchronized() {
            self.status = QueueStatus::Invalidated;
            return Err(QueueError::BookDesynchronized);
        }
        let result = self.apply_outcome(book, outcome);
        match result {
            Ok((action, filled)) => Ok(self.update(action, before, filled)),
            Err(error) => {
                self.status = QueueStatus::Invalidated;
                Err(error)
            }
        }
    }

    /// Mark the owned order canceled independently of public MBO publication.
    ///
    /// # Errors
    ///
    /// Returns [`QueueError::Inactive`] unless the tracker is active.
    pub fn cancel(&mut self) -> Result<QueueUpdate, QueueError> {
        self.require_active()?;
        let before = self.queue_ahead;
        self.status = QueueStatus::Canceled;
        Ok(self.update(QueueAction::OwnOrderCanceled, before, Quantity::ZERO))
    }

    /// Invalidate after an order-entry/market-data merge discontinuity.
    ///
    /// # Errors
    ///
    /// Returns [`QueueError::Inactive`] unless the tracker is active.
    pub fn invalidate(&mut self) -> Result<QueueUpdate, QueueError> {
        self.require_active()?;
        let before = self.queue_ahead;
        self.status = QueueStatus::Invalidated;
        Ok(self.update(QueueAction::Invalidated, before, Quantity::ZERO))
    }

    fn apply_outcome<const MAX_ORDERS: usize, const MAX_LEVELS: usize>(
        &mut self,
        book: &L3Book<MAX_ORDERS, MAX_LEVELS>,
        outcome: ApplyOutcome,
    ) -> Result<(QueueAction, Quantity), QueueError> {
        match outcome {
            ApplyOutcome::Added(order) => self.apply_added(book, order),
            ApplyOutcome::Modified { previous, current } => {
                self.apply_modified(book, previous, current)
            }
            ApplyOutcome::Canceled(order) => self.apply_canceled(order),
            ApplyOutcome::Executed {
                order_id,
                executed,
                remaining,
            } => self.apply_executed(order_id, executed, remaining),
            ApplyOutcome::Cleared { .. } => {
                self.ahead.clear();
                self.queue_ahead = Quantity::ZERO;
                self.status = QueueStatus::Invalidated;
                Ok((QueueAction::BookCleared, Quantity::ZERO))
            }
        }
    }

    fn apply_added<const MAX_ORDERS: usize, const MAX_LEVELS: usize>(
        &mut self,
        book: &L3Book<MAX_ORDERS, MAX_LEVELS>,
        order: BookOrder,
    ) -> Result<(QueueAction, Quantity), QueueError> {
        if order.id == self.order_id {
            if self.own_visible {
                return Err(QueueError::OwnOrderAlreadyVisible(order.id));
            }
            self.validate_owned(order)?;
            self.rebuild_visible_prefix(book, order)?;
            self.own_visible = true;
            return Ok((QueueAction::OwnOrderBecameVisible, Quantity::ZERO));
        }
        if !self.own_visible && order.side == self.side && order.price == self.price {
            self.insert_ahead(order)?;
            Ok((QueueAction::AheadOrderJoined, Quantity::ZERO))
        } else {
            Ok((QueueAction::BehindOrderEvent, Quantity::ZERO))
        }
    }

    fn apply_modified<const MAX_ORDERS: usize, const MAX_LEVELS: usize>(
        &mut self,
        book: &L3Book<MAX_ORDERS, MAX_LEVELS>,
        previous: BookOrder,
        current: BookOrder,
    ) -> Result<(QueueAction, Quantity), QueueError> {
        if previous.id == self.order_id {
            return self.apply_owned_replacement(book, current);
        }
        let was_ahead = self.remove_ahead_exact(previous.id, previous.quantity)?;
        if !self.own_visible && current.side == self.side && current.price == self.price {
            self.insert_ahead(current)?;
            Ok((QueueAction::AheadOrderReplacedLostPriority, Quantity::ZERO))
        } else if was_ahead {
            Ok((QueueAction::AheadOrderReplacedLostPriority, Quantity::ZERO))
        } else {
            Ok((QueueAction::BehindOrderEvent, Quantity::ZERO))
        }
    }

    fn apply_owned_replacement<const MAX_ORDERS: usize, const MAX_LEVELS: usize>(
        &mut self,
        book: &L3Book<MAX_ORDERS, MAX_LEVELS>,
        current: BookOrder,
    ) -> Result<(QueueAction, Quantity), QueueError> {
        if !self.own_visible {
            return Err(QueueError::OwnOrderNotVisible(self.order_id));
        }
        if current.id != self.order_id
            || !current.price.is_positive()
            || !current.quantity.is_positive()
        {
            return Err(QueueError::OwnOrderMismatch(current.id));
        }
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or(QueueError::GenerationExhausted)?;
        self.side = current.side;
        self.price = current.price;
        self.working_quantity = current.quantity;
        self.remaining_quantity = current.quantity;
        self.rebuild_visible_prefix(book, current)?;
        Ok((QueueAction::OwnOrderReplacedLostPriority, Quantity::ZERO))
    }

    fn apply_canceled(&mut self, order: BookOrder) -> Result<(QueueAction, Quantity), QueueError> {
        if order.id == self.order_id {
            if !self.own_visible {
                return Err(QueueError::OwnOrderNotVisible(self.order_id));
            }
            if order.quantity != self.remaining_quantity {
                return Err(QueueError::AheadQuantityMismatch {
                    order_id: order.id,
                    expected: self.remaining_quantity,
                    received: order.quantity,
                });
            }
            self.status = QueueStatus::Canceled;
            return Ok((QueueAction::OwnOrderCanceled, Quantity::ZERO));
        }
        if self.remove_ahead_exact(order.id, order.quantity)? {
            Ok((QueueAction::AheadOrderCanceled, Quantity::ZERO))
        } else {
            Ok((QueueAction::BehindOrderEvent, Quantity::ZERO))
        }
    }

    fn apply_executed(
        &mut self,
        order_id: OrderId,
        executed: Quantity,
        remaining: Quantity,
    ) -> Result<(QueueAction, Quantity), QueueError> {
        if order_id == self.order_id {
            return self.apply_owned_execution(order_id, executed, remaining);
        }
        if self.execute_ahead(order_id, executed, remaining)? {
            Ok((QueueAction::AheadOrderExecuted, Quantity::ZERO))
        } else {
            Ok((QueueAction::BehindOrderEvent, Quantity::ZERO))
        }
    }

    fn apply_owned_execution(
        &mut self,
        order_id: OrderId,
        executed: Quantity,
        remaining: Quantity,
    ) -> Result<(QueueAction, Quantity), QueueError> {
        if !self.own_visible {
            return Err(QueueError::OwnOrderNotVisible(self.order_id));
        }
        let expected = self
            .remaining_quantity
            .0
            .checked_sub(executed.0)
            .filter(|value| *value >= 0)
            .map(Quantity)
            .ok_or(QueueError::AheadQuantityMismatch {
                order_id,
                expected: self.remaining_quantity,
                received: executed,
            })?;
        if expected != remaining {
            return Err(QueueError::AheadQuantityMismatch {
                order_id,
                expected,
                received: remaining,
            });
        }
        self.remaining_quantity = remaining;
        if remaining == Quantity::ZERO {
            self.status = QueueStatus::Filled;
        }
        Ok((QueueAction::OwnOrderExecuted, executed))
    }

    fn validate_owned(&self, order: BookOrder) -> Result<(), QueueError> {
        if order.id != self.order_id
            || order.side != self.side
            || order.price != self.price
            || order.quantity != self.remaining_quantity
        {
            return Err(QueueError::OwnOrderMismatch(order.id));
        }
        Ok(())
    }

    fn rebuild_visible_prefix<const MAX_ORDERS: usize, const MAX_LEVELS: usize>(
        &mut self,
        book: &L3Book<MAX_ORDERS, MAX_LEVELS>,
        own: BookOrder,
    ) -> Result<(), QueueError> {
        self.ahead.clear();
        self.queue_ahead = Quantity::ZERO;
        let mut cursor = book.front_order(own.side, own.price);
        while let Some(order) = cursor {
            if order.id == own.id {
                return Ok(());
            }
            self.insert_ahead(order)?;
            cursor = book.next_order(order.id);
        }
        Err(QueueError::OwnOrderMissing(own.id))
    }

    fn insert_ahead(&mut self, order: BookOrder) -> Result<(), QueueError> {
        if self.ahead.get(order.id).is_some() {
            return Err(QueueError::DuplicateAheadOrder(order.id));
        }
        let total = self
            .queue_ahead
            .0
            .checked_add(order.quantity.0)
            .filter(|value| *value >= 0)
            .ok_or(QueueError::QuantityOverflow)?;
        match self.ahead.insert(order.id, order.quantity) {
            Ok(None) => {
                self.queue_ahead = Quantity(total);
                Ok(())
            }
            Ok(Some(_)) => Err(QueueError::DuplicateAheadOrder(order.id)),
            Err(CapacityError::Full | CapacityError::InvalidCapacity) => {
                Err(QueueError::AheadCapacity {
                    capacity: MAX_AHEAD,
                })
            }
        }
    }

    fn remove_ahead_exact(
        &mut self,
        order_id: OrderId,
        expected_quantity: Quantity,
    ) -> Result<bool, QueueError> {
        let Some(stored) = self.ahead.get(order_id).copied() else {
            return Ok(false);
        };
        if stored != expected_quantity {
            return Err(QueueError::AheadQuantityMismatch {
                order_id,
                expected: stored,
                received: expected_quantity,
            });
        }
        let remaining_total = self
            .queue_ahead
            .0
            .checked_sub(stored.0)
            .filter(|value| *value >= 0)
            .ok_or(QueueError::QuantityOverflow)?;
        let removed = self.ahead.remove(order_id);
        if removed != Some(stored) {
            return Err(QueueError::AheadQuantityMismatch {
                order_id,
                expected: stored,
                received: Quantity::ZERO,
            });
        }
        self.queue_ahead = Quantity(remaining_total);
        Ok(true)
    }

    fn execute_ahead(
        &mut self,
        order_id: OrderId,
        executed: Quantity,
        remaining: Quantity,
    ) -> Result<bool, QueueError> {
        let Some(stored) = self.ahead.get(order_id).copied() else {
            return Ok(false);
        };
        let expected = stored
            .0
            .checked_sub(executed.0)
            .filter(|value| *value >= 0)
            .map(Quantity)
            .ok_or(QueueError::AheadQuantityMismatch {
                order_id,
                expected: stored,
                received: executed,
            })?;
        if expected != remaining {
            return Err(QueueError::AheadQuantityMismatch {
                order_id,
                expected,
                received: remaining,
            });
        }
        let total = self
            .queue_ahead
            .0
            .checked_sub(executed.0)
            .filter(|value| *value >= 0)
            .ok_or(QueueError::QuantityOverflow)?;
        if remaining == Quantity::ZERO {
            self.ahead.remove(order_id);
        } else if let Some(quantity) = self.ahead.get_mut(order_id) {
            *quantity = remaining;
        } else {
            return Err(QueueError::AheadQuantityMismatch {
                order_id,
                expected: stored,
                received: Quantity::ZERO,
            });
        }
        self.queue_ahead = Quantity(total);
        Ok(true)
    }

    fn require_active(&self) -> Result<(), QueueError> {
        if self.status == QueueStatus::Active {
            Ok(())
        } else {
            Err(QueueError::Inactive(self.status))
        }
    }

    fn update(
        &self,
        action: QueueAction,
        queue_ahead_before: Quantity,
        filled_quantity: Quantity,
    ) -> QueueUpdate {
        QueueUpdate {
            action,
            queue_ahead_before,
            queue_ahead_after: self.queue_ahead,
            filled_quantity,
            remaining_quantity: self.remaining_quantity,
            status: self.status,
            generation: self.generation,
        }
    }
}
