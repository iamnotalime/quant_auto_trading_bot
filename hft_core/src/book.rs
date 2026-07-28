//! Fixed-capacity level-three order book with strict venue sequencing.
//!
//! The normal event path uses preallocated open-addressed indexes for order and
//! level lookup, intrusive FIFO links within each price level, cached aggregates,
//! and cached best-level pointers. Consequently, order lookup, level lookup,
//! aggregation, and FIFO maintenance are O(1) expected work without allocation.
//! Removing the current best price is the deliberate exception: selecting the
//! next best scans at most `MAX_LEVELS` preallocated slots. The diagnostic visit
//! count makes that rare bounded path observable in tests and telemetry adapters.

use crate::types::{OrderId, PriceTicks, Quantity, Sequence, Side};

/// One live venue order. `priority` is a monotonic local arrival ordinal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BookOrder {
    pub id: OrderId,
    pub side: Side,
    pub price: PriceTicks,
    pub quantity: Quantity,
    pub priority: u64,
}

/// Aggregated view of one price level.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PriceLevel {
    pub side: Side,
    pub price: PriceTicks,
    pub total_quantity: Quantity,
    pub order_count: usize,
}

/// Normalized venue book event. Every event consumes exactly one venue sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BookEvent {
    Add {
        order_id: OrderId,
        side: Side,
        price: PriceTicks,
        quantity: Quantity,
    },
    /// Venue replace: side and identifier are retained, while time priority is lost.
    Modify {
        order_id: OrderId,
        price: PriceTicks,
        quantity: Quantity,
    },
    Cancel {
        order_id: OrderId,
    },
    Execute {
        order_id: OrderId,
        quantity: Quantity,
    },
    Clear,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplyOutcome {
    Added(BookOrder),
    Modified {
        previous: BookOrder,
        current: BookOrder,
    },
    Canceled(BookOrder),
    Executed {
        order_id: OrderId,
        executed: Quantity,
        remaining: Quantity,
    },
    Cleared {
        removed_orders: usize,
    },
}

/// A book error always leaves the book latched as desynchronized.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BookError {
    Desynchronized,
    SequenceMismatch {
        expected: Sequence,
        received: Sequence,
    },
    SequenceExhausted,
    InvalidOrderId,
    InvalidPrice(PriceTicks),
    InvalidQuantity(Quantity),
    DuplicateOrder(OrderId),
    UnknownOrder(OrderId),
    ExecuteExceedsRemaining {
        order_id: OrderId,
        requested: Quantity,
        remaining: Quantity,
    },
    CrossedBook {
        side: Side,
        price: PriceTicks,
        opposite_best: PriceTicks,
    },
    OrderCapacity {
        capacity: usize,
    },
    LevelCapacity {
        capacity: usize,
    },
    QuantityOverflow,
    PriorityExhausted,
}

trait IndexKey: Copy + Eq {
    fn index_hash(self) -> u64;
}

const fn mix_u64(mut value: u64) -> u64 {
    value ^= value >> 30;
    value = value.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value ^= value >> 27;
    value = value.wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

impl IndexKey for OrderId {
    fn index_hash(self) -> u64 {
        mix_u64(self.0)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LevelKey {
    side: Side,
    price: PriceTicks,
}

impl IndexKey for LevelKey {
    fn index_hash(self) -> u64 {
        let side_salt = match self.side {
            Side::Buy => 0x243f_6a88_85a3_08d3,
            Side::Sell => 0x1319_8a2e_0370_7344,
        };
        let price_bits = u64::from_ne_bytes(self.price.0.to_ne_bytes());
        mix_u64(price_bits ^ side_salt)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IndexSlot<K> {
    Empty,
    Tombstone,
    Occupied { key: K, value: usize },
}

#[derive(Debug, Eq, PartialEq)]
struct FixedIndex<K, const N: usize> {
    slots: [IndexSlot<K>; N],
    len: usize,
}

impl<K: IndexKey, const N: usize> FixedIndex<K, N> {
    const fn new() -> Self {
        Self {
            slots: [IndexSlot::Empty; N],
            len: 0,
        }
    }

    fn start(key: K) -> Option<usize> {
        if N == 0 {
            return None;
        }
        let capacity = u64::try_from(N).ok()?;
        usize::try_from(key.index_hash() % capacity).ok()
    }

    fn find_detail(&self, key: K) -> (Option<(usize, usize)>, usize) {
        let Some(start) = Self::start(key) else {
            return (None, 0);
        };
        let mut probes = 0;
        for offset in 0..N {
            let bucket = (start + offset) % N;
            probes += 1;
            match self.slots[bucket] {
                IndexSlot::Empty => return (None, probes),
                IndexSlot::Occupied {
                    key: candidate,
                    value,
                } if candidate == key => return (Some((bucket, value)), probes),
                IndexSlot::Occupied { .. } | IndexSlot::Tombstone => {}
            }
        }
        (None, probes)
    }

    fn find(&self, key: K) -> Option<(usize, usize)> {
        self.find_detail(key).0
    }

    /// Plan an insertion without mutation. `virtual_tombstone` supports an atomic
    /// replace that deletes its sole old level before inserting a new level into
    /// an otherwise full table.
    fn plan_insert(&self, key: K, virtual_tombstone: Option<usize>) -> Option<usize> {
        let start = Self::start(key)?;
        let mut first_tombstone = None;
        for offset in 0..N {
            let bucket = (start + offset) % N;
            let slot_is_virtual_tombstone = virtual_tombstone == Some(bucket);
            match self.slots[bucket] {
                _ if slot_is_virtual_tombstone => {
                    first_tombstone.get_or_insert(bucket);
                }
                IndexSlot::Tombstone => {
                    first_tombstone.get_or_insert(bucket);
                }
                IndexSlot::Empty => return Some(first_tombstone.unwrap_or(bucket)),
                IndexSlot::Occupied { key: candidate, .. } if candidate == key => {
                    return Some(bucket);
                }
                IndexSlot::Occupied { .. } => {}
            }
        }
        first_tombstone
    }

    fn insert_planned(&mut self, bucket: usize, key: K, value: usize) {
        debug_assert!(bucket < N);
        debug_assert!(matches!(
            self.slots[bucket],
            IndexSlot::Empty | IndexSlot::Tombstone
        ));
        self.slots[bucket] = IndexSlot::Occupied { key, value };
        self.len += 1;
    }

    fn remove_bucket(&mut self, bucket: usize) {
        debug_assert!(bucket < N);
        debug_assert!(matches!(self.slots[bucket], IndexSlot::Occupied { .. }));
        self.slots[bucket] = IndexSlot::Tombstone;
        self.len -= 1;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OrderNode {
    order: BookOrder,
    level_slot: usize,
    previous: Option<usize>,
    next: Option<usize>,
    index_bucket: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LevelNode {
    key: LevelKey,
    total_quantity: Quantity,
    order_count: usize,
    head: Option<usize>,
    tail: Option<usize>,
    index_bucket: usize,
}

impl LevelNode {
    const fn view(self) -> PriceLevel {
        PriceLevel {
            side: self.key.side,
            price: self.key.price,
            total_quantity: self.total_quantity,
            order_count: self.order_count,
        }
    }
}

const fn free_links<const N: usize>() -> [Option<usize>; N] {
    let mut links = [None; N];
    let mut index = 0;
    while index < N {
        links[index] = if index + 1 < N { Some(index + 1) } else { None };
        index += 1;
    }
    links
}

const fn free_head<const N: usize>() -> Option<usize> {
    if N == 0 { None } else { Some(0) }
}

/// Allocation-free indexed L3 book. Capacity exhaustion is a hard synchronization fault.
///
/// The order and level indexes use linear probing. Expected lookup is O(1) when
/// provisioned below saturation; even at saturation, work is bounded by the
/// corresponding compile-time capacity. FIFO head/tail and aggregate access are O(1).
#[derive(Debug, Eq, PartialEq)]
pub struct L3Book<const MAX_ORDERS: usize, const MAX_LEVELS: usize> {
    orders: [Option<OrderNode>; MAX_ORDERS],
    order_free_next: [Option<usize>; MAX_ORDERS],
    order_free_head: Option<usize>,
    order_index: FixedIndex<OrderId, MAX_ORDERS>,
    levels: [Option<LevelNode>; MAX_LEVELS],
    level_free_next: [Option<usize>; MAX_LEVELS],
    level_free_head: Option<usize>,
    level_index: FixedIndex<LevelKey, MAX_LEVELS>,
    order_count: usize,
    level_count: usize,
    best_bid_slot: Option<usize>,
    best_ask_slot: Option<usize>,
    expected_sequence: Sequence,
    next_priority: u64,
    synchronized: bool,
    last_best_recompute_visits: usize,
}

impl<const MAX_ORDERS: usize, const MAX_LEVELS: usize> L3Book<MAX_ORDERS, MAX_LEVELS> {
    #[must_use]
    pub const fn new(next_sequence: Sequence) -> Self {
        Self {
            orders: [None; MAX_ORDERS],
            order_free_next: free_links(),
            order_free_head: free_head::<MAX_ORDERS>(),
            order_index: FixedIndex::new(),
            levels: [None; MAX_LEVELS],
            level_free_next: free_links(),
            level_free_head: free_head::<MAX_LEVELS>(),
            level_index: FixedIndex::new(),
            order_count: 0,
            level_count: 0,
            best_bid_slot: None,
            best_ask_slot: None,
            expected_sequence: next_sequence,
            next_priority: 1,
            synchronized: true,
            last_best_recompute_visits: 0,
        }
    }

    /// Clear all state and authorize a new snapshot boundary.
    pub fn reset_from_snapshot(&mut self, next_sequence: Sequence) {
        *self = Self::new(next_sequence);
    }

    #[must_use]
    pub const fn is_synchronized(&self) -> bool {
        self.synchronized
    }

    #[must_use]
    pub const fn expected_sequence(&self) -> Sequence {
        self.expected_sequence
    }

    #[must_use]
    pub const fn order_count(&self) -> usize {
        self.order_count
    }

    #[must_use]
    pub const fn level_count(&self) -> usize {
        self.level_count
    }

    #[must_use]
    pub fn order(&self, order_id: OrderId) -> Option<BookOrder> {
        let (_, slot) = self.order_index.find(order_id)?;
        self.orders[slot].map(|node| node.order)
    }

    #[must_use]
    pub fn level(&self, side: Side, price: PriceTicks) -> Option<PriceLevel> {
        let key = LevelKey { side, price };
        let (_, slot) = self.level_index.find(key)?;
        self.levels[slot].map(LevelNode::view)
    }

    #[must_use]
    pub fn best_bid(&self) -> Option<PriceLevel> {
        self.best_bid_slot
            .and_then(|slot| self.levels[slot].map(LevelNode::view))
    }

    #[must_use]
    pub fn best_ask(&self) -> Option<PriceLevel> {
        self.best_ask_slot
            .and_then(|slot| self.levels[slot].map(LevelNode::view))
    }

    /// Earliest live order at a level under price-time priority.
    #[must_use]
    pub fn front_order(&self, side: Side, price: PriceTicks) -> Option<BookOrder> {
        let key = LevelKey { side, price };
        let (_, level_slot) = self.level_index.find(key)?;
        let order_slot = self.levels[level_slot]?.head?;
        self.orders[order_slot].map(|node| node.order)
    }

    /// Next live order at the same level under price-time priority.
    ///
    /// This is an indexed lookup followed by one intrusive-list hop. It lets an
    /// exact queue tracker take a bounded, allocation-free snapshot of all venue
    /// orders ahead of a locally owned order.
    #[must_use]
    pub fn next_order(&self, order_id: OrderId) -> Option<BookOrder> {
        let (_, order_slot) = self.order_index.find(order_id)?;
        let next_slot = self.orders[order_slot]?.next?;
        self.orders[next_slot].map(|node| node.order)
    }

    /// Return the exact number of hash buckets inspected by an order lookup.
    ///
    /// This diagnostic performs a lookup but does not affect the production lookup
    /// path. It exists so collision/load-factor behavior can be regression tested.
    #[doc(hidden)]
    #[must_use]
    pub fn diagnostic_order_lookup_probes(&self, order_id: OrderId) -> usize {
        self.order_index.find_detail(order_id).1
    }

    /// Return the exact number of hash buckets inspected by a level lookup.
    #[doc(hidden)]
    #[must_use]
    pub fn diagnostic_level_lookup_probes(&self, side: Side, price: PriceTicks) -> usize {
        self.level_index.find_detail(LevelKey { side, price }).1
    }

    /// Number of preallocated level slots visited by the most recent best-price
    /// recomputation. It is always zero or at most `MAX_LEVELS`.
    #[doc(hidden)]
    #[must_use]
    pub const fn diagnostic_last_best_recompute_visits(&self) -> usize {
        self.last_best_recompute_visits
    }

    /// Apply one exact-sequence event. Any error latches desynchronization.
    ///
    /// # Errors
    ///
    /// Returns [`BookError`] for sequence, validation, capacity, arithmetic, or
    /// synchronization faults. Failed events do not partially mutate book contents.
    pub fn apply(
        &mut self,
        sequence: Sequence,
        event: BookEvent,
    ) -> Result<ApplyOutcome, BookError> {
        if !self.synchronized {
            return Err(BookError::Desynchronized);
        }
        if sequence != self.expected_sequence {
            self.synchronized = false;
            return Err(BookError::SequenceMismatch {
                expected: self.expected_sequence,
                received: sequence,
            });
        }
        let Some(next_sequence) = sequence.0.checked_add(1).map(Sequence) else {
            self.synchronized = false;
            return Err(BookError::SequenceExhausted);
        };

        match self.apply_validated(event) {
            Ok(outcome) => {
                self.expected_sequence = next_sequence;
                Ok(outcome)
            }
            Err(error) => {
                self.synchronized = false;
                Err(error)
            }
        }
    }

    fn apply_validated(&mut self, event: BookEvent) -> Result<ApplyOutcome, BookError> {
        match event {
            BookEvent::Add {
                order_id,
                side,
                price,
                quantity,
            } => self.add(order_id, side, price, quantity),
            BookEvent::Modify {
                order_id,
                price,
                quantity,
            } => self.modify(order_id, price, quantity),
            BookEvent::Cancel { order_id } => self.cancel(order_id),
            BookEvent::Execute { order_id, quantity } => self.execute(order_id, quantity),
            BookEvent::Clear => Ok(self.clear()),
        }
    }

    fn add(
        &mut self,
        order_id: OrderId,
        side: Side,
        price: PriceTicks,
        quantity: Quantity,
    ) -> Result<ApplyOutcome, BookError> {
        Self::validate_order_fields(order_id, price, quantity)?;
        if self.order_index.find(order_id).is_some() {
            return Err(BookError::DuplicateOrder(order_id));
        }
        self.validate_not_crossed(side, price)?;
        if self.order_count == MAX_ORDERS {
            return Err(BookError::OrderCapacity {
                capacity: MAX_ORDERS,
            });
        }

        let key = LevelKey { side, price };
        let existing_level = self.level_index.find(key).map(|(_, slot)| slot);
        if existing_level.is_none() && self.level_count == MAX_LEVELS {
            return Err(BookError::LevelCapacity {
                capacity: MAX_LEVELS,
            });
        }
        let new_total = self.checked_level_add(existing_level, quantity)?;
        let priority = self.next_priority;
        let next_priority = priority
            .checked_add(1)
            .ok_or(BookError::PriorityExhausted)?;
        let order_bucket =
            self.order_index
                .plan_insert(order_id, None)
                .ok_or(BookError::OrderCapacity {
                    capacity: MAX_ORDERS,
                })?;
        let level_bucket = if existing_level.is_none() {
            Some(
                self.level_index
                    .plan_insert(key, None)
                    .ok_or(BookError::LevelCapacity {
                        capacity: MAX_LEVELS,
                    })?,
            )
        } else {
            None
        };

        let order_slot = self.pop_order_slot();
        let level_slot = match existing_level {
            Some(slot) => slot,
            None => self.create_level(key, level_bucket.expect("preflight planned level bucket")),
        };
        let order = BookOrder {
            id: order_id,
            side,
            price,
            quantity,
            priority,
        };
        self.orders[order_slot] = Some(OrderNode {
            order,
            level_slot,
            previous: None,
            next: None,
            index_bucket: order_bucket,
        });
        self.order_index
            .insert_planned(order_bucket, order_id, order_slot);
        self.append_to_level(order_slot, level_slot, new_total);
        self.order_count += 1;
        self.next_priority = next_priority;
        Ok(ApplyOutcome::Added(order))
    }

    fn modify(
        &mut self,
        order_id: OrderId,
        price: PriceTicks,
        quantity: Quantity,
    ) -> Result<ApplyOutcome, BookError> {
        if order_id.0 == 0 {
            return Err(BookError::InvalidOrderId);
        }
        if !price.is_positive() {
            return Err(BookError::InvalidPrice(price));
        }
        if !quantity.is_positive() {
            return Err(BookError::InvalidQuantity(quantity));
        }
        let (_, order_slot) = self
            .order_index
            .find(order_id)
            .ok_or(BookError::UnknownOrder(order_id))?;
        let order_node = self.orders[order_slot].expect("order index invariant");
        let previous = order_node.order;
        self.validate_not_crossed(previous.side, price)?;

        let old_level_slot = order_node.level_slot;
        let old_level = self.levels[old_level_slot].expect("order level invariant");
        let target_key = LevelKey {
            side: previous.side,
            price,
        };
        let target_level = self.level_index.find(target_key).map(|(_, slot)| slot);
        let stays_at_level = target_level == Some(old_level_slot);
        let removes_old_level = !stays_at_level && old_level.order_count == 1;
        let creates_level = target_level.is_none();
        let projected_levels =
            self.level_count - usize::from(removes_old_level) + usize::from(creates_level);
        if projected_levels > MAX_LEVELS {
            return Err(BookError::LevelCapacity {
                capacity: MAX_LEVELS,
            });
        }

        let target_total = if stays_at_level {
            let without_order = old_level.total_quantity.0 - previous.quantity.0;
            Quantity(
                without_order
                    .checked_add(quantity.0)
                    .ok_or(BookError::QuantityOverflow)?,
            )
        } else {
            self.checked_level_add(target_level, quantity)?
        };
        let priority = self.next_priority;
        let next_priority = priority
            .checked_add(1)
            .ok_or(BookError::PriorityExhausted)?;
        let new_level_bucket = if creates_level {
            let virtual_removal = removes_old_level.then_some(old_level.index_bucket);
            Some(
                self.level_index
                    .plan_insert(target_key, virtual_removal)
                    .ok_or(BookError::LevelCapacity {
                        capacity: MAX_LEVELS,
                    })?,
            )
        } else {
            None
        };

        self.detach_from_level(order_slot);
        if removes_old_level {
            self.remove_empty_level(old_level_slot);
        }
        let target_level_slot = match target_level {
            Some(slot) => slot,
            None => self.create_level(
                target_key,
                new_level_bucket.expect("preflight planned replacement level bucket"),
            ),
        };
        let current = BookOrder {
            id: order_id,
            side: previous.side,
            price,
            quantity,
            priority,
        };
        let node = self.orders[order_slot]
            .as_mut()
            .expect("detached order invariant");
        node.order = current;
        node.level_slot = target_level_slot;
        self.append_to_level(order_slot, target_level_slot, target_total);
        self.level_count = projected_levels;
        self.next_priority = next_priority;
        Ok(ApplyOutcome::Modified { previous, current })
    }

    fn cancel(&mut self, order_id: OrderId) -> Result<ApplyOutcome, BookError> {
        let (_, order_slot) = self
            .order_index
            .find(order_id)
            .ok_or(BookError::UnknownOrder(order_id))?;
        let node = self.orders[order_slot].expect("order index invariant");
        let order = node.order;
        let level_slot = node.level_slot;
        let removes_level = self.levels[level_slot].is_some_and(|level| level.order_count == 1);

        self.detach_from_level(order_slot);
        if removes_level {
            self.remove_empty_level(level_slot);
        }
        self.remove_order_slot(order_slot);
        Ok(ApplyOutcome::Canceled(order))
    }

    fn execute(
        &mut self,
        order_id: OrderId,
        quantity: Quantity,
    ) -> Result<ApplyOutcome, BookError> {
        if !quantity.is_positive() {
            return Err(BookError::InvalidQuantity(quantity));
        }
        let (_, order_slot) = self
            .order_index
            .find(order_id)
            .ok_or(BookError::UnknownOrder(order_id))?;
        let node = self.orders[order_slot].expect("order index invariant");
        let order = node.order;
        if quantity.0 > order.quantity.0 {
            return Err(BookError::ExecuteExceedsRemaining {
                order_id,
                requested: quantity,
                remaining: order.quantity,
            });
        }
        let remaining = Quantity(order.quantity.0 - quantity.0);
        if remaining == Quantity::ZERO {
            let level_slot = node.level_slot;
            let removes_level = self.levels[level_slot].is_some_and(|level| level.order_count == 1);
            self.detach_from_level(order_slot);
            if removes_level {
                self.remove_empty_level(level_slot);
            }
            self.remove_order_slot(order_slot);
        } else {
            let level = self.levels[node.level_slot]
                .as_mut()
                .expect("order level invariant");
            level.total_quantity = Quantity(level.total_quantity.0 - quantity.0);
            self.orders[order_slot]
                .as_mut()
                .expect("order index invariant")
                .order
                .quantity = remaining;
        }
        Ok(ApplyOutcome::Executed {
            order_id,
            executed: quantity,
            remaining,
        })
    }

    fn clear(&mut self) -> ApplyOutcome {
        let removed_orders = self.order_count;
        self.orders = [None; MAX_ORDERS];
        self.order_free_next = free_links();
        self.order_free_head = free_head::<MAX_ORDERS>();
        self.order_index = FixedIndex::new();
        self.levels = [None; MAX_LEVELS];
        self.level_free_next = free_links();
        self.level_free_head = free_head::<MAX_LEVELS>();
        self.level_index = FixedIndex::new();
        self.order_count = 0;
        self.level_count = 0;
        self.best_bid_slot = None;
        self.best_ask_slot = None;
        self.next_priority = 1;
        self.last_best_recompute_visits = 0;
        ApplyOutcome::Cleared { removed_orders }
    }

    fn validate_order_fields(
        order_id: OrderId,
        price: PriceTicks,
        quantity: Quantity,
    ) -> Result<(), BookError> {
        if order_id.0 == 0 {
            return Err(BookError::InvalidOrderId);
        }
        if !price.is_positive() {
            return Err(BookError::InvalidPrice(price));
        }
        if !quantity.is_positive() {
            return Err(BookError::InvalidQuantity(quantity));
        }
        Ok(())
    }

    fn validate_not_crossed(&self, side: Side, price: PriceTicks) -> Result<(), BookError> {
        let opposite = match side {
            Side::Buy => self.best_ask(),
            Side::Sell => self.best_bid(),
        };
        if let Some(level) = opposite {
            let crossed = match side {
                Side::Buy => price >= level.price,
                Side::Sell => price <= level.price,
            };
            if crossed {
                return Err(BookError::CrossedBook {
                    side,
                    price,
                    opposite_best: level.price,
                });
            }
        }
        Ok(())
    }

    fn checked_level_add(
        &self,
        level_slot: Option<usize>,
        quantity: Quantity,
    ) -> Result<Quantity, BookError> {
        let current = level_slot
            .and_then(|slot| self.levels[slot])
            .map_or(0, |level| level.total_quantity.0);
        current
            .checked_add(quantity.0)
            .map(Quantity)
            .ok_or(BookError::QuantityOverflow)
    }

    fn pop_order_slot(&mut self) -> usize {
        let slot = self
            .order_free_head
            .expect("order capacity preflight guarantees a free slot");
        self.order_free_head = self.order_free_next[slot];
        self.order_free_next[slot] = None;
        slot
    }

    fn pop_level_slot(&mut self) -> usize {
        let slot = self
            .level_free_head
            .expect("level capacity preflight guarantees a free slot");
        self.level_free_head = self.level_free_next[slot];
        self.level_free_next[slot] = None;
        slot
    }

    fn create_level(&mut self, key: LevelKey, index_bucket: usize) -> usize {
        let slot = self.pop_level_slot();
        self.levels[slot] = Some(LevelNode {
            key,
            total_quantity: Quantity::ZERO,
            order_count: 0,
            head: None,
            tail: None,
            index_bucket,
        });
        self.level_index.insert_planned(index_bucket, key, slot);
        self.level_count += 1;
        self.update_best_on_insert(slot);
        slot
    }

    fn update_best_on_insert(&mut self, candidate_slot: usize) {
        let candidate = self.levels[candidate_slot].expect("new level invariant");
        let best_slot = match candidate.key.side {
            Side::Buy => &mut self.best_bid_slot,
            Side::Sell => &mut self.best_ask_slot,
        };
        let replaces = best_slot.is_none_or(|slot| {
            let best = self.levels[slot].expect("best level invariant");
            match candidate.key.side {
                Side::Buy => candidate.key.price > best.key.price,
                Side::Sell => candidate.key.price < best.key.price,
            }
        });
        if replaces {
            *best_slot = Some(candidate_slot);
        }
    }

    fn append_to_level(&mut self, order_slot: usize, level_slot: usize, new_total: Quantity) {
        let tail = self.levels[level_slot]
            .expect("target level invariant")
            .tail;
        if let Some(tail_slot) = tail {
            self.orders[tail_slot]
                .as_mut()
                .expect("level tail invariant")
                .next = Some(order_slot);
        }
        let node = self.orders[order_slot]
            .as_mut()
            .expect("order attachment invariant");
        node.level_slot = level_slot;
        node.previous = tail;
        node.next = None;

        let level = self.levels[level_slot]
            .as_mut()
            .expect("target level invariant");
        if level.head.is_none() {
            level.head = Some(order_slot);
        }
        level.tail = Some(order_slot);
        level.order_count += 1;
        level.total_quantity = new_total;
    }

    fn detach_from_level(&mut self, order_slot: usize) {
        let node = self.orders[order_slot].expect("order detachment invariant");
        if let Some(previous) = node.previous {
            self.orders[previous]
                .as_mut()
                .expect("previous order invariant")
                .next = node.next;
        }
        if let Some(next) = node.next {
            self.orders[next]
                .as_mut()
                .expect("next order invariant")
                .previous = node.previous;
        }
        let level = self.levels[node.level_slot]
            .as_mut()
            .expect("order level invariant");
        if level.head == Some(order_slot) {
            level.head = node.next;
        }
        if level.tail == Some(order_slot) {
            level.tail = node.previous;
        }
        level.order_count -= 1;
        level.total_quantity = Quantity(level.total_quantity.0 - node.order.quantity.0);
        let detached = self.orders[order_slot]
            .as_mut()
            .expect("detached order invariant");
        detached.previous = None;
        detached.next = None;
    }

    fn remove_order_slot(&mut self, order_slot: usize) {
        let node = self.orders[order_slot]
            .take()
            .expect("live order invariant");
        self.order_index.remove_bucket(node.index_bucket);
        self.order_free_next[order_slot] = self.order_free_head;
        self.order_free_head = Some(order_slot);
        self.order_count -= 1;
    }

    fn remove_empty_level(&mut self, level_slot: usize) {
        let level = self.levels[level_slot]
            .take()
            .expect("live level invariant");
        debug_assert_eq!(level.order_count, 0);
        debug_assert_eq!(level.total_quantity, Quantity::ZERO);
        self.level_index.remove_bucket(level.index_bucket);
        self.level_free_next[level_slot] = self.level_free_head;
        self.level_free_head = Some(level_slot);
        self.level_count -= 1;

        let removed_best = match level.key.side {
            Side::Buy => self.best_bid_slot == Some(level_slot),
            Side::Sell => self.best_ask_slot == Some(level_slot),
        };
        if removed_best {
            self.recompute_best(level.key.side);
        }
    }

    fn recompute_best(&mut self, side: Side) {
        let mut best_slot: Option<usize> = None;
        let mut visits = 0;
        for (slot, level) in self.levels.iter().enumerate() {
            visits += 1;
            let Some(candidate) = level else {
                continue;
            };
            if candidate.key.side != side {
                continue;
            }
            let improves = best_slot.is_none_or(|current_slot| {
                let current = self.levels[current_slot].expect("best candidate invariant");
                match side {
                    Side::Buy => candidate.key.price > current.key.price,
                    Side::Sell => candidate.key.price < current.key.price,
                }
            });
            if improves {
                best_slot = Some(slot);
            }
        }
        match side {
            Side::Buy => self.best_bid_slot = best_slot,
            Side::Sell => self.best_ask_slot = best_slot,
        }
        self.last_best_recompute_visits = visits;
    }
}
