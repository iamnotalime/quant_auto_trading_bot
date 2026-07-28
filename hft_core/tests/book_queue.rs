use quant_hft_core::book::{ApplyOutcome, BookError, BookEvent, L3Book};
use quant_hft_core::queue::{
    ExactQueuePosition, QueueAction, QueueError, QueuePolicy, QueuePosition, QueueStatus,
};
use quant_hft_core::{OrderId, PriceTicks, Quantity, Sequence, Side};

fn add<const MAX_ORDERS: usize, const MAX_LEVELS: usize>(
    book: &mut L3Book<MAX_ORDERS, MAX_LEVELS>,
    sequence: u64,
    id: u64,
    side: Side,
    price: i64,
    quantity: i64,
) {
    book.apply(
        Sequence(sequence),
        BookEvent::Add {
            order_id: OrderId(id),
            side,
            price: PriceTicks(price),
            quantity: Quantity(quantity),
        },
    )
    .expect("valid add");
}

#[test]
fn book_aggregates_levels_and_enforces_price_time_priority() {
    let mut book = L3Book::<8, 6>::new(Sequence(10));
    add(&mut book, 10, 1, Side::Buy, 100, 30);
    add(&mut book, 11, 2, Side::Buy, 100, 40);
    add(&mut book, 12, 3, Side::Buy, 99, 50);
    add(&mut book, 13, 4, Side::Sell, 101, 25);

    let bid = book.best_bid().expect("best bid");
    assert_eq!(bid.price, PriceTicks(100));
    assert_eq!(bid.total_quantity, Quantity(70));
    assert_eq!(bid.order_count, 2);
    assert_eq!(book.best_ask().expect("best ask").price, PriceTicks(101));
    assert_eq!(
        book.front_order(Side::Buy, PriceTicks(100))
            .expect("front")
            .id,
        OrderId(1)
    );

    let modified = book
        .apply(
            Sequence(14),
            BookEvent::Modify {
                order_id: OrderId(1),
                price: PriceTicks(100),
                quantity: Quantity(20),
            },
        )
        .expect("replace");
    let ApplyOutcome::Modified { previous, current } = modified else {
        panic!("expected modify outcome");
    };
    assert!(current.priority > previous.priority);
    assert_eq!(
        book.front_order(Side::Buy, PriceTicks(100))
            .expect("new front")
            .id,
        OrderId(2),
        "replace must lose queue priority"
    );
    assert_eq!(
        book.level(Side::Buy, PriceTicks(100))
            .expect("level")
            .total_quantity,
        Quantity(60)
    );

    let partial = book
        .apply(
            Sequence(15),
            BookEvent::Execute {
                order_id: OrderId(2),
                quantity: Quantity(15),
            },
        )
        .expect("partial execute");
    assert_eq!(
        partial,
        ApplyOutcome::Executed {
            order_id: OrderId(2),
            executed: Quantity(15),
            remaining: Quantity(25),
        }
    );
    assert_eq!(
        book.order(OrderId(2)).expect("remaining").quantity,
        Quantity(25)
    );

    book.apply(
        Sequence(16),
        BookEvent::Execute {
            order_id: OrderId(2),
            quantity: Quantity(25),
        },
    )
    .expect("full execute");
    assert!(book.order(OrderId(2)).is_none());
    assert_eq!(book.order_count(), 3);
    assert_eq!(book.level_count(), 3);

    book.apply(
        Sequence(17),
        BookEvent::Cancel {
            order_id: OrderId(3),
        },
    )
    .expect("cancel");
    let cleared = book.apply(Sequence(18), BookEvent::Clear).expect("clear");
    assert_eq!(cleared, ApplyOutcome::Cleared { removed_orders: 2 });
    assert_eq!(book.order_count(), 0);
    assert_eq!(book.level_count(), 0);
    assert_eq!(book.expected_sequence(), Sequence(19));
}

#[test]
fn sequence_gap_latches_until_explicit_snapshot_reset() {
    let mut book = L3Book::<8, 6>::new(Sequence(100));
    add(&mut book, 100, 1, Side::Buy, 100, 10);
    let error = book
        .apply(
            Sequence(102),
            BookEvent::Cancel {
                order_id: OrderId(1),
            },
        )
        .expect_err("sequence gap must fail");
    assert_eq!(
        error,
        BookError::SequenceMismatch {
            expected: Sequence(101),
            received: Sequence(102),
        }
    );
    assert!(!book.is_synchronized());
    assert!(book.order(OrderId(1)).is_some(), "gap cannot mutate state");
    assert_eq!(
        book.apply(Sequence(101), BookEvent::Clear),
        Err(BookError::Desynchronized)
    );

    book.reset_from_snapshot(Sequence(500));
    assert!(book.is_synchronized());
    assert_eq!(book.order_count(), 0);
    add(&mut book, 500, 9, Side::Sell, 105, 12);
}

#[test]
fn invalid_crossed_and_capacity_events_fail_closed_without_partial_mutation() {
    let mut crossed = L3Book::<8, 6>::new(Sequence(1));
    add(&mut crossed, 1, 1, Side::Sell, 101, 10);
    assert_eq!(
        crossed.apply(
            Sequence(2),
            BookEvent::Add {
                order_id: OrderId(2),
                side: Side::Buy,
                price: PriceTicks(101),
                quantity: Quantity(10),
            },
        ),
        Err(BookError::CrossedBook {
            side: Side::Buy,
            price: PriceTicks(101),
            opposite_best: PriceTicks(101),
        })
    );
    assert_eq!(crossed.order_count(), 1);
    assert!(!crossed.is_synchronized());

    let mut invalid = L3Book::<2, 2>::new(Sequence(7));
    assert_eq!(
        invalid.apply(
            Sequence(7),
            BookEvent::Add {
                order_id: OrderId(1),
                side: Side::Buy,
                price: PriceTicks(100),
                quantity: Quantity(0),
            },
        ),
        Err(BookError::InvalidQuantity(Quantity(0)))
    );
    assert_eq!(invalid.order_count(), 0);

    let mut order_full = L3Book::<1, 2>::new(Sequence(20));
    order_full
        .apply(
            Sequence(20),
            BookEvent::Add {
                order_id: OrderId(1),
                side: Side::Buy,
                price: PriceTicks(100),
                quantity: Quantity(10),
            },
        )
        .expect("first order");
    assert_eq!(
        order_full.apply(
            Sequence(21),
            BookEvent::Add {
                order_id: OrderId(2),
                side: Side::Buy,
                price: PriceTicks(100),
                quantity: Quantity(10),
            },
        ),
        Err(BookError::OrderCapacity { capacity: 1 })
    );
    assert_eq!(order_full.order_count(), 1);
    assert_eq!(
        order_full
            .level(Side::Buy, PriceTicks(100))
            .expect("unchanged")
            .total_quantity,
        Quantity(10)
    );

    let mut level_full = L3Book::<3, 1>::new(Sequence(30));
    level_full
        .apply(
            Sequence(30),
            BookEvent::Add {
                order_id: OrderId(1),
                side: Side::Buy,
                price: PriceTicks(100),
                quantity: Quantity(10),
            },
        )
        .expect("first level");
    assert_eq!(
        level_full.apply(
            Sequence(31),
            BookEvent::Add {
                order_id: OrderId(2),
                side: Side::Buy,
                price: PriceTicks(99),
                quantity: Quantity(10),
            },
        ),
        Err(BookError::LevelCapacity { capacity: 1 })
    );
    assert_eq!(level_full.level_count(), 1);

    let mut overflow = L3Book::<3, 2>::new(Sequence(40));
    overflow
        .apply(
            Sequence(40),
            BookEvent::Add {
                order_id: OrderId(1),
                side: Side::Buy,
                price: PriceTicks(100),
                quantity: Quantity(i64::MAX),
            },
        )
        .expect("maximum aggregate");
    assert_eq!(
        overflow.apply(
            Sequence(41),
            BookEvent::Add {
                order_id: OrderId(2),
                side: Side::Buy,
                price: PriceTicks(100),
                quantity: Quantity(1),
            },
        ),
        Err(BookError::QuantityOverflow)
    );
    assert_eq!(overflow.order_count(), 1);
}

#[test]
fn execute_overrun_and_unknown_order_are_hard_faults() {
    let mut overrun = L3Book::<4, 4>::new(Sequence(1));
    overrun
        .apply(
            Sequence(1),
            BookEvent::Add {
                order_id: OrderId(1),
                side: Side::Buy,
                price: PriceTicks(100),
                quantity: Quantity(5),
            },
        )
        .expect("add");
    assert_eq!(
        overrun.apply(
            Sequence(2),
            BookEvent::Execute {
                order_id: OrderId(1),
                quantity: Quantity(6),
            },
        ),
        Err(BookError::ExecuteExceedsRemaining {
            order_id: OrderId(1),
            requested: Quantity(6),
            remaining: Quantity(5),
        })
    );
    assert_eq!(
        overrun.order(OrderId(1)).expect("unchanged").quantity,
        Quantity(5)
    );

    let mut unknown = L3Book::<4, 4>::new(Sequence(9));
    assert_eq!(
        unknown.apply(
            Sequence(9),
            BookEvent::Cancel {
                order_id: OrderId(77),
            },
        ),
        Err(BookError::UnknownOrder(OrderId(77)))
    );
    assert!(!unknown.is_synchronized());
}

#[test]
fn conservative_queue_advances_only_on_trades_and_supports_partial_fills() {
    let mut queue = QueuePosition::new(
        OrderId(500),
        Side::Buy,
        PriceTicks(100),
        Quantity(20),
        Quantity(100),
        QueuePolicy::Conservative,
    )
    .expect("queue");

    let cancellation = queue
        .on_cancel(PriceTicks(100), Quantity(80))
        .expect("cancel observation");
    assert_eq!(cancellation.action, QueueAction::CancelAssumedBehind);
    assert_eq!(queue.queue_ahead(), Quantity(100));

    let unrelated = queue
        .on_trade(PriceTicks(99), Quantity(1_000))
        .expect("unrelated trade");
    assert_eq!(unrelated.action, QueueAction::UnrelatedTrade);
    assert_eq!(queue.queue_ahead(), Quantity(100));

    let advance = queue
        .on_trade(PriceTicks(100), Quantity(60))
        .expect("advance");
    assert_eq!(advance.filled_quantity, Quantity::ZERO);
    assert_eq!(queue.queue_ahead(), Quantity(40));

    let partial = queue
        .on_trade(PriceTicks(100), Quantity(50))
        .expect("partial fill");
    assert_eq!(partial.filled_quantity, Quantity(10));
    assert_eq!(partial.remaining_quantity, Quantity(10));
    assert_eq!(partial.status, QueueStatus::Active);
    assert_eq!(queue.queue_ahead(), Quantity::ZERO);

    let full = queue
        .on_trade(PriceTicks(100), Quantity(10))
        .expect("full fill");
    assert_eq!(full.filled_quantity, Quantity(10));
    assert_eq!(full.remaining_quantity, Quantity::ZERO);
    assert_eq!(full.status, QueueStatus::Filled);
    assert_eq!(
        queue.on_trade(PriceTicks(100), Quantity(1)),
        Err(QueueError::Inactive(QueueStatus::Filled))
    );
}

#[test]
fn replace_resets_displayed_depth_and_loses_priority_generation() {
    let mut queue = QueuePosition::new(
        OrderId(7),
        Side::Sell,
        PriceTicks(105),
        Quantity(15),
        Quantity(40),
        QueuePolicy::Conservative,
    )
    .expect("queue");
    queue
        .on_trade(PriceTicks(105), Quantity(25))
        .expect("advance");
    assert_eq!(queue.queue_ahead(), Quantity(15));

    let replaced = queue
        .replace(PriceTicks(104), Quantity(30), Quantity(90))
        .expect("replace");
    assert_eq!(replaced.action, QueueAction::ReplacedLostPriority);
    assert_eq!(replaced.generation, 2);
    assert_eq!(queue.price(), PriceTicks(104));
    assert_eq!(queue.queue_ahead(), Quantity(90));
    assert_eq!(queue.remaining_quantity(), Quantity(30));

    let canceled = queue.cancel().expect("own cancel");
    assert_eq!(canceled.status, QueueStatus::Canceled);
    assert_eq!(
        queue.replace(PriceTicks(104), Quantity(1), Quantity::ZERO),
        Err(QueueError::Inactive(QueueStatus::Canceled))
    );
}

#[test]
fn queue_initializes_from_book_depth_and_cancels_do_not_optimistically_advance() {
    let mut book = L3Book::<8, 6>::new(Sequence(1));
    add(&mut book, 1, 1, Side::Buy, 100, 30);
    add(&mut book, 2, 2, Side::Buy, 100, 40);
    let displayed = book
        .level(Side::Buy, PriceTicks(100))
        .expect("displayed level")
        .total_quantity;
    let mut queue = QueuePosition::new(
        OrderId(900),
        Side::Buy,
        PriceTicks(100),
        Quantity(10),
        displayed,
        QueuePolicy::Conservative,
    )
    .expect("passive queue");
    assert_eq!(queue.queue_ahead(), Quantity(70));

    book.apply(
        Sequence(3),
        BookEvent::Execute {
            order_id: OrderId(1),
            quantity: Quantity(30),
        },
    )
    .expect("venue trade");
    queue
        .on_trade(PriceTicks(100), Quantity(30))
        .expect("queue trade");
    assert_eq!(queue.queue_ahead(), Quantity(40));

    book.apply(
        Sequence(4),
        BookEvent::Cancel {
            order_id: OrderId(2),
        },
    )
    .expect("venue cancel");
    queue
        .on_cancel(PriceTicks(100), Quantity(40))
        .expect("conservative cancel");
    assert!(book.level(Side::Buy, PriceTicks(100)).is_none());
    assert_eq!(
        queue.queue_ahead(),
        Quantity(40),
        "anonymous cancellation must not grant optimistic advancement"
    );
}

#[test]
fn queue_rejects_invalid_signed_inputs() {
    assert_eq!(
        QueuePosition::new(
            OrderId(1),
            Side::Buy,
            PriceTicks(100),
            Quantity(10),
            Quantity(-1),
            QueuePolicy::Conservative,
        ),
        Err(QueueError::InvalidDisplayedDepth(Quantity(-1)))
    );
    assert_eq!(
        QueuePosition::new(
            OrderId(0),
            Side::Buy,
            PriceTicks(100),
            Quantity(10),
            Quantity::ZERO,
            QueuePolicy::Conservative,
        ),
        Err(QueueError::InvalidOrderId)
    );
}

#[test]
fn exact_mbo_queue_tracks_identified_ahead_orders_and_own_fills() {
    let mut book = L3Book::<16, 8>::new(Sequence(1));
    add(&mut book, 1, 1, Side::Buy, 100, 30);
    add(&mut book, 2, 2, Side::Buy, 100, 40);
    add(&mut book, 3, 99, Side::Buy, 100, 10);

    let mut queue = ExactQueuePosition::<8>::from_visible_order(&book, OrderId(99))
        .expect("visible owned order");
    assert!(queue.own_visible());
    assert_eq!(queue.ahead_order_count(), 2);
    assert_eq!(queue.queue_ahead(), Quantity(70));
    assert_eq!(queue.ahead_quantity(OrderId(1)), Some(Quantity(30)));

    let partial = book
        .apply(
            Sequence(4),
            BookEvent::Execute {
                order_id: OrderId(1),
                quantity: Quantity(10),
            },
        )
        .expect("ahead partial execution");
    let update = queue
        .on_book_outcome(&book, partial)
        .expect("exact ahead execution");
    assert_eq!(update.action, QueueAction::AheadOrderExecuted);
    assert_eq!(queue.ahead_quantity(OrderId(1)), Some(Quantity(20)));
    assert_eq!(queue.queue_ahead(), Quantity(60));

    let canceled = book
        .apply(
            Sequence(5),
            BookEvent::Cancel {
                order_id: OrderId(2),
            },
        )
        .expect("ahead cancel");
    queue
        .on_book_outcome(&book, canceled)
        .expect("exact ahead cancel");
    assert_eq!(queue.ahead_order_count(), 1);
    assert_eq!(queue.queue_ahead(), Quantity(20));

    let behind = book
        .apply(
            Sequence(6),
            BookEvent::Add {
                order_id: OrderId(4),
                side: Side::Buy,
                price: PriceTicks(100),
                quantity: Quantity(1_000),
            },
        )
        .expect("later order");
    let update = queue
        .on_book_outcome(&book, behind)
        .expect("later order remains behind");
    assert_eq!(update.action, QueueAction::BehindOrderEvent);
    assert_eq!(queue.queue_ahead(), Quantity(20));

    let own_fill = book
        .apply(
            Sequence(7),
            BookEvent::Execute {
                order_id: OrderId(99),
                quantity: Quantity(5),
            },
        )
        .expect("own partial fill");
    let update = queue
        .on_book_outcome(&book, own_fill)
        .expect("own exact fill");
    assert_eq!(update.action, QueueAction::OwnOrderExecuted);
    assert_eq!(update.filled_quantity, Quantity(5));
    assert_eq!(queue.remaining_quantity(), Quantity(5));
}

#[test]
fn exact_mbo_queue_merges_pre_echo_adds_and_rejects_optimistic_identity_guesses() {
    let mut book = L3Book::<16, 8>::new(Sequence(1));
    add(&mut book, 1, 1, Side::Sell, 105, 25);
    let mut queue = ExactQueuePosition::<8>::join_behind_book(
        &book,
        OrderId(99),
        Side::Sell,
        PriceTicks(105),
        Quantity(10),
    )
    .expect("pending owned order");
    assert!(!queue.own_visible());
    assert_eq!(queue.queue_ahead(), Quantity(25));

    let before_echo = book
        .apply(
            Sequence(2),
            BookEvent::Add {
                order_id: OrderId(2),
                side: Side::Sell,
                price: PriceTicks(105),
                quantity: Quantity(15),
            },
        )
        .expect("venue order before own echo");
    queue
        .on_book_outcome(&book, before_echo)
        .expect("pre-echo order is ahead");
    assert_eq!(queue.queue_ahead(), Quantity(40));

    let own_echo = book
        .apply(
            Sequence(3),
            BookEvent::Add {
                order_id: OrderId(99),
                side: Side::Sell,
                price: PriceTicks(105),
                quantity: Quantity(10),
            },
        )
        .expect("owned MBO echo");
    let update = queue
        .on_book_outcome(&book, own_echo)
        .expect("merge owned echo");
    assert_eq!(update.action, QueueAction::OwnOrderBecameVisible);
    assert!(queue.own_visible());
    assert_eq!(queue.queue_ahead(), Quantity(40));

    let bad = ApplyOutcome::Executed {
        order_id: OrderId(1),
        executed: Quantity(5),
        remaining: Quantity(999),
    };
    assert!(matches!(
        queue.on_book_outcome(&book, bad),
        Err(QueueError::AheadQuantityMismatch {
            order_id: OrderId(1),
            ..
        })
    ));
    assert_eq!(queue.status(), QueueStatus::Invalidated);
}

#[test]
fn exact_mbo_queue_replace_loses_priority_and_capacity_is_fail_closed() {
    let mut book = L3Book::<16, 8>::new(Sequence(1));
    add(&mut book, 1, 1, Side::Buy, 100, 30);
    add(&mut book, 2, 2, Side::Buy, 100, 40);
    add(&mut book, 3, 99, Side::Buy, 100, 10);

    assert!(matches!(
        ExactQueuePosition::<1>::from_visible_order(&book, OrderId(99)),
        Err(QueueError::AheadCapacity { capacity: 1 })
    ));

    let mut queue =
        ExactQueuePosition::<8>::from_visible_order(&book, OrderId(99)).expect("exact queue");
    let replacement = book
        .apply(
            Sequence(4),
            BookEvent::Modify {
                order_id: OrderId(1),
                price: PriceTicks(100),
                quantity: Quantity(50),
            },
        )
        .expect("ahead replace");
    let update = queue
        .on_book_outcome(&book, replacement)
        .expect("replace loses ahead priority");
    assert_eq!(update.action, QueueAction::AheadOrderReplacedLostPriority);
    assert_eq!(queue.ahead_order_count(), 1);
    assert_eq!(queue.ahead_quantity(OrderId(1)), None);
    assert_eq!(queue.queue_ahead(), Quantity(40));

    let own_replace = book
        .apply(
            Sequence(5),
            BookEvent::Modify {
                order_id: OrderId(99),
                price: PriceTicks(100),
                quantity: Quantity(12),
            },
        )
        .expect("own replace");
    let update = queue
        .on_book_outcome(&book, own_replace)
        .expect("rebuild exact prefix");
    assert_eq!(update.action, QueueAction::OwnOrderReplacedLostPriority);
    assert_eq!(queue.generation(), 2);
    assert_eq!(queue.queue_ahead(), Quantity(90));
    assert_eq!(queue.remaining_quantity(), Quantity(12));
}
