use quant_hft_core::{
    ApplyOutcome, BookError, BookEvent, BookOrder, L3Book, OrderId, PriceTicks, Quantity, Sequence,
    Side,
};
use std::collections::BTreeMap;

const fn mix_u64(mut value: u64) -> u64 {
    value ^= value >> 30;
    value = value.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value ^= value >> 27;
    value = value.wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

fn order_bucket(id: u64, capacity: usize) -> usize {
    let capacity_u64 = u64::try_from(capacity).expect("test capacity fits u64");
    usize::try_from(mix_u64(id) % capacity_u64).expect("bucket fits usize")
}

fn level_bucket(side: Side, price: i64, capacity: usize) -> usize {
    let side_salt = match side {
        Side::Buy => 0x243f_6a88_85a3_08d3,
        Side::Sell => 0x1319_8a2e_0370_7344,
    };
    let price_bits = u64::from_ne_bytes(price.to_ne_bytes());
    let capacity_u64 = u64::try_from(capacity).expect("test capacity fits u64");
    usize::try_from(mix_u64(price_bits ^ side_salt) % capacity_u64).expect("bucket fits usize")
}

fn colliding_order_ids(capacity: usize, count: usize) -> Vec<u64> {
    let target = order_bucket(1, capacity);
    (1_u64..)
        .filter(|id| order_bucket(*id, capacity) == target)
        .take(count)
        .collect()
}

fn colliding_prices(side: Side, capacity: usize, count: usize) -> Vec<i64> {
    let target = level_bucket(side, 1, capacity);
    (1_i64..)
        .filter(|price| level_bucket(side, *price, capacity) == target)
        .take(count)
        .collect()
}

fn add<const ORDERS: usize, const LEVELS: usize>(
    book: &mut L3Book<ORDERS, LEVELS>,
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
    .expect("valid indexed add");
}

#[test]
fn order_index_survives_adversarial_collisions_tombstones_and_slot_reuse() {
    let ids = colliding_order_ids(16, 13);
    let mut book = L3Book::<16, 2>::new(Sequence(1));
    let mut sequence = 1_u64;
    for id in ids.iter().take(12) {
        add(&mut book, sequence, *id, Side::Buy, 100, 1);
        sequence += 1;
    }

    assert_eq!(book.diagnostic_order_lookup_probes(OrderId(ids[11])), 12);
    assert_eq!(
        book.front_order(Side::Buy, PriceTicks(100))
            .expect("front order")
            .id,
        OrderId(ids[0])
    );

    book.apply(
        Sequence(sequence),
        BookEvent::Cancel {
            order_id: OrderId(ids[0]),
        },
    )
    .expect("cancel collision-chain head");
    sequence += 1;
    assert_eq!(
        book.order(OrderId(ids[11]))
            .expect("tail survives tombstone")
            .id,
        OrderId(ids[11])
    );
    assert_eq!(book.diagnostic_order_lookup_probes(OrderId(ids[11])), 12);

    add(&mut book, sequence, ids[12], Side::Buy, 100, 1);
    assert_eq!(
        book.diagnostic_order_lookup_probes(OrderId(ids[12])),
        1,
        "insertion must reuse the first tombstone in the collision chain"
    );
    assert_eq!(
        book.front_order(Side::Buy, PriceTicks(100))
            .expect("next FIFO order")
            .id,
        OrderId(ids[1]),
        "reused storage must not grant queue priority"
    );
    assert_eq!(book.order_count(), 12);
    assert_eq!(
        book.level(Side::Buy, PriceTicks(100))
            .expect("aggregate")
            .total_quantity,
        Quantity(12)
    );
}

#[test]
fn level_index_survives_collisions_and_reuses_deleted_bucket() {
    let prices = colliding_prices(Side::Buy, 8, 6);
    let mut book = L3Book::<16, 8>::new(Sequence(10));
    let mut sequence = 10_u64;
    for (offset, price) in prices.iter().take(5).enumerate() {
        let id = u64::try_from(offset + 1).expect("small id");
        add(&mut book, sequence, id, Side::Buy, *price, 10);
        sequence += 1;
    }
    assert_eq!(
        book.diagnostic_level_lookup_probes(Side::Buy, PriceTicks(prices[4])),
        5
    );

    book.apply(
        Sequence(sequence),
        BookEvent::Cancel {
            order_id: OrderId(1),
        },
    )
    .expect("remove collision-chain head level");
    sequence += 1;
    assert!(book.level(Side::Buy, PriceTicks(prices[4])).is_some());
    assert_eq!(
        book.diagnostic_level_lookup_probes(Side::Buy, PriceTicks(prices[4])),
        5,
        "a tombstone must not terminate lookup"
    );

    add(&mut book, sequence, 99, Side::Buy, prices[5], 7);
    assert_eq!(
        book.diagnostic_level_lookup_probes(Side::Buy, PriceTicks(prices[5])),
        1,
        "new colliding level must reuse the leading tombstone"
    );
    assert_eq!(book.level_count(), 5);
}

#[test]
fn full_level_index_can_atomically_replace_its_only_level() {
    let mut book = L3Book::<1, 1>::new(Sequence(50));
    add(&mut book, 50, 1, Side::Buy, 100, 5);

    let outcome = book
        .apply(
            Sequence(51),
            BookEvent::Modify {
                order_id: OrderId(1),
                price: PriceTicks(99),
                quantity: Quantity(8),
            },
        )
        .expect("sole level can move despite a saturated level index");
    let ApplyOutcome::Modified { previous, current } = outcome else {
        panic!("expected modify outcome");
    };
    assert_eq!(previous.price, PriceTicks(100));
    assert_eq!(current.price, PriceTicks(99));
    assert!(book.level(Side::Buy, PriceTicks(100)).is_none());
    assert_eq!(
        book.level(Side::Buy, PriceTicks(99))
            .expect("replacement level")
            .total_quantity,
        Quantity(8)
    );
    assert_eq!(book.order_count(), 1);
    assert_eq!(book.level_count(), 1);
    assert!(book.is_synchronized());
}

#[test]
fn best_removal_is_bounded_and_fifo_links_preserve_priority() {
    let mut book = L3Book::<16, 8>::new(Sequence(1));
    add(&mut book, 1, 1, Side::Buy, 100, 10);
    add(&mut book, 2, 2, Side::Buy, 99, 20);
    add(&mut book, 3, 3, Side::Buy, 99, 30);
    add(&mut book, 4, 4, Side::Buy, 98, 40);
    add(&mut book, 5, 5, Side::Sell, 101, 50);
    add(&mut book, 6, 6, Side::Sell, 102, 60);

    book.apply(
        Sequence(7),
        BookEvent::Cancel {
            order_id: OrderId(1),
        },
    )
    .expect("delete best bid");
    assert_eq!(book.best_bid().expect("next bid").price, PriceTicks(99));
    assert_eq!(book.diagnostic_last_best_recompute_visits(), 8);

    book.apply(
        Sequence(8),
        BookEvent::Modify {
            order_id: OrderId(5),
            price: PriceTicks(103),
            quantity: Quantity(55),
        },
    )
    .expect("move best ask behind another ask");
    assert_eq!(book.best_ask().expect("next ask").price, PriceTicks(102));
    assert_eq!(book.diagnostic_last_best_recompute_visits(), 8);

    assert_eq!(
        book.front_order(Side::Buy, PriceTicks(99))
            .expect("initial front")
            .id,
        OrderId(2)
    );
    book.apply(
        Sequence(9),
        BookEvent::Modify {
            order_id: OrderId(2),
            price: PriceTicks(99),
            quantity: Quantity(25),
        },
    )
    .expect("replace loses priority");
    assert_eq!(
        book.front_order(Side::Buy, PriceTicks(99))
            .expect("new front")
            .id,
        OrderId(3)
    );
    book.apply(
        Sequence(10),
        BookEvent::Cancel {
            order_id: OrderId(3),
        },
    )
    .expect("unlink FIFO head");
    assert_eq!(
        book.front_order(Side::Buy, PriceTicks(99))
            .expect("remaining order")
            .id,
        OrderId(2)
    );
    let level = book
        .level(Side::Buy, PriceTicks(99))
        .expect("remaining level");
    assert_eq!(level.order_count, 1);
    assert_eq!(level.total_quantity, Quantity(25));
}

#[test]
fn saturated_order_index_fails_without_partial_book_mutation() {
    let ids = colliding_order_ids(4, 5);
    let mut book = L3Book::<4, 1>::new(Sequence(1));
    for (offset, id) in ids.iter().take(4).enumerate() {
        add(
            &mut book,
            u64::try_from(offset + 1).expect("small sequence"),
            *id,
            Side::Buy,
            100,
            2,
        );
    }
    let before = book.level(Side::Buy, PriceTicks(100));
    let error = book
        .apply(
            Sequence(5),
            BookEvent::Add {
                order_id: OrderId(ids[4]),
                side: Side::Buy,
                price: PriceTicks(100),
                quantity: Quantity(9),
            },
        )
        .expect_err("fifth order exceeds capacity");
    assert_eq!(error, BookError::OrderCapacity { capacity: 4 });
    assert_eq!(book.order_count(), 4);
    assert_eq!(book.level(Side::Buy, PriceTicks(100)), before);
    assert!(book.order(OrderId(ids[4])).is_none());
    assert!(!book.is_synchronized());
}

fn direct_bucket_probe_count<const ORDERS: usize>() -> usize {
    let target_count = ORDERS / 2;
    let mut occupied = vec![false; ORDERS];
    let mut ids = Vec::with_capacity(target_count);
    for id in 1_u64.. {
        let bucket = order_bucket(id, ORDERS);
        if !occupied[bucket] {
            occupied[bucket] = true;
            ids.push(id);
            if ids.len() == target_count {
                break;
            }
        }
    }

    let mut book = L3Book::<ORDERS, 1>::new(Sequence(1));
    for (offset, id) in ids.iter().enumerate() {
        add(
            &mut book,
            u64::try_from(offset + 1).expect("bounded sequence"),
            *id,
            Side::Buy,
            100,
            1,
        );
    }
    let target = *ids.last().expect("nonempty test population");
    assert!(book.order(OrderId(target)).is_some());
    book.diagnostic_order_lookup_probes(OrderId(target))
}

#[test]
fn indexed_lookup_work_does_not_scale_with_order_capacity() {
    assert_eq!(direct_bucket_probe_count::<32>(), 1);
    assert_eq!(direct_bucket_probe_count::<1024>(), 1);
}

#[derive(Clone, Copy, Debug)]
struct ReferenceOrder {
    price: i64,
    quantity: i64,
    priority: u64,
}

fn next_random(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    *state
}

fn select_reference_order(
    orders: &BTreeMap<u64, ReferenceOrder>,
    random: u64,
) -> (u64, ReferenceOrder) {
    let len_u64 = u64::try_from(orders.len()).expect("reference size fits u64");
    let index = usize::try_from(random % len_u64).expect("reference index fits usize");
    let (&id, &order) = orders.iter().nth(index).expect("selected order exists");
    (id, order)
}

fn assert_matches_reference(
    book: &L3Book<64, 16>,
    orders: &BTreeMap<u64, ReferenceOrder>,
    expected_sequence: u64,
) {
    assert_eq!(book.order_count(), orders.len());
    assert_eq!(book.expected_sequence(), Sequence(expected_sequence));
    assert!(book.is_synchronized());

    let mut levels: BTreeMap<i64, (i64, usize, u64, u64)> = BTreeMap::new();
    for (&id, order) in orders {
        assert_eq!(
            book.order(OrderId(id)),
            Some(BookOrder {
                id: OrderId(id),
                side: Side::Buy,
                price: PriceTicks(order.price),
                quantity: Quantity(order.quantity),
                priority: order.priority,
            })
        );
        levels
            .entry(order.price)
            .and_modify(|(quantity, count, front_priority, front_id)| {
                *quantity += order.quantity;
                *count += 1;
                if order.priority < *front_priority {
                    *front_priority = order.priority;
                    *front_id = id;
                }
            })
            .or_insert((order.quantity, 1, order.priority, id));
    }
    assert_eq!(book.level_count(), levels.len());

    for price in 90_i64..98 {
        match levels.get(&price) {
            Some(&(quantity, count, _, front_id)) => {
                let level = book
                    .level(Side::Buy, PriceTicks(price))
                    .expect("reference level exists");
                assert_eq!(level.total_quantity, Quantity(quantity));
                assert_eq!(level.order_count, count);
                assert_eq!(
                    book.front_order(Side::Buy, PriceTicks(price))
                        .expect("reference front exists")
                        .id,
                    OrderId(front_id)
                );
            }
            None => assert!(book.level(Side::Buy, PriceTicks(price)).is_none()),
        }
    }

    let expected_best = levels.last_key_value().map(|(&price, _)| PriceTicks(price));
    assert_eq!(book.best_bid().map(|level| level.price), expected_best);
    assert!(book.best_ask().is_none());
}

#[test]
fn deterministic_randomized_stream_matches_reference_model() {
    let mut book = L3Book::<64, 16>::new(Sequence(1));
    let mut orders = BTreeMap::<u64, ReferenceOrder>::new();
    let mut random_state = 0x7f4a_7c15_d1ce_b00c_u64;
    let mut sequence = 1_u64;
    let mut next_id = 1_u64;
    let mut next_priority = 1_u64;

    for _ in 0..5_000 {
        let choice = next_random(&mut random_state) % 100;
        if orders.is_empty() || (choice < 30 && orders.len() < 48) {
            let price_random = next_random(&mut random_state) % 8;
            let quantity_random = next_random(&mut random_state) % 1_000;
            let price = 90 + i64::try_from(price_random).expect("bounded price");
            let quantity = 1 + i64::try_from(quantity_random).expect("bounded quantity");
            add(&mut book, sequence, next_id, Side::Buy, price, quantity);
            orders.insert(
                next_id,
                ReferenceOrder {
                    price,
                    quantity,
                    priority: next_priority,
                },
            );
            next_id += 1;
            next_priority += 1;
        } else if choice < 55 {
            let selection = next_random(&mut random_state);
            let (id, _) = select_reference_order(&orders, selection);
            let price_random = next_random(&mut random_state) % 8;
            let quantity_random = next_random(&mut random_state) % 1_000;
            let price = 90 + i64::try_from(price_random).expect("bounded price");
            let quantity = 1 + i64::try_from(quantity_random).expect("bounded quantity");
            book.apply(
                Sequence(sequence),
                BookEvent::Modify {
                    order_id: OrderId(id),
                    price: PriceTicks(price),
                    quantity: Quantity(quantity),
                },
            )
            .expect("valid reference modify");
            orders.insert(
                id,
                ReferenceOrder {
                    price,
                    quantity,
                    priority: next_priority,
                },
            );
            next_priority += 1;
        } else if choice < 78 {
            let selection = next_random(&mut random_state);
            let (id, reference) = select_reference_order(&orders, selection);
            let quantity_random = next_random(&mut random_state);
            let reference_quantity =
                u64::try_from(reference.quantity).expect("positive reference quantity");
            let executed_u64 = 1 + quantity_random % reference_quantity;
            let executed = i64::try_from(executed_u64).expect("execution fits i64");
            book.apply(
                Sequence(sequence),
                BookEvent::Execute {
                    order_id: OrderId(id),
                    quantity: Quantity(executed),
                },
            )
            .expect("valid reference execute");
            if executed == reference.quantity {
                orders.remove(&id);
            } else {
                orders.insert(
                    id,
                    ReferenceOrder {
                        quantity: reference.quantity - executed,
                        ..reference
                    },
                );
            }
        } else if choice < 96 {
            let selection = next_random(&mut random_state);
            let (id, _) = select_reference_order(&orders, selection);
            book.apply(
                Sequence(sequence),
                BookEvent::Cancel {
                    order_id: OrderId(id),
                },
            )
            .expect("valid reference cancel");
            orders.remove(&id);
        } else {
            book.apply(Sequence(sequence), BookEvent::Clear)
                .expect("valid reference clear");
            orders.clear();
            next_priority = 1;
        }
        sequence += 1;
        assert_matches_reference(&book, &orders, sequence);
    }
}
