use quant_hft_core::ownership::{OwnedMboRegistry, OwnershipBindOutcome, OwnershipError};
use quant_hft_core::types::{Sequence, VenueId};
use quant_hft_core::venue::{
    ClientOrderId, MarketByOrderId, OwnedMboBinding, OwnedMboBindingMethod, VenueOrderId,
};

fn binding(client: u64, private: u64, public: u64) -> OwnedMboBinding {
    OwnedMboBinding {
        venue: VenueId(7),
        client_order_id: ClientOrderId(client),
        venue_order_id: VenueOrderId(private),
        market_by_order_id: MarketByOrderId(public),
        order_entry_sequence: Sequence(client),
        method: OwnedMboBindingMethod::CertifiedDeterministicRule { rule_id: 19 },
    }
}

#[test]
fn numeric_id_equality_never_creates_implicit_ownership() {
    let mut registry = OwnedMboRegistry::<2>::new();
    assert_eq!(registry.by_client(ClientOrderId(11)), None);
    assert_eq!(registry.by_venue_order(VenueOrderId(11)), None);
    assert_eq!(registry.by_market_order(MarketByOrderId(11)), None);

    let explicit = binding(11, 11, 11);
    assert_eq!(registry.bind(explicit), Ok(OwnershipBindOutcome::Inserted));
    assert_eq!(registry.by_client(ClientOrderId(11)), Some(explicit));
    assert_eq!(registry.by_venue_order(VenueOrderId(11)), Some(explicit));
    assert_eq!(
        registry.by_market_order(MarketByOrderId(11)),
        Some(explicit)
    );
    assert_eq!(registry.bind(explicit), Ok(OwnershipBindOutcome::Duplicate));
}

#[test]
fn every_namespace_is_one_to_one_and_collision_failures_are_atomic() {
    let mut registry = OwnedMboRegistry::<3>::new();
    let first = binding(1, 101, 201);
    registry.bind(first).unwrap();

    assert!(matches!(
        registry.bind(binding(1, 102, 202)),
        Err(OwnershipError::ClientCollision { .. })
    ));
    assert!(matches!(
        registry.bind(binding(2, 101, 202)),
        Err(OwnershipError::VenueOrderCollision { .. })
    ));
    assert!(matches!(
        registry.bind(binding(2, 102, 201)),
        Err(OwnershipError::MarketByOrderCollision { .. })
    ));
    assert_eq!(registry.len(), 1);
    assert_eq!(registry.by_client(ClientOrderId(1)), Some(first));
    assert_eq!(registry.by_client(ClientOrderId(2)), None);
}

#[test]
fn capacity_and_removal_preserve_all_three_indexes() {
    let mut registry = OwnedMboRegistry::<1>::new();
    let first = binding(1, 101, 201);
    registry.bind(first).unwrap();
    assert_eq!(
        registry.bind(binding(2, 102, 202)),
        Err(OwnershipError::Capacity { capacity: 1 })
    );
    assert_eq!(registry.len(), 1);

    assert_eq!(registry.remove_by_client(ClientOrderId(1)), Ok(Some(first)));
    assert!(registry.is_empty());
    assert_eq!(registry.by_venue_order(VenueOrderId(101)), None);
    assert_eq!(registry.by_market_order(MarketByOrderId(201)), None);

    let second = binding(2, 102, 202);
    assert_eq!(registry.bind(second), Ok(OwnershipBindOutcome::Inserted));
    assert_eq!(registry.remove_by_client(ClientOrderId(99)), Ok(None));
    assert_eq!(registry.by_client(ClientOrderId(2)), Some(second));
}

#[test]
fn invalid_binding_methods_and_zero_identifiers_are_rejected() {
    let mut registry = OwnedMboRegistry::<1>::new();
    let mut invalid = binding(1, 2, 3);
    invalid.method = OwnedMboBindingMethod::CertifiedDeterministicRule { rule_id: 0 };
    assert_eq!(registry.bind(invalid), Err(OwnershipError::InvalidBinding));
    invalid = binding(1, 2, 3);
    invalid.market_by_order_id = MarketByOrderId(0);
    assert_eq!(registry.bind(invalid), Err(OwnershipError::InvalidBinding));
    assert!(registry.is_empty());
}
