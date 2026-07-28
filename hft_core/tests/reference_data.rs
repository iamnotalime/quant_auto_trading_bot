use quant_hft_core::reference_data::{
    FixedInstrumentValue, InstrumentDefinition, InstrumentDefinitionError, InstrumentRuleViolation,
    NativeProductId, RationalScale, ReferenceDataAuthorityId, ReferenceDataDigest,
    SelfTradePreventionInstruction,
};
use quant_hft_core::{CurrencyId, InstrumentId, PriceTicks, Quantity, TimestampNs, VenueId};

const VENUE: VenueId = VenueId(7);
const INSTRUMENT: InstrumentId = InstrumentId(42);

const fn definition() -> InstrumentDefinition {
    InstrumentDefinition {
        venue: VENUE,
        instrument: INSTRUMENT,
        native_product: NativeProductId(9_001),
        authority: ReferenceDataAuthorityId(501),
        reference_data_version: 77,
        reference_data_digest: ReferenceDataDigest([0xA5; 32]),
        valid_from: TimestampNs(1_000),
        valid_until: TimestampNs(2_000),
        price_scale: RationalScale {
            numerator: 1,
            denominator: 100,
        },
        quantity_scale: RationalScale {
            numerator: 1,
            denominator: 1_000,
        },
        fixed_value: FixedInstrumentValue {
            settlement_currency: CurrencyId(840),
            settlement_units_per_price_tick: 25,
            contract_multiplier: 10,
        },
        minimum_price: PriceTicks(10),
        maximum_price: PriceTicks(1_000),
        price_increment: PriceTicks(5),
        minimum_quantity: Quantity(10),
        maximum_quantity: Quantity(1_000),
        quantity_increment: Quantity(10),
        continuous_trading_status_code: 17,
        self_trade_prevention: SelfTradePreventionInstruction(3),
        cancel_on_disconnect_required: true,
    }
}

#[test]
fn exact_canonical_definition_and_boundary_economics_are_accepted() {
    let reference = definition();
    assert_eq!(reference.validate(), Ok(()));
    assert!(reference.is_continuous_trading(17));
    assert!(!reference.is_continuous_trading(16));
    for (price, quantity, observed) in [
        (PriceTicks(10), Quantity(10), TimestampNs(1_000)),
        (PriceTicks(1_000), Quantity(1_000), TimestampNs(2_000)),
        (PriceTicks(500), Quantity(500), TimestampNs(1_500)),
    ] {
        assert_eq!(
            reference.validate_order_economics(VENUE, INSTRUMENT, price, quantity, observed,),
            Ok(())
        );
    }
}

#[test]
fn absent_provenance_and_noncanonical_scales_are_rejected() {
    let mut candidate = definition();
    candidate.reference_data_digest = ReferenceDataDigest([0; 32]);
    assert_eq!(
        candidate.validate(),
        Err(InstrumentDefinitionError::InvalidReferenceDataDigest)
    );

    candidate = definition();
    candidate.price_scale = RationalScale {
        numerator: 2,
        denominator: 100,
    };
    assert_eq!(
        candidate.validate(),
        Err(InstrumentDefinitionError::InvalidPriceScale)
    );

    candidate = definition();
    candidate.valid_until = candidate.valid_from;
    assert_eq!(
        candidate.validate(),
        Err(InstrumentDefinitionError::InvalidValidityWindow)
    );

    candidate = definition();
    candidate.self_trade_prevention = SelfTradePreventionInstruction(0);
    assert_eq!(
        candidate.validate(),
        Err(InstrumentDefinitionError::InvalidSelfTradePrevention)
    );

    candidate = definition();
    candidate.fixed_value.settlement_currency = CurrencyId(0);
    assert_eq!(
        candidate.validate(),
        Err(InstrumentDefinitionError::InvalidFixedValue)
    );

    candidate = definition();
    candidate.fixed_value.settlement_units_per_price_tick = 0;
    assert_eq!(
        candidate.validate(),
        Err(InstrumentDefinitionError::InvalidFixedValue)
    );

    candidate = definition();
    candidate.fixed_value.contract_multiplier = 0;
    assert_eq!(
        candidate.validate(),
        Err(InstrumentDefinitionError::InvalidFixedValue)
    );

    candidate = definition();
    candidate.fixed_value.settlement_units_per_price_tick = i128::MAX;
    candidate.fixed_value.contract_multiplier = 2;
    assert_eq!(
        candidate.validate(),
        Err(InstrumentDefinitionError::InvalidFixedValue)
    );
}

#[test]
fn route_expiry_band_and_increment_drift_are_typed_failures() {
    let reference = definition();
    let economics = |venue, instrument, price, quantity, observed| {
        reference.validate_order_economics(venue, instrument, price, quantity, observed)
    };

    assert_eq!(
        economics(
            VenueId(8),
            INSTRUMENT,
            PriceTicks(100),
            Quantity(100),
            TimestampNs(1_500),
        ),
        Err(InstrumentRuleViolation::VenueMismatch {
            expected: VENUE,
            received: VenueId(8),
        })
    );
    assert_eq!(
        economics(
            VENUE,
            InstrumentId(43),
            PriceTicks(100),
            Quantity(100),
            TimestampNs(1_500),
        ),
        Err(InstrumentRuleViolation::InstrumentMismatch {
            expected: INSTRUMENT,
            received: InstrumentId(43),
        })
    );
    assert_eq!(
        economics(
            VENUE,
            INSTRUMENT,
            PriceTicks(100),
            Quantity(100),
            TimestampNs(2_001),
        ),
        Err(InstrumentRuleViolation::ReferenceDataNotEffective {
            valid_from: TimestampNs(1_000),
            valid_until: TimestampNs(2_000),
            observed: TimestampNs(2_001),
        })
    );
    assert_eq!(
        economics(
            VENUE,
            INSTRUMENT,
            PriceTicks(1_005),
            Quantity(100),
            TimestampNs(1_500),
        ),
        Err(InstrumentRuleViolation::PriceOutOfBounds {
            minimum: PriceTicks(10),
            maximum: PriceTicks(1_000),
            received: PriceTicks(1_005),
        })
    );
    assert_eq!(
        economics(
            VENUE,
            INSTRUMENT,
            PriceTicks(101),
            Quantity(100),
            TimestampNs(1_500),
        ),
        Err(InstrumentRuleViolation::PriceIncrementMismatch {
            increment: PriceTicks(5),
            received: PriceTicks(101),
        })
    );
    assert_eq!(
        economics(
            VENUE,
            INSTRUMENT,
            PriceTicks(100),
            Quantity(1_010),
            TimestampNs(1_500),
        ),
        Err(InstrumentRuleViolation::QuantityOutOfBounds {
            minimum: Quantity(10),
            maximum: Quantity(1_000),
            received: Quantity(1_010),
        })
    );
    assert_eq!(
        economics(
            VENUE,
            INSTRUMENT,
            PriceTicks(100),
            Quantity(101),
            TimestampNs(1_500),
        ),
        Err(InstrumentRuleViolation::QuantityIncrementMismatch {
            increment: Quantity(10),
            received: Quantity(101),
        })
    );
}
