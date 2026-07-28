//! Immutable, allocation-free venue instrument reference data.
//!
//! The core does not invent venue economics. A deployment must populate this
//! definition from an authenticated, licensed reference-data artifact and bind the
//! artifact digest through its deployment/recovery seal. The digest is an identity,
//! not a signature verifier. Native adapters remain responsible for proving the
//! external artifact's authenticity before constructing the live process.

use crate::types::{CurrencyId, InstrumentId, PriceTicks, Quantity, TimestampNs, VenueId};

/// Venue-native stable product identifier, or an authoritative adapter mapping key
/// when the wire identifier is not numeric. Zero is reserved for "not configured".
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct NativeProductId(pub u64);

/// Identity of the authority that issued the reference-data artifact.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct ReferenceDataAuthorityId(pub u64);

/// Digest of the exact authenticated reference-data artifact.
///
/// This value provides immutable identity inside the core; it does not by itself
/// authenticate the artifact. All-zero is invalid and reserved for absent evidence.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct ReferenceDataDigest(pub [u8; 32]);

impl ReferenceDataDigest {
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

/// Exact reduced rational mapping from one normalized core unit to native product
/// units. Both terms are positive and the fraction must be in canonical form.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct RationalScale {
    pub numerator: u64,
    pub denominator: u64,
}

impl RationalScale {
    #[must_use]
    pub const fn is_valid(self) -> bool {
        self.numerator != 0
            && self.denominator != 0
            && greatest_common_divisor(self.numerator, self.denominator) == 1
    }
}

/// Exact venue-native self-trade-prevention instruction selected for every new
/// order on this instrument. Zero is reserved for no/unknown protection.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct SelfTradePreventionInstruction(pub u16);

/// Venue-authenticated fixed linear value mapping for one normalized contract.
///
/// The current risk core supports no dynamic FX. A live engine can therefore use
/// this product only when `settlement_currency` is also its risk base currency and
/// both integer valuation terms match exactly. The currency identifier includes the
/// deployment's atomic-unit convention.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FixedInstrumentValue {
    pub settlement_currency: CurrencyId,
    /// Settlement-currency atomic units for one normalized price tick and one
    /// underlying unit.
    pub settlement_units_per_price_tick: i128,
    /// Underlying units represented by one normalized risk quantity/contract.
    pub contract_multiplier: u64,
}

impl FixedInstrumentValue {
    #[must_use]
    pub const fn is_valid(self) -> bool {
        self.settlement_currency.0 != 0
            && self.settlement_units_per_price_tick > 0
            && self.contract_multiplier != 0
            && self
                .settlement_units_per_price_tick
                .checked_mul(self.contract_multiplier as i128)
                .is_some()
    }
}

/// Compact immutable identity sealed into live recovery state. The digest names the
/// exact authenticated artifact from which all economics were decoded; the remaining
/// fields prevent cross-authority, cross-version, and cross-product substitution.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct InstrumentDefinitionBinding {
    pub venue: VenueId,
    pub instrument: InstrumentId,
    pub native_product: NativeProductId,
    pub authority: ReferenceDataAuthorityId,
    pub reference_data_version: u64,
    pub reference_data_digest: ReferenceDataDigest,
}

impl InstrumentDefinitionBinding {
    #[must_use]
    pub const fn is_valid(self) -> bool {
        self.venue.0 != 0
            && self.instrument.0 != 0
            && self.native_product.0 != 0
            && self.authority.0 != 0
            && self.reference_data_version != 0
            && self.reference_data_digest.is_valid()
    }
}

/// Immutable effective-dated economics for one exact venue product.
///
/// Prices and quantities remain normalized integers on the hot path. The rational
/// scales state their exact native meaning, while bounds and increments constrain
/// every value that may influence or enter an order. Updating bands or economics
/// requires a newly authenticated definition and a clean restart/recovery binding;
/// an expired definition simply becomes ineligible.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InstrumentDefinition {
    pub venue: VenueId,
    pub instrument: InstrumentId,
    pub native_product: NativeProductId,
    pub authority: ReferenceDataAuthorityId,
    pub reference_data_version: u64,
    pub reference_data_digest: ReferenceDataDigest,
    pub valid_from: TimestampNs,
    pub valid_until: TimestampNs,
    pub price_scale: RationalScale,
    pub quantity_scale: RationalScale,
    /// Authenticated currency, tick value, and contract-size economics. This is
    /// checked exactly against the independently configured risk definition.
    pub fixed_value: FixedInstrumentValue,
    pub minimum_price: PriceTicks,
    pub maximum_price: PriceTicks,
    pub price_increment: PriceTicks,
    pub minimum_quantity: Quantity,
    pub maximum_quantity: Quantity,
    pub quantity_increment: Quantity,
    pub continuous_trading_status_code: u16,
    pub self_trade_prevention: SelfTradePreventionInstruction,
    /// Whether a live session must expose venue-native cancel-on-disconnect support.
    /// Runtime activation/acknowledgement remains a concrete adapter deployment gate.
    pub cancel_on_disconnect_required: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstrumentDefinitionError {
    InvalidVenue,
    InvalidInstrument,
    InvalidNativeProduct,
    InvalidAuthority,
    InvalidReferenceDataVersion,
    InvalidReferenceDataDigest,
    InvalidValidityWindow,
    InvalidPriceScale,
    InvalidQuantityScale,
    InvalidFixedValue,
    InvalidPriceRules,
    InvalidQuantityRules,
    InvalidTradingStatus,
    InvalidSelfTradePrevention,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstrumentRuleViolation {
    InvalidDefinition(InstrumentDefinitionError),
    VenueMismatch {
        expected: VenueId,
        received: VenueId,
    },
    InstrumentMismatch {
        expected: InstrumentId,
        received: InstrumentId,
    },
    ReferenceDataNotEffective {
        valid_from: TimestampNs,
        valid_until: TimestampNs,
        observed: TimestampNs,
    },
    PriceOutOfBounds {
        minimum: PriceTicks,
        maximum: PriceTicks,
        received: PriceTicks,
    },
    PriceIncrementMismatch {
        increment: PriceTicks,
        received: PriceTicks,
    },
    QuantityOutOfBounds {
        minimum: Quantity,
        maximum: Quantity,
        received: Quantity,
    },
    QuantityIncrementMismatch {
        increment: Quantity,
        received: Quantity,
    },
}

impl InstrumentDefinition {
    #[must_use]
    pub const fn binding(self) -> InstrumentDefinitionBinding {
        InstrumentDefinitionBinding {
            venue: self.venue,
            instrument: self.instrument,
            native_product: self.native_product,
            authority: self.authority,
            reference_data_version: self.reference_data_version,
            reference_data_digest: self.reference_data_digest,
        }
    }

    /// Validate canonical identity, provenance, scales, effective dates, and rules.
    ///
    /// # Errors
    ///
    /// Returns the first non-canonical or missing field. No external authenticity is
    /// inferred from a structurally valid digest.
    pub const fn validate(self) -> Result<(), InstrumentDefinitionError> {
        if self.venue.0 == 0 {
            return Err(InstrumentDefinitionError::InvalidVenue);
        }
        if self.instrument.0 == 0 {
            return Err(InstrumentDefinitionError::InvalidInstrument);
        }
        if self.native_product.0 == 0 {
            return Err(InstrumentDefinitionError::InvalidNativeProduct);
        }
        if self.authority.0 == 0 {
            return Err(InstrumentDefinitionError::InvalidAuthority);
        }
        if self.reference_data_version == 0 {
            return Err(InstrumentDefinitionError::InvalidReferenceDataVersion);
        }
        if !self.reference_data_digest.is_valid() {
            return Err(InstrumentDefinitionError::InvalidReferenceDataDigest);
        }
        if self.valid_from.0 == 0 || self.valid_from.0 >= self.valid_until.0 {
            return Err(InstrumentDefinitionError::InvalidValidityWindow);
        }
        if !self.price_scale.is_valid() {
            return Err(InstrumentDefinitionError::InvalidPriceScale);
        }
        if !self.quantity_scale.is_valid() {
            return Err(InstrumentDefinitionError::InvalidQuantityScale);
        }
        if !self.fixed_value.is_valid() {
            return Err(InstrumentDefinitionError::InvalidFixedValue);
        }
        if self.minimum_price.0 <= 0
            || self.minimum_price.0 > self.maximum_price.0
            || self.price_increment.0 <= 0
            || self.minimum_price.0 % self.price_increment.0 != 0
            || self.maximum_price.0 % self.price_increment.0 != 0
        {
            return Err(InstrumentDefinitionError::InvalidPriceRules);
        }
        if self.minimum_quantity.0 <= 0
            || self.minimum_quantity.0 > self.maximum_quantity.0
            || self.quantity_increment.0 <= 0
            || self.minimum_quantity.0 % self.quantity_increment.0 != 0
            || self.maximum_quantity.0 % self.quantity_increment.0 != 0
        {
            return Err(InstrumentDefinitionError::InvalidQuantityRules);
        }
        if self.continuous_trading_status_code == 0 {
            return Err(InstrumentDefinitionError::InvalidTradingStatus);
        }
        if self.self_trade_prevention.0 == 0 {
            return Err(InstrumentDefinitionError::InvalidSelfTradePrevention);
        }
        Ok(())
    }

    #[must_use]
    pub const fn is_effective_at(self, observed: TimestampNs) -> bool {
        observed.0 >= self.valid_from.0 && observed.0 <= self.valid_until.0
    }

    #[must_use]
    pub const fn is_continuous_trading(self, status_code: u16) -> bool {
        status_code == self.continuous_trading_status_code
    }

    /// Validate the exact route and economics before order preparation or encoding.
    ///
    /// # Errors
    ///
    /// Returns a typed mismatch for invalid/stale definitions, route drift, bands,
    /// or increments.
    pub const fn validate_order_economics(
        self,
        venue: VenueId,
        instrument: InstrumentId,
        price: PriceTicks,
        quantity: Quantity,
        observed: TimestampNs,
    ) -> Result<(), InstrumentRuleViolation> {
        if let Err(error) = self.validate() {
            return Err(InstrumentRuleViolation::InvalidDefinition(error));
        }
        if venue.0 != self.venue.0 {
            return Err(InstrumentRuleViolation::VenueMismatch {
                expected: self.venue,
                received: venue,
            });
        }
        if instrument.0 != self.instrument.0 {
            return Err(InstrumentRuleViolation::InstrumentMismatch {
                expected: self.instrument,
                received: instrument,
            });
        }
        if !self.is_effective_at(observed) {
            return Err(InstrumentRuleViolation::ReferenceDataNotEffective {
                valid_from: self.valid_from,
                valid_until: self.valid_until,
                observed,
            });
        }
        self.validate_normalized_economics(instrument, price, quantity)
    }

    /// Validate normalized venue data without requiring the definition to be current.
    /// This lets an expired session continue consuming market data and cancel resting
    /// orders while still rejecting impossible bands, increments, or product routes.
    ///
    /// # Errors
    ///
    /// Returns a typed structural, instrument, price, or quantity mismatch.
    pub const fn validate_normalized_economics(
        self,
        instrument: InstrumentId,
        price: PriceTicks,
        quantity: Quantity,
    ) -> Result<(), InstrumentRuleViolation> {
        if let Err(error) = self.validate() {
            return Err(InstrumentRuleViolation::InvalidDefinition(error));
        }
        if instrument.0 != self.instrument.0 {
            return Err(InstrumentRuleViolation::InstrumentMismatch {
                expected: self.instrument,
                received: instrument,
            });
        }
        if price.0 < self.minimum_price.0 || price.0 > self.maximum_price.0 {
            return Err(InstrumentRuleViolation::PriceOutOfBounds {
                minimum: self.minimum_price,
                maximum: self.maximum_price,
                received: price,
            });
        }
        if price.0 % self.price_increment.0 != 0 {
            return Err(InstrumentRuleViolation::PriceIncrementMismatch {
                increment: self.price_increment,
                received: price,
            });
        }
        if quantity.0 < self.minimum_quantity.0 || quantity.0 > self.maximum_quantity.0 {
            return Err(InstrumentRuleViolation::QuantityOutOfBounds {
                minimum: self.minimum_quantity,
                maximum: self.maximum_quantity,
                received: quantity,
            });
        }
        if quantity.0 % self.quantity_increment.0 != 0 {
            return Err(InstrumentRuleViolation::QuantityIncrementMismatch {
                increment: self.quantity_increment,
                received: quantity,
            });
        }
        Ok(())
    }
}

const fn greatest_common_divisor(mut left: u64, mut right: u64) -> u64 {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left
}
