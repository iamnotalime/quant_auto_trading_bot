//! Fixed-capacity, one-to-one binding of private order-entry and public MBO identities.
//!
//! Numeric equality never creates ownership. Only an explicit binding emitted by a
//! certified native adapter can populate this registry.

use crate::fixed::{CapacityError, FixedIndexMap, FixedKey};
use crate::venue::{ClientOrderId, MarketByOrderId, OwnedMboBinding, VenueOrderId};

impl FixedKey for MarketByOrderId {
    fn fixed_hash(self) -> u64 {
        self.0.fixed_hash()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnershipBindOutcome {
    Inserted,
    Duplicate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnershipError {
    InvalidBinding,
    ClientCollision { client_order_id: ClientOrderId },
    VenueOrderCollision { venue_order_id: VenueOrderId },
    MarketByOrderCollision { market_by_order_id: MarketByOrderId },
    Capacity { capacity: usize },
    InternalInvariant,
}

/// Transactional fixed-capacity three-way identity index.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnedMboRegistry<const MAX_BINDINGS: usize> {
    clients: FixedIndexMap<ClientOrderId, OwnedMboBinding, MAX_BINDINGS>,
    private_orders: FixedIndexMap<VenueOrderId, ClientOrderId, MAX_BINDINGS>,
    public_orders: FixedIndexMap<MarketByOrderId, ClientOrderId, MAX_BINDINGS>,
}

impl<const MAX_BINDINGS: usize> OwnedMboRegistry<MAX_BINDINGS> {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            clients: FixedIndexMap::new(),
            private_orders: FixedIndexMap::new(),
            public_orders: FixedIndexMap::new(),
        }
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.clients.len()
    }

    #[must_use]
    pub const fn capacity(&self) -> usize {
        MAX_BINDINGS
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.clients.is_empty()
    }

    #[must_use]
    pub fn by_client(&self, client_order_id: ClientOrderId) -> Option<OwnedMboBinding> {
        self.clients.get(client_order_id).copied()
    }

    #[must_use]
    pub fn by_venue_order(&self, venue_order_id: VenueOrderId) -> Option<OwnedMboBinding> {
        let client_order_id = *self.private_orders.get(venue_order_id)?;
        self.by_client(client_order_id)
    }

    #[must_use]
    pub fn by_market_order(&self, market_by_order_id: MarketByOrderId) -> Option<OwnedMboBinding> {
        let client_order_id = *self.public_orders.get(market_by_order_id)?;
        self.by_client(client_order_id)
    }

    /// Atomically insert an adapter-authenticated one-to-one binding.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid identifiers, conflicting namespaces, exhausted
    /// fixed capacity, or a broken internal index invariant. The registry is unchanged
    /// on every error.
    pub fn bind(
        &mut self,
        binding: OwnedMboBinding,
    ) -> Result<OwnershipBindOutcome, OwnershipError> {
        if !binding.is_valid() {
            return Err(OwnershipError::InvalidBinding);
        }
        if let Some(existing) = self.by_client(binding.client_order_id) {
            return if existing == binding {
                Ok(OwnershipBindOutcome::Duplicate)
            } else {
                Err(OwnershipError::ClientCollision {
                    client_order_id: binding.client_order_id,
                })
            };
        }
        if self.private_orders.get(binding.venue_order_id).is_some() {
            return Err(OwnershipError::VenueOrderCollision {
                venue_order_id: binding.venue_order_id,
            });
        }
        if self.public_orders.get(binding.market_by_order_id).is_some() {
            return Err(OwnershipError::MarketByOrderCollision {
                market_by_order_id: binding.market_by_order_id,
            });
        }
        if self.len() >= MAX_BINDINGS {
            return Err(OwnershipError::Capacity {
                capacity: MAX_BINDINGS,
            });
        }

        let mut candidate = self.clone();
        insert_new(
            &mut candidate.clients,
            binding.client_order_id,
            binding,
            MAX_BINDINGS,
        )?;
        insert_new(
            &mut candidate.private_orders,
            binding.venue_order_id,
            binding.client_order_id,
            MAX_BINDINGS,
        )?;
        insert_new(
            &mut candidate.public_orders,
            binding.market_by_order_id,
            binding.client_order_id,
            MAX_BINDINGS,
        )?;
        *self = candidate;
        Ok(OwnershipBindOutcome::Inserted)
    }

    /// Atomically remove one binding by its locally generated client identifier.
    ///
    /// # Errors
    ///
    /// Returns an internal-invariant error if the secondary indexes do not exactly
    /// match the primary binding. The registry remains unchanged on error.
    pub fn remove_by_client(
        &mut self,
        client_order_id: ClientOrderId,
    ) -> Result<Option<OwnedMboBinding>, OwnershipError> {
        let Some(binding) = self.by_client(client_order_id) else {
            return Ok(None);
        };
        let mut candidate = self.clone();
        if candidate.clients.remove(client_order_id) != Some(binding)
            || candidate.private_orders.remove(binding.venue_order_id) != Some(client_order_id)
            || candidate.public_orders.remove(binding.market_by_order_id) != Some(client_order_id)
        {
            return Err(OwnershipError::InternalInvariant);
        }
        *self = candidate;
        Ok(Some(binding))
    }

    pub fn clear(&mut self) {
        self.clients.clear();
        self.private_orders.clear();
        self.public_orders.clear();
    }
}

impl<const MAX_BINDINGS: usize> Default for OwnedMboRegistry<MAX_BINDINGS> {
    fn default() -> Self {
        Self::new()
    }
}

fn insert_new<K: FixedKey, V, const N: usize>(
    map: &mut FixedIndexMap<K, V, N>,
    key: K,
    value: V,
    capacity: usize,
) -> Result<(), OwnershipError> {
    match map.insert(key, value) {
        Ok(None) => Ok(()),
        Ok(Some(_)) => Err(OwnershipError::InternalInvariant),
        Err(CapacityError::Full | CapacityError::InvalidCapacity) => {
            Err(OwnershipError::Capacity { capacity })
        }
    }
}
