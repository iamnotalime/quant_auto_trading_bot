use crate::types::{InstrumentId, OrderId};
use core::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapacityError {
    Full,
    InvalidCapacity,
}

#[derive(Clone, Eq, PartialEq)]
pub struct FixedVec<T, const N: usize> {
    slots: [Option<T>; N],
    len: usize,
}

impl<T: fmt::Debug, const N: usize> fmt::Debug for FixedVec<T, N> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_list().entries(self.iter()).finish()
    }
}

impl<T, const N: usize> FixedVec<T, N> {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            slots: [const { None }; N],
            len: 0,
        }
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    #[must_use]
    pub const fn capacity(&self) -> usize {
        N
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[must_use]
    pub const fn is_full(&self) -> bool {
        self.len == N
    }

    /// Append without allocating.
    ///
    /// # Errors
    ///
    /// Returns [`CapacityError::Full`] when all compile-time slots are occupied.
    pub fn push(&mut self, value: T) -> Result<(), CapacityError> {
        if self.is_full() {
            return Err(CapacityError::Full);
        }
        self.slots[self.len] = Some(value);
        self.len += 1;
        Ok(())
    }

    pub fn pop(&mut self) -> Option<T> {
        if self.len == 0 {
            return None;
        }
        self.len -= 1;
        self.slots[self.len].take()
    }

    #[must_use]
    pub fn get(&self, index: usize) -> Option<&T> {
        (index < self.len)
            .then(|| self.slots[index].as_ref())
            .flatten()
    }

    pub fn get_mut(&mut self, index: usize) -> Option<&mut T> {
        if index >= self.len {
            return None;
        }
        self.slots[index].as_mut()
    }

    pub fn remove(&mut self, index: usize) -> Option<T> {
        if index >= self.len {
            return None;
        }
        let removed = self.slots[index].take();
        let mut position = index;
        while position + 1 < self.len {
            self.slots[position] = self.slots[position + 1].take();
            position += 1;
        }
        self.len -= 1;
        self.slots[self.len] = None;
        removed
    }

    pub fn clear(&mut self) {
        while self.pop().is_some() {}
    }

    /// Iterate over the initialized prefix.
    ///
    /// # Panics
    ///
    /// Panics only if this type's private contiguous-prefix invariant is violated.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = &T> + DoubleEndedIterator {
        self.slots[..self.len].iter().map(|slot| {
            slot.as_ref()
                .expect("FixedVec initialized prefix invariant violated")
        })
    }

    /// Mutably iterate over the initialized prefix.
    ///
    /// # Panics
    ///
    /// Panics only if this type's private contiguous-prefix invariant is violated.
    pub fn iter_mut(&mut self) -> impl ExactSizeIterator<Item = &mut T> + DoubleEndedIterator {
        self.slots[..self.len].iter_mut().map(|slot| {
            slot.as_mut()
                .expect("FixedVec initialized prefix invariant violated")
        })
    }
}

impl<T, const N: usize> Default for FixedVec<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

pub trait FixedKey: Copy + Eq {
    fn fixed_hash(self) -> u64;
}

const fn mix_u64(mut value: u64) -> u64 {
    value ^= value >> 30;
    value = value.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value ^= value >> 27;
    value = value.wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

impl FixedKey for u64 {
    fn fixed_hash(self) -> u64 {
        mix_u64(self)
    }
}

impl FixedKey for u32 {
    fn fixed_hash(self) -> u64 {
        mix_u64(u64::from(self))
    }
}

impl FixedKey for InstrumentId {
    fn fixed_hash(self) -> u64 {
        self.0.fixed_hash()
    }
}

impl FixedKey for OrderId {
    fn fixed_hash(self) -> u64 {
        self.0.fixed_hash()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SlotState {
    Empty,
    Occupied,
    Tombstone,
}

#[derive(Clone, Eq, PartialEq)]
pub struct FixedIndexMap<K, V, const N: usize> {
    states: [SlotState; N],
    entries: [Option<(K, V)>; N],
    len: usize,
}

impl<K: FixedKey + fmt::Debug, V: fmt::Debug, const N: usize> fmt::Debug
    for FixedIndexMap<K, V, N>
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_map().entries(self.iter()).finish()
    }
}

impl<K: FixedKey, V, const N: usize> FixedIndexMap<K, V, N> {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            states: [SlotState::Empty; N],
            entries: [const { None }; N],
            len: 0,
        }
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    #[must_use]
    pub const fn capacity(&self) -> usize {
        N
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn start_index(key: K) -> Result<usize, CapacityError> {
        if N == 0 {
            return Err(CapacityError::InvalidCapacity);
        }
        let capacity = u64::try_from(N).map_err(|_| CapacityError::InvalidCapacity)?;
        usize::try_from(key.fixed_hash() % capacity).map_err(|_| CapacityError::InvalidCapacity)
    }

    fn find_index(&self, key: K) -> Option<usize> {
        let start = Self::start_index(key).ok()?;
        for offset in 0..N {
            let index = (start + offset) % N;
            match self.states[index] {
                SlotState::Empty => return None,
                SlotState::Occupied => {
                    if self.entries[index]
                        .as_ref()
                        .is_some_and(|(candidate, _)| *candidate == key)
                    {
                        return Some(index);
                    }
                }
                SlotState::Tombstone => {}
            }
        }
        None
    }

    /// Insert or replace a value without allocating.
    ///
    /// # Errors
    ///
    /// Returns [`CapacityError::InvalidCapacity`] for a zero-sized map and
    /// [`CapacityError::Full`] when no slot or tombstone is available.
    pub fn insert(&mut self, key: K, value: V) -> Result<Option<V>, CapacityError> {
        let start = Self::start_index(key)?;
        let mut first_tombstone = None;
        for offset in 0..N {
            let index = (start + offset) % N;
            match self.states[index] {
                SlotState::Occupied => {
                    if self.entries[index]
                        .as_ref()
                        .is_some_and(|(candidate, _)| *candidate == key)
                    {
                        let prior = self.entries[index].replace((key, value));
                        return Ok(prior.map(|(_, old)| old));
                    }
                }
                SlotState::Tombstone => {
                    first_tombstone.get_or_insert(index);
                }
                SlotState::Empty => {
                    let target = first_tombstone.unwrap_or(index);
                    self.states[target] = SlotState::Occupied;
                    self.entries[target] = Some((key, value));
                    self.len += 1;
                    return Ok(None);
                }
            }
        }
        if let Some(target) = first_tombstone {
            self.states[target] = SlotState::Occupied;
            self.entries[target] = Some((key, value));
            self.len += 1;
            return Ok(None);
        }
        Err(CapacityError::Full)
    }

    #[must_use]
    pub fn get(&self, key: K) -> Option<&V> {
        self.find_index(key)
            .and_then(|index| self.entries[index].as_ref().map(|(_, value)| value))
    }

    pub fn get_mut(&mut self, key: K) -> Option<&mut V> {
        let index = self.find_index(key)?;
        self.entries[index].as_mut().map(|(_, value)| value)
    }

    pub fn remove(&mut self, key: K) -> Option<V> {
        let index = self.find_index(key)?;
        self.states[index] = SlotState::Tombstone;
        self.len -= 1;
        self.entries[index].take().map(|(_, value)| value)
    }

    pub fn clear(&mut self) {
        for index in 0..N {
            self.states[index] = SlotState::Empty;
            self.entries[index] = None;
        }
        self.len = 0;
    }

    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.entries
            .iter()
            .filter_map(|entry| entry.as_ref().map(|(key, value)| (key, value)))
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&K, &mut V)> {
        self.entries
            .iter_mut()
            .filter_map(|entry| entry.as_mut().map(|(key, value)| (&*key, value)))
    }
}

impl<K: FixedKey, V, const N: usize> Default for FixedIndexMap<K, V, N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{CapacityError, FixedIndexMap, FixedVec};

    #[test]
    fn fixed_vec_never_grows_and_preserves_order() {
        let mut values = FixedVec::<u64, 3>::new();
        values.push(10).unwrap();
        values.push(20).unwrap();
        values.push(30).unwrap();
        assert_eq!(values.push(40), Err(CapacityError::Full));
        assert_eq!(values.remove(1), Some(20));
        assert_eq!(values.iter().copied().collect::<Vec<_>>(), vec![10, 30]);
    }

    #[test]
    fn fixed_map_handles_replace_remove_and_tombstones() {
        let mut values = FixedIndexMap::<u64, u64, 4>::new();
        assert_eq!(values.insert(1, 10), Ok(None));
        assert_eq!(values.insert(2, 20), Ok(None));
        assert_eq!(values.insert(1, 11), Ok(Some(10)));
        assert_eq!(values.remove(2), Some(20));
        assert_eq!(values.insert(3, 30), Ok(None));
        assert_eq!(values.get(1), Some(&11));
        assert_eq!(values.get(2), None);
        assert_eq!(values.get(3), Some(&30));
    }
}
