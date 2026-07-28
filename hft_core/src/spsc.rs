use core::cell::UnsafeCell;
use core::fmt;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicUsize, Ordering};

#[repr(align(64))]
struct CacheLine<T>(T);

impl<T: fmt::Debug> fmt::Debug for CacheLine<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Fixed-capacity single-producer/single-consumer ring.
///
/// One slot is deliberately unused to distinguish full from empty. `split` requires an
/// exclusive borrow, preventing safe Rust from creating multiple producers or consumers.
pub struct SpscRing<T, const N: usize> {
    slots: [UnsafeCell<MaybeUninit<T>>; N],
    head: CacheLine<AtomicUsize>,
    tail: CacheLine<AtomicUsize>,
}

impl<T, const N: usize> fmt::Debug for SpscRing<T, N> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SpscRing")
            .field("capacity", &self.capacity())
            .field("len", &self.len())
            .finish_non_exhaustive()
    }
}

// SAFETY: each slot is written only by the unique Producer before a Release head
// publication, and read/dropped only by the unique Consumer after its Acquire load.
unsafe impl<T: Send, const N: usize> Sync for SpscRing<T, N> {}
// SAFETY: moving an un-split ring transfers exclusive ownership of every slot.
unsafe impl<T: Send, const N: usize> Send for SpscRing<T, N> {}

impl<T, const N: usize> SpscRing<T, N> {
    /// Construct an empty ring with one sentinel slot.
    ///
    /// # Panics
    ///
    /// Panics when `N < 2`, because one data and one sentinel slot are required.
    #[must_use]
    pub fn new() -> Self {
        assert!(N >= 2, "SPSC storage requires at least two slots");
        Self {
            slots: core::array::from_fn(|_| UnsafeCell::new(MaybeUninit::uninit())),
            head: CacheLine(AtomicUsize::new(0)),
            tail: CacheLine(AtomicUsize::new(0)),
        }
    }

    #[must_use]
    pub const fn capacity(&self) -> usize {
        N.saturating_sub(1)
    }

    #[must_use]
    /// Return an instantaneous advisory length.
    ///
    /// While producer and consumer run concurrently this is not a linearizable
    /// transaction across both cursors. `try_push`/`try_pop` remain authoritative.
    pub fn len(&self) -> usize {
        let head = self.head.0.load(Ordering::Acquire);
        let tail = self.tail.0.load(Ordering::Acquire);
        if head >= tail {
            head - tail
        } else {
            N - tail + head
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.head.0.load(Ordering::Acquire) == self.tail.0.load(Ordering::Acquire)
    }

    pub fn split(&mut self) -> (Producer<'_, T, N>, Consumer<'_, T, N>) {
        let shared: &Self = self;
        (Producer { ring: shared }, Consumer { ring: shared })
    }

    fn next(index: usize) -> usize {
        let incremented = index + 1;
        if incremented == N { 0 } else { incremented }
    }
}

impl<T, const N: usize> Default for SpscRing<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T, const N: usize> Drop for SpscRing<T, N> {
    fn drop(&mut self) {
        let mut tail = self.tail.0.load(Ordering::Relaxed);
        let head = self.head.0.load(Ordering::Relaxed);
        while tail != head {
            // SAFETY: drop has exclusive access to the ring, and indices in the
            // published tail..head range contain initialized, not-yet-consumed values.
            unsafe {
                (*self.slots[tail].get()).assume_init_drop();
            }
            tail = Self::next(tail);
        }
    }
}

#[derive(Debug)]
pub struct Producer<'a, T, const N: usize> {
    ring: &'a SpscRing<T, N>,
}

impl<T, const N: usize> Producer<'_, T, N> {
    /// Publish one item without blocking.
    ///
    /// # Errors
    ///
    /// Returns the unchanged item when the ring is full.
    pub fn try_push(&mut self, value: T) -> Result<(), T> {
        let head = self.ring.head.0.load(Ordering::Relaxed);
        let next = SpscRing::<T, N>::next(head);
        if next == self.ring.tail.0.load(Ordering::Acquire) {
            return Err(value);
        }
        // SAFETY: only this Producer writes the current unpublished head slot. The
        // Consumer cannot access it until the following Release store.
        unsafe {
            (*self.ring.slots[head].get()).write(value);
        }
        self.ring.head.0.store(next, Ordering::Release);
        Ok(())
    }

    #[must_use]
    /// Return advisory free capacity; concurrent consumer progress can change it.
    pub fn remaining(&self) -> usize {
        self.ring.capacity().saturating_sub(self.ring.len())
    }
}

#[derive(Debug)]
pub struct Consumer<'a, T, const N: usize> {
    ring: &'a SpscRing<T, N>,
}

impl<T, const N: usize> Consumer<'_, T, N> {
    pub fn try_pop(&mut self) -> Option<T> {
        let tail = self.ring.tail.0.load(Ordering::Relaxed);
        if tail == self.ring.head.0.load(Ordering::Acquire) {
            return None;
        }
        // SAFETY: the Acquire head load proves this slot was initialized by the
        // Producer, and only this Consumer reads the current tail slot.
        let value = unsafe { (*self.ring.slots[tail].get()).assume_init_read() };
        self.ring
            .tail
            .0
            .store(SpscRing::<T, N>::next(tail), Ordering::Release);
        Some(value)
    }

    #[must_use]
    /// Return advisory readable capacity; concurrent producer progress can change it.
    pub fn available(&self) -> usize {
        self.ring.len()
    }
}

#[cfg(test)]
mod tests {
    use super::SpscRing;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;

    #[derive(Debug)]
    struct DropCount(Arc<AtomicUsize>);

    impl Drop for DropCount {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn ring_is_fixed_capacity_and_fifo() {
        let mut ring = SpscRing::<u64, 4>::new();
        let (mut producer, mut consumer) = ring.split();
        producer.try_push(1).unwrap();
        producer.try_push(2).unwrap();
        producer.try_push(3).unwrap();
        assert_eq!(producer.try_push(4), Err(4));
        assert_eq!(consumer.try_pop(), Some(1));
        assert_eq!(consumer.try_pop(), Some(2));
        producer.try_push(4).unwrap();
        assert_eq!(consumer.try_pop(), Some(3));
        assert_eq!(consumer.try_pop(), Some(4));
        assert_eq!(consumer.try_pop(), None);
    }

    #[test]
    fn ring_transfers_across_pinned_threads() {
        let mut ring = SpscRing::<u64, 1024>::new();
        thread::scope(|scope| {
            let (mut producer, mut consumer) = ring.split();
            scope.spawn(move || {
                for value in 0..100_000_u64 {
                    let mut pending = value;
                    loop {
                        match producer.try_push(pending) {
                            Ok(()) => break,
                            Err(value) => {
                                pending = value;
                                core::hint::spin_loop();
                            }
                        }
                    }
                }
            });
            scope.spawn(move || {
                for expected in 0..100_000_u64 {
                    loop {
                        if let Some(actual) = consumer.try_pop() {
                            assert_eq!(actual, expected);
                            break;
                        }
                        core::hint::spin_loop();
                    }
                }
            });
        });
        assert!(ring.is_empty());
    }

    #[test]
    fn wraparound_preserves_fifo_and_drops_each_item_once() {
        let drops = Arc::new(AtomicUsize::new(0));
        {
            let mut ring = SpscRing::<(u64, DropCount), 8>::new();
            let (mut producer, mut consumer) = ring.split();
            for cycle in 0..100_u64 {
                for offset in 0..7_u64 {
                    producer
                        .try_push((cycle * 7 + offset, DropCount(Arc::clone(&drops))))
                        .map_err(drop)
                        .expect("bounded push");
                }
                for offset in 0..6_u64 {
                    let (value, item) = consumer.try_pop().expect("published item");
                    assert_eq!(value, cycle * 7 + offset);
                    drop(item);
                }
                let (value, item) = consumer.try_pop().expect("last published item");
                assert_eq!(value, cycle * 7 + 6);
                drop(item);
            }
            for value in 0..3_u64 {
                producer
                    .try_push((value, DropCount(Arc::clone(&drops))))
                    .map_err(drop)
                    .expect("final push");
            }
            assert_eq!(drops.load(Ordering::Relaxed), 700);
            // Three unconsumed values are dropped with the ring.
        }
        assert_eq!(drops.load(Ordering::Relaxed), 703);
    }
}
