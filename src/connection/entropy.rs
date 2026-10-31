//! One fresh encryption response prefetched while radio scheduling continues.

use crate::crypto;
use core::{cell::RefCell, ops::AsyncFnMut};
use embassy_sync::{
    blocking_mutex::{Mutex, raw::CriticalSectionRawMutex},
    signal::Signal,
};

/// Peripheral session-key diversifier (8 bytes) and initialization vector (4).
pub(super) struct Material([u8; 12]);

impl Material {
    /// Borrows the completed block without permitting another pool insertion.
    pub(super) const fn bytes(&self) -> &[u8; 12] { &self.0 }
}

impl Drop for Material {
    fn drop(&mut self) { crypto::wipe(&mut self.0); }
}

/// A per-connection, single-use entropy slot. Dropping it wipes unused
/// material.
pub(super) struct Prefetch {
    /// Ready material is moved out once, never copied back into the slot.
    ready:  Mutex<CriticalSectionRawMutex, RefCell<Option<Material>>>,
    /// Taking the ready block requests exactly one replacement.
    refill: Signal<CriticalSectionRawMutex, ()>,
}

impl Prefetch {
    /// Starts empty: no prior connection's material can be inherited.
    pub(super) const fn new() -> Self { Self { ready: Mutex::new(RefCell::new(None)), refill: Signal::new() } }

    /// Produces at most one spare response, yielding to the radio between
    /// bytes.
    pub(super) async fn run(&self) -> ! { self.run_with(crate::rng::fill_async).await }

    /// Supplies entropy through an injectable async source for host
    /// regressions.
    pub(super) async fn run_with(&self, mut fill: impl AsyncFnMut(&mut [u8])) -> ! {
        loop {
            self.refill.reset();
            let mut material = Material([0; 12]);
            fill(&mut material.0).await;
            self.ready.lock(|slot| *slot.borrow_mut() = Some(material));
            self.refill.wait().await;
        }
    }

    /// Takes ownership without waiting; an empty slot never starts hardware.
    pub(super) fn take(&self) -> Option<Material> {
        let material = self.ready.lock(|slot| slot.borrow_mut().take());
        if material.is_some() {
            self.refill.signal(());
        }
        material
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::{
        cell::Cell,
        future::{Future, pending},
        pin::pin,
        task::{Context, Waker},
    };

    #[test]
    fn blocks_are_single_use_and_collection_stops_when_the_slot_is_full() {
        let prefetch = Prefetch::new();
        let produced = Cell::new(0_u8);
        let mut worker = pin!(prefetch.run_with(async |bytes: &mut [u8]| {
            produced.set(produced.get() + 1);
            bytes.fill(produced.get());
        }));
        let mut context = Context::from_waker(Waker::noop());
        assert!(prefetch.take().is_none());
        assert!(worker.as_mut().poll(&mut context).is_pending());
        assert_eq!(produced.get(), 1);
        assert!(worker.as_mut().poll(&mut context).is_pending());
        assert_eq!(produced.get(), 1);
        assert_eq!(prefetch.take().unwrap().0, [1; 12]);
        assert!(prefetch.take().is_none());
        assert!(worker.as_mut().poll(&mut context).is_pending());
        assert_eq!(prefetch.take().unwrap().0, [2; 12]);
        assert!(prefetch.take().is_none());
    }

    #[test]
    fn cancellation_never_publishes_a_partial_response() {
        let prefetch = Prefetch::new();
        {
            let mut worker = pin!(prefetch.run_with(async |bytes: &mut [u8]| {
                bytes[..5].fill(0xA5);
                pending::<()>().await;
            }));
            assert!(worker.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
        }
        assert!(prefetch.take().is_none());
        let mut replacement = pin!(prefetch.run_with(async |bytes: &mut [u8]| bytes.fill(0x3C)));
        assert!(replacement.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
        assert_eq!(prefetch.take().unwrap().0, [0x3C; 12]);
    }

    #[test]
    fn a_new_connection_does_not_inherit_a_ready_block() {
        {
            let old = Prefetch::new();
            let mut worker = pin!(old.run_with(async |bytes: &mut [u8]| bytes.fill(7)));
            assert!(worker.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
        }
        let next = Prefetch::new();
        assert!(next.take().is_none());
        let mut worker = pin!(next.run_with(async |bytes: &mut [u8]| bytes.fill(8)));
        assert!(worker.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
        assert_eq!(next.take().unwrap().0, [8; 12]);
    }
}
