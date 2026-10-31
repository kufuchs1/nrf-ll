//! Exclusive flash maintenance between radio events.
//!
//! The CPU stops while the NVMC writes or erases, so the link layer cannot
//! answer the radio meanwhile. A flash owner asks the link layer to park
//! between two radio events, before it advertises or listens again, and
//! releases it when done. A connection survives the pause: its events that
//! pass meanwhile are skipped, as with peripheral latency.
//!
//! Both sides change the request and the parked state together in a
//! critical section, so a request that is cancelled at any point, or followed
//! at once by the next one, can neither leave the link layer parked nor let
//! flash run while it is not.

use crate::{clock::Clock, radio::Radio};
use core::cell::Cell;
use embassy_sync::{
    blocking_mutex::{Mutex, raw::CriticalSectionRawMutex},
    signal::Signal,
};

/// The link layer parked for the flash owner.
static READY: Signal<CriticalSectionRawMutex, ()> = Signal::new();
/// The flash owner finished or gave up its request.
static RESUME: Signal<CriticalSectionRawMutex, ()> = Signal::new();
/// The request of the flash owner and whether the link layer is parked.
static STATE: Mutex<CriticalSectionRawMutex, Cell<State>> = Mutex::new(Cell::new(State::IDLE));
/// Wakes an idle link layer for a request.
static WAKE: Signal<CriticalSectionRawMutex, ()> = Signal::new();

/// Exclusive ownership of the parked radio while it lives.
#[non_exhaustive]
pub struct Guard;

impl Drop for Guard {
    #[inline]
    fn drop(&mut self) {
        STATE.lock(|state| state.set(State { requested: false, ..state.get() }));
        RESUME.signal(());
    }
}

/// Request and parked state.
#[derive(Clone, Copy)]
struct State {
    /// The link layer is parked and stays so while the request holds.
    parked:    bool,
    /// A flash owner wants the link layer parked.
    requested: bool,
}

impl State {
    /// Nothing requested, the link layer running.
    const IDLE: Self = Self { parked: false, requested: false };
}

/// Parks the link layer and returns once it is parked. Only one owner may
/// ask at a time; the firmware's single profile store is it. Dropping the
/// future before it returns withdraws the request.
#[inline]
pub async fn acquire() -> Guard {
    // Created first, so a cancelled request is withdrawn as well.
    let guard = Guard;
    STATE.lock(|state| state.set(State { requested: true, ..state.get() }));
    WAKE.signal(());
    loop {
        READY.reset();
        if STATE.lock(|state| state.get().parked) {
            return guard;
        }
        READY.wait().await;
    }
}

/// Stays parked while a request holds, and acknowledges it.
async fn park() {
    loop {
        RESUME.reset();
        let parked = STATE.lock(|state| {
            let current = state.get();
            state.set(State { parked: current.requested, ..current });
            current.requested
        });
        if !parked {
            return;
        }
        READY.signal(());
        RESUME.wait().await;
    }
}

/// Whether a flash owner waits for the link layer to park.
#[inline]
#[must_use = "a request has to be served"]
pub fn pending() -> bool { STATE.lock(|state| state.get().requested) }

/// Wakes an idle link layer when flash maintenance is requested.
#[inline]
pub async fn requested() { WAKE.wait().await; }

/// Parks the radio and its clock while flash maintenance is requested.
/// Called between radio events only.
#[inline]
pub async fn service(clock: &mut Clock<'_>, radio: &mut Radio<'_>) {
    if !pending() {
        return;
    }
    radio.disable();
    clock.pause();
    crate::health::suspend();
    park().await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::{
        future::Future,
        pin::pin,
        task::{Context, Poll, Waker},
    };

    fn context() -> Context<'static> { Context::from_waker(Waker::noop()) }

    // One test: the state is global, and tests run in parallel.
    #[test]
    fn grants_survive_back_to_back_and_cancelled_requests() {
        let mut first = pin!(acquire());
        assert!(first.as_mut().poll(&mut context()).is_pending());
        assert!(pending());
        let mut parked = pin!(park());
        assert!(parked.as_mut().poll(&mut context()).is_pending());
        let Poll::Ready(guard) = first.as_mut().poll(&mut context()) else { panic!("not granted") };
        assert!(parked.as_mut().poll(&mut context()).is_pending());
        // The next request arrives before the link layer saw the release:
        // it stays parked and grants it at once.
        drop(guard);
        let mut second = pin!(acquire());
        let Poll::Ready(guard) = second.as_mut().poll(&mut context()) else { panic!("second not granted") };
        assert!(parked.as_mut().poll(&mut context()).is_pending());
        drop(guard);
        assert!(parked.as_mut().poll(&mut context()).is_ready());
        assert!(!pending());

        // Withdrawn before the link layer saw it.
        {
            let mut request = pin!(acquire());
            assert!(request.as_mut().poll(&mut context()).is_pending());
        }
        assert!(!pending());
        assert!(pin!(park()).as_mut().poll(&mut context()).is_ready());

        // Withdrawn while the link layer is parked for it.
        let mut parked = pin!(park());
        {
            let mut request = pin!(acquire());
            assert!(request.as_mut().poll(&mut context()).is_pending());
            assert!(parked.as_mut().poll(&mut context()).is_pending());
        }
        assert!(parked.as_mut().poll(&mut context()).is_ready());
        assert!(!pending());
    }
}
