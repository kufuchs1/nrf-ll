//! Shared entropy for async tasks and preempting radio events.

use crate::sleep;
use core::{cell::Cell, future::poll_fn, task::Poll};
use embassy_nrf::pac::RNG as REGS;
use embassy_sync::{
    blocking_mutex::{Mutex, raw::CriticalSectionRawMutex},
    mutex::Mutex as AsyncMutex,
    waitqueue::AtomicWaker,
};

/// The hardware generator and its shared ownership.
static RNG: Generator<Hardware> = Generator::new(Hardware);

/// Register operations, replaceable by a host backend for cancellation tests.
trait Backend {
    /// Enables the next data-ready interrupt.
    fn arm(&self);
    /// Disables the data-ready interrupt without consuming a byte.
    fn disarm(&self);
    /// Starts entropy collection with bias correction.
    fn start(&self);
    /// Stops collection after the final owner finishes.
    fn stop(&self);
    /// Consumes one ready byte without waiting.
    fn try_read(&self) -> Option<u8>;
    /// Sleeps in the timing-critical synchronous context.
    fn wait(&self);
}

/// Serializes async consumers and register transactions, not radio preemption.
struct Generator<Peripheral> {
    /// Only one async caller owns the registered waker at a time.
    asynchronous: AsyncMutex<CriticalSectionRawMutex, ()>,
    /// Hardware or host test backend.
    peripheral:   Peripheral,
    /// Wakes the current async consumer.
    ready:        AtomicWaker,
    /// Number of synchronous and async callers still collecting entropy.
    users:        Mutex<CriticalSectionRawMutex, Cell<usize>>,
}

impl<Peripheral: Backend> Generator<Peripheral> {
    /// Keeps collection running until this particular caller finishes or
    /// cancels.
    fn acquire(&self) -> Lease<'_, Peripheral> {
        self.users.lock(|users| {
            if users.get() == 0 {
                self.peripheral.start();
            }
            users.set(users.get().saturating_add(1));
        });
        Lease { generator: self }
    }

    /// Collects bytes without yielding inside a radio event.
    fn fill(&self, bytes: &mut [u8]) {
        if bytes.is_empty() {
            return;
        }
        let _lease = self.acquire();
        for byte in bytes {
            loop {
                if let Some(value) = self.try_read() {
                    *byte = value;
                    break;
                }
                self.peripheral.wait();
            }
        }
    }

    /// Collects bytes while allowing other tasks and radio events to run.
    async fn fill_async(&self, bytes: &mut [u8]) {
        if bytes.is_empty() {
            return;
        }
        let _asynchronous = self.asynchronous.lock().await;
        let _lease = self.acquire();
        for byte in bytes {
            *byte = poll_fn(|cx| {
                self.ready.register(cx.waker());
                self.try_read().map_or(Poll::Pending, Poll::Ready)
            })
            .await;
        }
    }

    /// Wakes a task without consuming entropy needed by a preempting caller.
    fn interrupt(&self) {
        self.peripheral.disarm();
        self.ready.wake();
    }

    /// Initializes a generator without touching the hardware.
    const fn new(peripheral: Peripheral) -> Self {
        Self {
            asynchronous: AsyncMutex::new(()),
            peripheral,
            ready: AtomicWaker::new(),
            users: Mutex::new(Cell::new(0)),
        }
    }

    /// Atomically samples or arms the level-triggered data-ready interrupt.
    fn try_read(&self) -> Option<u8> {
        self.users.lock(|_| {
            let result = self.peripheral.try_read();
            if result.is_none() {
                self.peripheral.arm();
            }
            result
        })
    }
}

/// nRF52832 entropy register backend.
struct Hardware;

impl Backend for Hardware {
    fn arm(&self) { REGS.intenset().write(|w| w.set_valrdy(true)); }

    fn disarm(&self) { REGS.intenclr().write(|w| w.set_valrdy(true)); }

    fn start(&self) {
        REGS.config().write(|w| w.set_dercen(true));
        REGS.events_valrdy().write_value(0);
        REGS.tasks_start().write_value(1);
    }

    fn stop(&self) {
        self.disarm();
        REGS.tasks_stop().write_value(1);
    }

    fn try_read(&self) -> Option<u8> {
        if REGS.events_valrdy().read() == 0 {
            return None;
        }
        let value = REGS.value().read().value();
        REGS.events_valrdy().write_value(0);
        Some(value)
    }

    fn wait(&self) { sleep::until(|| REGS.events_valrdy().read() != 0); }
}

/// A borrow that keeps the peripheral running, including across `.await`.
struct Lease<'generator, Peripheral: Backend> {
    /// Generator this lease keeps active.
    generator: &'generator Generator<Peripheral>,
}

impl<Peripheral: Backend> Drop for Lease<'_, Peripheral> {
    fn drop(&mut self) {
        self.generator.users.lock(|users| {
            users.set(users.get().saturating_sub(1));
            if users.get() == 0 {
                self.generator.peripheral.stop();
            }
        });
    }
}

/// Fills bytes synchronously for callers that cannot yield, including crypto.
#[inline]
pub fn fill(bytes: &mut [u8]) { RNG.fill(bytes); }

/// Fills bytes without occupying the executor while entropy is collected.
///
/// Requires [`on_interrupt`] to be called from an enabled RNG interrupt.
/// Cancellation stops the peripheral unless another caller still owns it;
/// the already-filled prefix of `bytes` remains initialized.
#[inline]
pub async fn fill_async(bytes: &mut [u8]) { RNG.fill_async(bytes).await; }

/// Handles RNG data-ready: mask the source and wake the async owner.
#[inline]
pub fn on_interrupt() { RNG.interrupt(); }

#[cfg(test)]
mod tests {
    use super::*;
    use core::{
        future::Future,
        pin::pin,
        sync::atomic::{AtomicBool, AtomicUsize, Ordering},
        task::{Context, Waker},
    };

    struct Mock {
        armed:  AtomicBool,
        starts: AtomicUsize,
        stops:  AtomicUsize,
        value:  Mutex<CriticalSectionRawMutex, Cell<Option<u8>>>,
    }

    impl Backend for Mock {
        fn arm(&self) { self.armed.store(true, Ordering::Relaxed); }

        fn disarm(&self) { self.armed.store(false, Ordering::Relaxed); }

        fn start(&self) { self.starts.fetch_add(1, Ordering::Relaxed); }

        fn stop(&self) {
            self.disarm();
            self.stops.fetch_add(1, Ordering::Relaxed);
        }

        fn try_read(&self) -> Option<u8> { self.value.lock(Cell::take) }

        fn wait(&self) {
            panic!("test expected a ready synchronous byte");
        }
    }

    fn generator() -> Generator<Mock> {
        Generator::new(Mock {
            armed:  AtomicBool::new(false),
            starts: AtomicUsize::new(0),
            stops:  AtomicUsize::new(0),
            value:  Mutex::new(Cell::new(None)),
        })
    }

    #[test]
    fn cancellation_releases_hardware_and_async_lock() {
        let rng = generator();
        let mut bytes = [0; 2];
        let mut context = Context::from_waker(Waker::noop());
        {
            let mut future = pin!(rng.fill_async(&mut bytes));
            assert!(future.as_mut().poll(&mut context).is_pending());
            assert!(rng.peripheral.armed.load(Ordering::Relaxed));
            rng.peripheral.value.lock(|value| value.set(Some(0xA5)));
            rng.interrupt();
            assert!(future.as_mut().poll(&mut context).is_pending());
        }
        assert_eq!(bytes, [0xA5, 0]);
        assert_eq!(rng.peripheral.stops.load(Ordering::Relaxed), 1);
        assert!(!rng.peripheral.armed.load(Ordering::Relaxed));
        let mut next = [0];
        let mut future = pin!(rng.fill_async(&mut next));
        assert!(future.as_mut().poll(&mut context).is_pending());
        rng.peripheral.value.lock(|value| value.set(Some(0x3C)));
        rng.interrupt();
        assert!(future.as_mut().poll(&mut context).is_ready());
        assert_eq!(rng.peripheral.starts.load(Ordering::Relaxed), 2);
        assert_eq!(rng.peripheral.stops.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn synchronous_preemption_and_cancelled_waiter_preserve_async_owner() {
        let rng = generator();
        let mut owner_bytes = [0];
        let mut other_bytes = [0];
        let mut context = Context::from_waker(Waker::noop());
        let mut owner = pin!(rng.fill_async(&mut owner_bytes));
        assert!(owner.as_mut().poll(&mut context).is_pending());
        {
            let mut waiter = pin!(rng.fill_async(&mut other_bytes));
            assert!(waiter.as_mut().poll(&mut context).is_pending());
        }
        rng.peripheral.value.lock(|value| value.set(Some(7)));
        let mut synchronous = [0];
        rng.fill(&mut synchronous);
        assert_eq!(synchronous, [7]);
        assert_eq!(rng.peripheral.starts.load(Ordering::Relaxed), 1);
        assert_eq!(rng.peripheral.stops.load(Ordering::Relaxed), 0);
        assert!(owner.as_mut().poll(&mut context).is_pending());
        rng.peripheral.value.lock(|value| value.set(Some(8)));
        rng.interrupt();
        assert!(owner.as_mut().poll(&mut context).is_ready());
        assert_eq!(rng.peripheral.stops.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn empty_requests_do_not_power_the_peripheral() {
        let rng = generator();
        rng.fill(&mut []);
        let mut future = pin!(rng.fill_async(&mut []));
        assert!(future.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_ready());
        assert_eq!(rng.peripheral.starts.load(Ordering::Relaxed), 0);
    }
}
