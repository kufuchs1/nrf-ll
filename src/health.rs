//! Progress of the radio executor, independent of the application executor.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use embassy_time::Instant;

/// A radio operation is expected to make progress.
static ACTIVE: AtomicBool = AtomicBool::new(false);
/// Deadline in wrapping uptime seconds.
static DEADLINE: AtomicU32 = AtomicU32::new(0);

/// Arms the progress deadline for the next radio operation.
#[inline]
pub fn checkpoint(seconds: u32) {
    DEADLINE.store(seconds_now().wrapping_add(seconds), Ordering::Relaxed);
    ACTIVE.store(true, Ordering::Relaxed);
}

/// Whether the radio is idle or still within its progress deadline.
#[inline]
#[must_use = "radio health must gate watchdog feeding"]
pub fn healthy() -> bool { !ACTIVE.load(Ordering::Relaxed) || before(seconds_now(), DEADLINE.load(Ordering::Relaxed)) }

/// Suspends monitoring only for intentional indefinite idle/maintenance.
#[inline]
pub fn suspend() { ACTIVE.store(false, Ordering::Relaxed); }

/// Uptime modulo 2^32 seconds.
fn seconds_now() -> u32 { u32::try_from(Instant::now().as_secs() & u64::from(u32::MAX)).unwrap_or_default() }

/// Compares deadlines within half the wrapping time space.
const fn before(now: u32, deadline: u32) -> bool {
    let remaining = deadline.wrapping_sub(now);
    remaining != 0 && remaining < 0x8000_0000
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn radio_deadlines_expire_even_if_the_application_still_runs() {
        assert!(before(4, 10));
        assert!(!before(10, 10));
        assert!(!before(11, 10));
        assert!(before(u32::MAX, 2));
        assert!(!before(3, 2));
    }
}
