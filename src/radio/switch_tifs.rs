//! The turnaround on the nRF51: the radio's own interframe timing. With the
//! END to DISABLE and DISABLED to TXEN or RXEN shortcuts, the radio ramps up
//! right after a packet and starts sending 150 us (TIFS) after its END by
//! itself, as Nordic's nRF51 SoftDevices and Zephyr's nRF51 port do. The
//! nRF51 has only the slow ramp-up, with which this timing works, and keeps
//! TIMER1 and the PPI channels 4 and 5 free.
//!
//! The radio reads the packet pointer and the header when it starts, about
//! 150 us after the END of the packet before, so the CPU has that long to
//! decide on the answer.
//! TODO(timing): that is about 2,200 cycles of the 16 MHz Cortex-M0, for
//! the answer of a connection event (`Connection::respond` with the CCM
//! encryption) and for the scan request checks of the advertiser, which the
//! nRF52832 does in the same time at 64 MHz. A late answer sends whatever
//! the packet pointer points at. Measure the slack on hardware before relying
//! on it, and move work out of the interframe space where it is short.

use super::{REGS, Radio, Turnaround};
use core::sync::atomic::{Ordering, compiler_fence};

/// Sets what the radio does after the current packet.
#[inline]
pub fn arm(turnaround: Turnaround) {
    REGS.shorts().write(|w| {
        w.set_ready_start(true);
        w.set_end_disable(true);
        w.set_address_rssistart(true);
        w.set_disabled_rssistop(true);
        w.set_disabled_txen(turnaround == Turnaround::Transmit);
        w.set_disabled_rxen(turnaround == Turnaround::Receive);
    });
}

/// Nothing to set up: the radio times its turnarounds itself, with the
/// interframe space the radio driver sets.
#[inline]
pub const fn init() {}

/// Sleeps until the radio was disabled after the packet, which enabled it
/// again through the shortcut, and clears the disabled event.
#[inline]
pub fn wait() {
    Radio::sleep_on(|w| w.set_disabled(true), || REGS.events_disabled().read() != 0);
    REGS.events_disabled().write_value(0);
    compiler_fence(Ordering::SeqCst);
}
