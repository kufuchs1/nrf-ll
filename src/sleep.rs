//! Sleeping on peripheral events instead of polling them.
//!
//! The link layer waits for radio events inside its interrupt, where lower
//! priority code must not run in between: the radio turns around within the
//! 150 us interframe space on its own. `WFE` stops the CPU clock without
//! leaving the interrupt. With `SEVONPEND`, an event whose interrupt is
//! enabled in the peripheral but disabled in the NVIC only marks it pending,
//! and that wakes the CPU without running a handler.
//!
//! The RTC0 TICK event wakes every sleep at least every 30.5 us, so a wait
//! for a condition without an event of its own, such as a deadline, still
//! ends close to it, and an event lost to a race cannot hang the link layer.

use cortex_m::peripheral::SCB;
use embassy_nrf::{
    interrupt::{self, InterruptExt as _},
    pac::RTC0 as RTC,
};

/// Bit of SCB SCR that turns a newly pending interrupt into a wake event.
const SEVONPEND: u32 = 1 << 4;

/// Clears the TICK event and every wake source the link layer uses.
fn clear() {
    RTC.events_tick().write_value(0);
    // Reading back completes the write before the NVIC is sampled again.
    _ = RTC.events_tick().read();
    interrupt::RADIO.unpend();
    interrupt::RNG.unpend();
    interrupt::RTC0.unpend();
}

/// Lets pending interrupts wake `WFE`. Interrupts that are enabled in the
/// NVIC are unaffected: they wake the CPU anyway.
#[inline]
pub fn enable() {
    // SAFETY: SCB::PTR points to the system control block, which is always
    // mapped.
    let scr = unsafe { &(*SCB::PTR).scr };
    // SAFETY: a read-modify-write on the single core before the link layer
    // runs; no other code changes SCR.
    unsafe {
        scr.modify(|value| value | SEVONPEND);
    }
}

/// Sleeps until `ready` holds. `ready` must only depend on events whose
/// interrupt is enabled in their peripheral, or on time.
#[inline]
pub fn until<Ready>(mut ready: Ready)
where
    Ready: FnMut() -> bool,
{
    RTC.intenset().write(|w| w.set_tick(true));
    while !ready() {
        clear();
        if ready() {
            break;
        }
        cortex_m::asm::wfe();
    }
    RTC.intenclr().write(|w| w.set_tick(true));
    clear();
}
