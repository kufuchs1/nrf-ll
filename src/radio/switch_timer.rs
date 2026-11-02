//! The turnaround on the nRF52832: TIMER1, which PPI starts at the packet
//! END, enables the radio one interframe space after the packet through its
//! compare, as Zephyr's software switch does. The radio's own interframe
//! timing works only with the slow ramp-up.

use super::{REGS, Radio, Turnaround};
use crate::sleep;
use core::sync::atomic::{Ordering, compiler_fence};
use embassy_nrf::pac::{
    PPI,
    TIMER1 as SWITCH,
    timer::vals::{Bitmode, Mode as TimerMode},
};

/// Programmable PPI channel: RADIO END to TIMER1 START, which times the
/// turnaround after a packet.
const PPI_SWITCH_START: usize = 4;
/// Programmable PPI channel: TIMER1 COMPARE0 to RADIO TXEN or RXEN.
const PPI_SWITCH_ENABLE: usize = 5;
/// TIMER1 ticks per microsecond, at 16 MHz.
const SWITCH_TICKS_PER_US: u32 = 16;

/// The address of a register for a PPI endpoint.
fn address<T>(register: *mut T) -> u32 { u32::try_from(register.addr()).unwrap_or_default() }

/// Sets what `radio` does after the current packet, timed for its PHY.
#[inline]
pub fn arm(radio: &Radio<'_>, turnaround: Turnaround) {
    REGS.shorts().write(|w| {
        w.set_ready_start(true);
        w.set_end_disable(true);
        w.set_address_rssistart(true);
        w.set_disabled_rssistop(true);
    });
    PPI.chenclr().write(|w| {
        w.set_ch(PPI_SWITCH_START, true);
        w.set_ch(PPI_SWITCH_ENABLE, true);
    });
    SWITCH.tasks_stop().write_value(1);
    // STOP alone keeps the timer's clock requested (nRF52832 anomaly
    // 78), as Zephyr notes for its software switch timer.
    SWITCH.tasks_shutdown().write_value(1);
    SWITCH.tasks_clear().write_value(1);
    SWITCH.events_compare(0).write_value(0);
    let (task, offset) = match turnaround {
        Turnaround::None => return,
        Turnaround::Receive => (REGS.tasks_rxen().as_ptr(), radio.phy.listen_offset_us()),
        Turnaround::Transmit => (REGS.tasks_txen().as_ptr(), radio.phy.response_offset_us(radio.phy)),
    };
    SWITCH.cc(0).write_value(offset.saturating_mul(SWITCH_TICKS_PER_US));
    PPI.ch(PPI_SWITCH_ENABLE).tep().write_value(address(task));
    compiler_fence(Ordering::SeqCst);
    PPI.chenset().write(|w| {
        w.set_ch(PPI_SWITCH_START, true);
        w.set_ch(PPI_SWITCH_ENABLE, true);
    });
}

/// Sets up TIMER1 and the PPI channels that time the turnarounds.
#[inline]
pub fn init() {
    SWITCH.tasks_stop().write_value(1);
    SWITCH.mode().write(|w| w.set_mode(TimerMode::Timer));
    SWITCH.bitmode().write(|w| w.set_bitmode(Bitmode::_16bit));
    SWITCH.prescaler().write(|w| w.set_prescaler(0));
    SWITCH.shorts().write(|w| {
        w.set_compare_clear(0, true);
        w.set_compare_stop(0, true);
    });
    SWITCH.tasks_clear().write_value(1);
    let start = PPI.ch(PPI_SWITCH_START);
    start.eep().write_value(address(REGS.events_end().as_ptr()));
    start.tep().write_value(address(SWITCH.tasks_start().as_ptr()));
    PPI.ch(PPI_SWITCH_ENABLE).eep().write_value(address(SWITCH.events_compare(0).as_ptr()));
}

/// Sleeps until the turnaround enabled the radio again, and clears the
/// disabled event of the packet before it.
#[inline]
pub fn wait() {
    SWITCH.intenset().write(|w| w.set_compare(0, true));
    sleep::until(|| SWITCH.events_compare(0).read() != 0);
    SWITCH.intenclr().write(|w| w.set_compare(0, true));
    SWITCH.events_compare(0).write_value(0);
    REGS.events_disabled().write_value(0);
    compiler_fence(Ordering::SeqCst);
}
