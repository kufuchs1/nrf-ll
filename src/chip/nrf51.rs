//! nRF51 register code: the radio trim from FICR, LE 1M alone without fast
//! ramp-up, the 5-bit length field the CCM needs on the data channels, and a
//! second PPI channel in place of the FORK the nRF51 lacks.
//!
//! The clock sources of the board come from the firmware: the crystal
//! frequency, which CLOCK.XTALFREQ must match, and whether the low frequency
//! clock is the RC oscillator or a crystal, which sets the sleep clock
//! accuracy.
//!
//! Of the nRF51 workarounds only the radio trim and the sign of the
//! temperature are applied here.
//! TODO(errata): check the nRF51802 errata document (it derives from the
//! nRF51822 revision 3 PANs) before adding any other workaround, among them
//! the TIMER events lost with PPI, invalid RTC reads right after its start,
//! and the temperature offset that the nRF51 SDK writes to 0x4000_C504.

use crate::{
    clock::{HighFrequency, LowFrequency, RC_PPM},
    radio::{LENGTH_BITS, Phy},
};
use core::{
    future::poll_fn,
    sync::atomic::{AtomicBool, AtomicU32, Ordering},
    task::Poll,
};
use embassy_nrf::pac::{
    CCM,
    CLOCK,
    FICR,
    PPI,
    RADIO,
    TEMP,
    ccm::vals::Mode as CcmMode,
    clock::vals::Xtalfreq,
    ficr::vals::Ble1mbit,
    radio::vals::{Mode, Txpower},
};
use embassy_sync::waitqueue::AtomicWaker;

/// Time the high frequency crystal gets to start before TIMER0 restarts, at
/// first. TODO(datasheet): placeholders until the start-up time of the
/// board's crystal is known; the lead follows the crystal anyway.
pub const CRYSTAL_LEAD_US: u32 = 1500;
/// Bounds of the crystal lead time: an nRF51 crystal starts slower than
/// the nRF52832's.
pub const CRYSTAL_LEAD_RANGE_US: (u32, u32) = (300, 2500);
/// Largest advertising channel payload: 37 octets, a legacy advertising PDU.
pub const ADV_MAXLEN: u8 = 37;
/// Largest data channel payload: 27 octets and the four-byte MIC, as far as
/// the 5-bit length field reaches.
const DATA_MAXLEN: u8 = 31;
/// Length field size in bits on the data channels. The CCM reads the length
/// from the low five bits of the header byte that follows S0.
const DATA_LENGTH_BITS: u8 = 5;
/// S1 field size in bits on the data channels: the three bits above the
/// length make the header 16 bits on air and keep the S0, length and S1
/// bytes in RAM that the CCM expects, as in Zephyr's nRF51 port.
const DATA_S1_BITS: u8 = 3;
/// Busy-wait iterations for a decryption to finish after the packet end:
/// about the 250 us of the nRF52832's 2000 on the 16 MHz Cortex-M0.
pub const DECRYPT_WAIT: u32 = 400;
/// Largest payload the radio accepts on any channel, for the size of the
/// packet buffers: an advertising payload, as a data payload with its MIC
/// takes 31 octets at most.
pub const PAYLOAD_MAX: usize = 37;
/// Programmable PPI channels above a channel that its stand-in for FORK
/// uses: the nRF51 has 16 programmable channels and no FORK.
const FORK_OFFSET: usize = 8;
/// Transmit power levels in dBm, lowest first: the radio's levels from
/// -20 dBm up, without the +3 dBm of the nRF52832.
pub const LEVELS_DBM: [i8; 7] = [-20, -16, -12, -8, -4, 0, 4];
/// Whether the radio has LE 2M.
pub const PHY_2M: bool = false;
/// Receiver ready time after RXEN, without a fast ramp-up: about 140 us.
/// Zephyr's nRF51 HAL uses 138 us.
/// TODO(datasheet): confirm it in the nRF51802 product specification.
pub const RX_READY_US: u32 = 140;
/// CCM scratch space: 16 octets and the 27-octet payload the nRF51 CCM
/// handles at most, whatever the length field holds.
pub const SCRATCH_LEN: usize = 16 + 27;
/// Number of programmable PPI channels.
const PROGRAMMABLE_CHANNELS: usize = 16;
/// Whether the firmware configured the clock sources.
static CLOCKS_CONFIGURED: AtomicBool = AtomicBool::new(false);
/// Wakes [`calibrates_rc`] once the clock sources are configured.
static CLOCKS_CONFIGURED_WAKER: AtomicWaker = AtomicWaker::new();
/// Accuracy of the low frequency clock in ppm, as configured.
static SLEEP_CLOCK_PPM: AtomicU32 = AtomicU32::new(RC_PPM);
/// Whether the low frequency clock is the RC oscillator, as configured.
static SLEEP_CLOCK_RC: AtomicBool = AtomicBool::new(true);

/// Whether the low frequency clock is the RC oscillator, which needs
/// calibrating. Waits until the firmware configured the clock sources, so
/// the answer is the configured one, and the crystal frequency is set before
/// a calibration starts the crystal.
#[inline]
pub async fn calibrates_rc() -> bool {
    poll_fn(|cx| {
        CLOCKS_CONFIGURED_WAKER.register(cx.waker());
        if CLOCKS_CONFIGURED.load(Ordering::Acquire) { Poll::Ready(()) } else { Poll::Pending }
    })
    .await;
    SLEEP_CLOCK_RC.load(Ordering::Relaxed)
}

/// Sets the CCM mode for a packet. The nRF51 CCM has no data rate or length
/// setting: it follows LE 1M and payloads of up to 27 octets.
#[inline]
pub fn ccm_mode(mode: CcmMode, phy: Phy) {
    debug_assert!(phy == Phy::M1, "the nRF51 has LE 1M alone");
    CCM.mode().write(|w| w.set_mode(mode));
}

/// Takes the clock sources of the board: sets the crystal frequency, which
/// must happen before the crystal is first started, and keeps the sleep
/// clock's accuracy. Then marks the clocks configured, which lets
/// [`calibrates_rc`] answer.
#[inline]
pub fn configure_clocks(high_frequency: HighFrequency, low_frequency: LowFrequency) {
    CLOCK.xtalfreq().write(|w| w.set_xtalfreq(xtalfreq(high_frequency)));
    set_sleep_clock(low_frequency);
    CLOCKS_CONFIGURED.store(true, Ordering::Release);
    CLOCKS_CONFIGURED_WAKER.wake();
}

/// Disables PPI `channel` and the channel standing in for its FORK.
#[inline]
pub fn disable_channel(channel: usize) {
    PPI.chenclr().write(|w| {
        w.set_ch(channel, true);
        w.set_ch(fork_channel(channel), true);
    });
}

/// Nothing to do: the nRF51 has no fast ramp-up, its radio is ready about
/// 140 us after TXEN or RXEN.
#[inline]
pub const fn fast_ramp_up() {}

/// The programmable channel standing in for the FORK of `channel`.
const fn fork_channel(channel: usize) -> usize { channel.wrapping_add(FORK_OFFSET) }

/// Whether the channels standing in for the FORK of the channels `forked`
/// are programmable channels, distinct from each other and from every
/// channel in `used`.
#[must_use = "the check is only computed"]
pub const fn forks_are_free(forked: &[usize], used: &[usize]) -> bool {
    let mut rest = forked;
    while let Some((&channel, tail)) = rest.split_first() {
        let fork = fork_channel(channel);
        if fork >= PROGRAMMABLE_CHANNELS || contains(used, fork) || contains(tail, channel) {
            return false;
        }
        rest = tail;
    }
    true
}

/// Whether `channels` holds `channel`.
const fn contains(channels: &[usize], channel: usize) -> bool {
    let mut rest = channels;
    while let Some((&first, tail)) = rest.split_first() {
        if first == channel {
            return true;
        }
        rest = tail;
    }
    false
}

/// Copies the radio trim values for BLE 1 Mbit from FICR into the radio
/// after it was powered, if the factory requires them. The values are lost
/// whenever the radio is powered down.
#[inline]
pub fn radio_trim() {
    // The enable bit is active low.
    if FICR.overrideen().read().ble_1mbit() == Ble1mbit::Override {
        RADIO.override0().write_value(FICR.ble_1mbit(0).read());
        RADIO.override1().write_value(FICR.ble_1mbit(1).read());
        RADIO.override2().write_value(FICR.ble_1mbit(2).read());
        RADIO.override3().write_value(FICR.ble_1mbit(3).read());
        RADIO.override4().write(|w| {
            w.set_override4(FICR.ble_1mbit(4).read());
            w.set_enable(true);
        });
    }
}

/// The die temperature in units of 0.25 °C, once a measurement is ready. The
/// register holds a 10-bit two's complement value that the nRF51 does not
/// sign-extend (PAN 28, as the nRF51 SDK handles it); extending it is right
/// either way.
#[inline]
pub fn read_temperature() -> i32 { temperature(TEMP.temp().read()) }

/// Makes PPI `channel` disable `group` on its event: a second channel on
/// the same event triggers the group's disable task, and both are in the
/// group, so enabling the group arms them for one event. The event of
/// `channel` must be set before.
#[inline]
pub fn self_disabling(channel: usize, group: usize) {
    let fork = fork_channel(channel);
    let stand_in = PPI.ch(fork);
    stand_in.eep().write_value(PPI.ch(channel).eep().read());
    stand_in.tep().write_value(address(PPI.tasks_chg(group).dis().as_ptr()));
    PPI.chg(group).write(|w| {
        w.set_ch(channel, true);
        w.set_ch(fork, true);
    });
}

/// The temperature of a TEMP register value, sign-extended from its 10 bits.
const fn temperature(raw: u32) -> i32 { raw.wrapping_shl(22).cast_signed().wrapping_shr(22) }

/// Accuracy of the low frequency clock in ppm, as configured.
#[inline]
pub fn sleep_clock_ppm() -> u32 { SLEEP_CLOCK_PPM.load(Ordering::Relaxed) }

/// Keeps whether `low_frequency` is the RC oscillator, and its accuracy:
/// [`configure_clocks`] without the registers.
#[inline]
pub fn set_sleep_clock(low_frequency: LowFrequency) {
    let (rc, ppm) = match low_frequency {
        LowFrequency::Crystal { ppm } => (false, u32::from(ppm)),
        LowFrequency::Rc => (true, RC_PPM),
    };
    SLEEP_CLOCK_RC.store(rc, Ordering::Relaxed);
    SLEEP_CLOCK_PPM.store(ppm, Ordering::Relaxed);
}

/// Nothing to do: the RC oscillator needs no workaround around a
/// calibration on the nRF51 (anomaly 192 is an nRF52832 erratum).
#[inline]
pub const fn set_calibration_workaround(_calibrating: bool) {}

/// Sets the packet layout of the data channels or of the advertising
/// channels. On the data channels the length field has five bits, and the
/// three bits above it are the S1 field, so the header keeps its S0, length
/// and S1 bytes in RAM, which the CCM needs. A packet to send must keep the
/// S1 byte at zero: its bits go on air as the top bits of the length.
#[inline]
pub fn set_packet_layout(data_channel: bool) {
    let (maxlen, length_bits, s1_bits) =
        if data_channel { (DATA_MAXLEN, DATA_LENGTH_BITS, DATA_S1_BITS) } else { (ADV_MAXLEN, LENGTH_BITS, 0) };
    RADIO.pcnf1().modify(|w| w.set_maxlen(maxlen));
    RADIO.pcnf0().modify(|w| {
        w.set_lflen(length_bits);
        w.set_s0len(true);
        w.set_s1len(s1_bits);
    });
}

/// Sets the radio mode of `phy`: BLE 1 Mbit, the only one. The radio must be
/// disabled.
#[inline]
pub fn set_phy(phy: Phy) {
    debug_assert!(phy == Phy::M1, "the nRF51 has LE 1M alone");
    RADIO.mode().write(|w| w.set_mode(Mode::Ble1mbit));
}

/// The transmit power setting of the highest level the radio supports that
/// is not above `dbm`: +4, 0, -4, -8, -12, -16, -20 or -30 dBm.
#[inline]
pub const fn txpower(dbm: i8) -> Txpower {
    match dbm {
        4..=i8::MAX => Txpower::Pos4dBm,
        0..=3 => Txpower::_0dBm,
        -4..=-1 => Txpower::Neg4dBm,
        -8..=-5 => Txpower::Neg8dBm,
        -12..=-9 => Txpower::Neg12dBm,
        -16..=-13 => Txpower::Neg16dBm,
        -20..=-17 => Txpower::Neg20dBm,
        i8::MIN..=-21 => Txpower::Neg30dBm,
    }
}

/// The CLOCK.XTALFREQ setting of a crystal of `high_frequency`.
const fn xtalfreq(high_frequency: HighFrequency) -> Xtalfreq {
    match high_frequency {
        HighFrequency::Mhz16 => Xtalfreq::_16mHz,
        HighFrequency::Mhz32 => Xtalfreq::_32mHz,
    }
}

/// The address of a register for a PPI endpoint.
fn address<T>(register: *mut T) -> u32 { u32::try_from(register.addr()).unwrap_or_default() }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_crystal_frequency_maps_to_its_xtalfreq_setting() {
        assert_eq!(xtalfreq(HighFrequency::Mhz16).to_bits(), 0xFF);
        assert_eq!(xtalfreq(HighFrequency::Mhz32).to_bits(), 0x00);
    }

    #[test]
    fn fork_stand_ins_must_be_free_programmable_channels() {
        assert!(forks_are_free(&[1, 3], &[0, 1, 3]));
        assert!(!forks_are_free(&[1, 3], &[0, 1, 3, 9]));
        assert!(!forks_are_free(&[1, 8], &[0, 1, 8]));
        assert!(!forks_are_free(&[1, 1], &[0, 1]));
    }

    #[test]
    fn the_temperature_keeps_its_sign() {
        assert_eq!(temperature(0x064), 100);
        assert_eq!(temperature(0x3FF), -1);
        assert_eq!(temperature(0x3D8), -40);
        assert_eq!(temperature(0xFFFF_FFD8), -40);
    }

    #[test]
    fn a_power_between_levels_rounds_down_to_one() {
        assert!(txpower(3) == Txpower::_0dBm);
        assert!(txpower(-1) == Txpower::Neg4dBm);
        assert!(txpower(i8::MAX) == Txpower::Pos4dBm);
        assert!(txpower(-21) == Txpower::Neg30dBm);
        assert!(txpower(i8::MIN) == Txpower::Neg30dBm);
    }
}
