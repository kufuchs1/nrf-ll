//! nRF51 register code: the radio trim from FICR, LE 1M alone without fast
//! ramp-up, the 5-bit length field the CCM needs on the data channels, and a
//! second PPI channel in place of the FORK the nRF51 lacks.
//!
//! Of the nRF51 workarounds only the radio trim is applied here.
//! TODO(errata): check the nRF51802 errata document (it derives from the
//! nRF51822 revision 3 PANs) before adding any other workaround, among them
//! the TIMER events lost with PPI and invalid RTC reads right after its start.

use crate::radio::{LENGTH_BITS, Phy};
use embassy_nrf::pac::{
    CCM,
    FICR,
    PPI,
    RADIO,
    TEMP,
    ccm::vals::Mode as CcmMode,
    ficr::vals::Ble1mbit,
    radio::vals::{Mode, Txpower},
};

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
/// Programmable PPI channels above a channel that its stand-in for FORK
/// uses: the nRF51 has 16 programmable channels and no FORK.
const FORK_OFFSET: usize = 8;
/// Whether the radio has LE 2M.
pub const PHY_2M: bool = false;
/// Receiver ready time after RXEN, without a fast ramp-up: about 140 us.
/// Zephyr's nRF51 HAL uses 138 us.
/// TODO(datasheet): confirm it in the nRF51802 product specification.
pub const RX_READY_US: u32 = 140;

/// Sets the CCM mode for a packet. The nRF51 CCM has no data rate or length
/// setting: it follows LE 1M and payloads of up to 27 octets.
#[inline]
pub fn ccm_mode(mode: CcmMode, phy: Phy) {
    debug_assert!(phy == Phy::M1, "the nRF51 has LE 1M alone");
    CCM.mode().write(|w| w.set_mode(mode));
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

/// The die temperature in units of 0.25 °C, once a measurement is ready.
#[inline]
pub fn read_temperature() -> i32 { TEMP.temp().read().cast_signed() }

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

/// The address of a register for a PPI endpoint.
fn address<T>(register: *mut T) -> u32 { u32::try_from(register.addr()).unwrap_or_default() }
