//! nRF52832 register code: the errata workarounds, the fast ramp-up, LE 2M,
//! the radio's S1 byte in RAM and the CCM's extended length mode.

use crate::radio::{LENGTH_BITS, Phy};
use core::ptr::{read_volatile, with_exposed_provenance_mut, write_volatile};
use embassy_nrf::pac::{
    CCM,
    PPI,
    RADIO,
    TEMP,
    ccm::vals::{Datarate, Length, Mode as CcmMode},
    radio::vals::{Mode, Plen, Ru, S1incl, Txpower},
};

/// Register holding the enable bit for the fixes of anomalies 102, 106 and
/// 107 (anomaly 182).
const ANOMALY_182_REGISTER: usize = 0x4000_173C;
/// Enable bit in [`ANOMALY_182_REGISTER`].
const ANOMALY_182_BIT: u32 = 1 << 10;
/// Register of the workaround for nRF52832 anomaly 192: the RC oscillator's
/// frequency can be off by more than 500 ppm after a calibration during
/// which the CPU slept.
const ANOMALY_192_REGISTER: usize = 0x4000_0C34;
/// Largest advertising channel payload the radio accepts: as on the data
/// channels.
pub const ADV_MAXLEN: u8 = MAX_PAYLOAD;
/// Busy-wait iterations for a decryption to finish after the packet end,
/// about 250 us at 64 MHz.
pub const DECRYPT_WAIT: u32 = 2000;
/// Transmit power levels in dBm, lowest first: the radio's levels from
/// -20 dBm up.
pub const LEVELS_DBM: [i8; 8] = [-20, -16, -12, -8, -4, 0, 3, 4];
/// Largest payload the radio accepts on any channel.
const MAX_PAYLOAD: u8 = 255;
/// Whether the radio has LE 2M.
pub const PHY_2M: bool = true;
/// Receiver ready time after RXEN with fast ramp-up.
pub const RX_READY_US: u32 = 40;

/// Sets the CCM mode for a packet on `phy`, in the extended length mode.
#[inline]
pub fn ccm_mode(mode: CcmMode, phy: Phy) {
    CCM.mode().write(|w| {
        w.set_mode(mode);
        w.set_datarate(datarate(phy));
        w.set_length(Length::Extended);
    });
}

/// The CCM data rate matching `phy`, for decryption on the fly.
const fn datarate(phy: Phy) -> Datarate {
    match phy {
        Phy::M1 => Datarate::_1mbit,
        Phy::M2 => Datarate::_2mbit,
    }
}

/// Disables PPI `channel` alone.
#[inline]
pub fn disable_channel(channel: usize) { PPI.chenclr().write(|w| w.set_ch(channel, true)); }

/// The fast ramp-up of 40 us instead of 140 us.
#[inline]
pub fn fast_ramp_up() { RADIO.modecnf0().write(|w| w.set_ru(Ru::Fast)); }

/// Applies the fix for anomaly 182, which covers anomalies 102, 106 and 107,
/// after the radio was powered.
#[inline]
pub fn radio_trim() {
    let register = with_exposed_provenance_mut::<u32>(ANOMALY_182_REGISTER);
    // SAFETY: the anomaly 182 register is a word-aligned RADIO register.
    let value = unsafe { read_volatile(register) };
    // SAFETY: Nordic documents this write for the anomaly 182 fix.
    let () = unsafe { write_volatile(register, value | ANOMALY_182_BIT) };
}

/// The die temperature in units of 0.25 °C, once a measurement is ready.
#[inline]
pub fn read_temperature() -> i32 { TEMP.temp().read().cast_signed() }

/// Makes PPI `channel` disable `group` on its event, with the channel alone
/// in the group: enabling the group arms the channel for one event.
#[inline]
pub fn self_disabling(channel: usize, group: usize) {
    PPI.chg(group).write(|w| w.set_ch(channel, true));
    PPI.fork(channel).tep().write_value(address(PPI.tasks_chg(group).dis().as_ptr()));
}

/// Sets the workaround for anomaly 192 while an RC calibration may run, and
/// clears it after.
pub fn set_calibration_workaround(calibrating: bool) {
    let register = with_exposed_provenance_mut::<u32>(ANOMALY_192_REGISTER);
    // SAFETY: Nordic documents these writes for the anomaly 192 workaround.
    let () = unsafe { write_volatile(register, if calibrating { 2 } else { 0 }) };
}

/// Sets whether packets in RAM carry the S1 byte, which the CCM needs on
/// data channels.
#[inline]
pub fn set_packet_layout(data_channel: bool) {
    // Data PDUs carry up to 251 payload octets and the four-byte MIC
    // with the data length extension, as advertising PDUs fit 255 too:
    // the radio receives and sends whole packets of either.
    RADIO.pcnf1().modify(|w| w.set_maxlen(MAX_PAYLOAD));
    RADIO.pcnf0().modify(|w| {
        w.set_lflen(LENGTH_BITS);
        w.set_s0len(true);
        w.set_s1len(0);
        w.set_s1incl(if data_channel { S1incl::Include } else { S1incl::Automatic });
    });
}

/// Sets the radio mode and preamble of `phy`. The radio must be disabled.
#[inline]
pub fn set_phy(phy: Phy) {
    RADIO.mode().write(|w| {
        w.set_mode(match phy {
            Phy::M1 => Mode::Ble1mbit,
            Phy::M2 => Mode::Ble2mbit,
        });
    });
    RADIO.pcnf0().modify(|w| {
        w.set_plen(match phy {
            Phy::M1 => Plen::_8bit,
            Phy::M2 => Plen::_16bit,
        });
    });
}

/// The transmit power setting of `dbm`, one of the levels the radio
/// supports: the register takes the level in dBm.
#[inline]
pub const fn txpower(dbm: i8) -> Txpower { Txpower::from_bits(dbm.cast_unsigned()) }

/// The address of a register for a PPI endpoint.
fn address<T>(register: *mut T) -> u32 { u32::try_from(register.addr()).unwrap_or_default() }
