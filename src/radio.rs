//! BLE 1 Mbit radio driver.

/// The turnaround timing: the radio's own on the nRF51.
#[cfg(feature = "nrf51")]
#[path = "radio/switch_tifs.rs"]
mod switch;
/// The turnaround timing: TIMER1 on the nRF52832.
#[cfg(feature = "nrf52832")]
#[path = "radio/switch_timer.rs"]
mod switch;

use crate::{chip, sleep};
use core::sync::atomic::{Ordering, compiler_fence};
#[cfg(feature = "nrf52832")]
use embassy_nrf::peripherals::TIMER1;
use embassy_nrf::{
    Peri,
    interrupt::{self, InterruptExt as _},
    pac::{
        RADIO as REGS,
        radio::{
            regs::Int,
            vals::{Crcstatus, Endian, Len, Mode, Skipaddr, State, Txpower},
        },
    },
    peripherals::RADIO,
};

/// Base address length in bytes.
const BASE_ADDRESS_LEN: u8 = 3;
/// BLE CRC polynomial x^24 + x^10 + x^9 + x^6 + x^4 + x^3 + x + 1.
const CRC_POLY: u32 = 0x0000_065B;
/// Interframe space in microseconds.
const IFS_US: u8 = 150;
/// Length field size in bits.
pub(crate) const LENGTH_BITS: u8 = 8;
/// Receiver ready time after RXEN: 40 us with the fast ramp-up of the
/// nRF52832, about 140 us on the nRF51.
pub const RX_READY_US: u32 = chip::RX_READY_US;
/// Time by which the receiver is ready before the earliest packet start one
/// interframe space after our packet: the peer may be 2 us early, and the
/// receiver locks onto the preamble before the access address.
#[cfg(feature = "nrf52832")]
const RX_EARLY_US: u32 = 8;
/// Whitening initial value bit that the radio requires to be set.
const WHITENING_BIT6: u8 = 0x40;

/// Physical layer of a connection.
#[derive(Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum Phy {
    /// LE 1M: 1 Mbit/s, 8-bit preamble.
    M1,
    /// LE 2M: 2 Mbit/s, 16-bit preamble, half the airtime.
    M2,
}

impl Phy {
    /// Time from the start of a packet to the end of its access address:
    /// 8 preamble and 32 address bits at 1 Mbit/s, 16 and 32 at 2 Mbit/s.
    #[inline]
    #[must_use = "the time is only computed"]
    pub const fn address_offset_us(self) -> u32 {
        match self {
            Self::M1 => 40,
            Self::M2 => 24,
        }
    }

    /// The PHY of a link layer PHY bit field with exactly one of 1M and 2M,
    /// if the radio has it: the nRF51 has LE 1M alone.
    #[inline]
    #[must_use = "the PHY is only decoded"]
    pub const fn from_bits(bits: u8) -> Option<Self> {
        match bits {
            1 => Some(Self::M1),
            2 if chip::PHY_2M => Some(Self::M2),
            _ => None,
        }
    }

    /// The link layer and HCI value of the PHY.
    #[inline]
    #[must_use = "the value is only computed"]
    pub const fn hci(self) -> u8 {
        match self {
            Self::M1 => 1,
            Self::M2 => 2,
        }
    }

    /// TIMER RXEN offset from the END of our packet sent on this PHY, so the
    /// receiver is ready shortly before a packet one interframe space later.
    /// The fast ramp-up and TX chain timings follow Zephyr's Nordic HAL.
    #[cfg(feature = "nrf52832")]
    #[must_use = "the delay is only computed"]
    #[inline]
    pub const fn listen_offset_us(self) -> u32 {
        let rx_ready_ns = RX_READY_US.saturating_mul(1000);
        let tx_chain_ns = 600_u32;
        let Some(delay) = rx_ready_ns.saturating_add(tx_chain_ns).saturating_add(999).checked_div(1000) else {
            return 0;
        };
        150_u32.saturating_sub(delay).saturating_sub(RX_EARLY_US)
    }

    /// TIMER TXEN offset from RX END for a 150-us interframe space.
    /// nRF52832 fast-ramp and RX-chain timings match Zephyr's Nordic HAL.
    #[cfg(feature = "nrf52832")]
    #[must_use = "the delay is only computed"]
    #[inline]
    pub const fn response_offset_us(self, receive: Self) -> u32 {
        let tx_ready_ns = match self {
            Self::M1 => 41_050_u32,
            Self::M2 => 40_000_u32,
        };
        let rx_chain_ns = match receive {
            Self::M1 => 9400_u32,
            Self::M2 => 5450_u32,
        };
        let Some(delay) = tx_ready_ns.saturating_add(rx_chain_ns).saturating_add(500).checked_div(1000) else {
            return 0;
        };
        150_u32.saturating_sub(delay)
    }
}

/// What the radio does after a packet.
///
/// On the nRF52832 a turnaround is timed by TIMER1,
/// which PPI starts at the packet END, and whose compare enables the radio
/// one interframe space after the packet, as Zephyr's software switch does:
/// the radio's own interframe timing works only with the slow ramp-up. The
/// nRF51 has only that ramp-up and uses the radio's own timing.
#[derive(Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum Turnaround {
    /// Disables after the packet.
    None,
    /// Starts receiving one interframe space after the packet.
    Receive,
    /// Starts sending one interframe space after the packet.
    Transmit,
}

/// The radio, configured for BLE, with fast ramp-up on the nRF52832.
pub struct Radio<'peripherals> {
    /// The radio peripheral, owned for the lifetime of the driver.
    _peripheral: Peri<'peripherals, RADIO>,
    /// The timer of the turnarounds, owned for the lifetime of the driver.
    #[cfg(feature = "nrf52832")]
    _switch:     Peri<'peripherals, TIMER1>,
    /// PHY the turnarounds are timed for.
    #[cfg(feature = "nrf52832")]
    phy:         Phy,
}

impl<'peripherals> Radio<'peripherals> {
    /// Clears the access address event.
    #[inline]
    pub fn clear_address(&mut self) { REGS.events_address().write_value(0); }

    /// Whether the last received packet had a valid CRC.
    #[inline]
    #[must_use = "the CRC status is only read"]
    pub fn crc_ok(&self) -> bool { REGS.crcstatus().read().crcstatus() == Crcstatus::CrcOk }

    /// Stops sending or receiving and waits until the radio is disabled.
    #[inline]
    pub fn disable(&mut self) {
        // The turnaround goes first: on the nRF51 the disabled event that
        // follows would otherwise enable the radio again through the
        // shortcut, and send.
        self.set_turnaround(Turnaround::None);
        if REGS.state().read().state() != State::Disabled {
            REGS.events_disabled().write_value(0);
            REGS.tasks_disable().write_value(1);
            Self::sleep_on(|w| w.set_disabled(true), || self.is_disabled());
        }
        REGS.events_disabled().write_value(0);
        compiler_fence(Ordering::SeqCst);
    }

    /// Whether an access address was received or sent since the last start.
    #[inline]
    #[must_use = "the event is only read"]
    pub fn has_address(&self) -> bool { REGS.events_address().read() != 0 }

    /// Whether the radio became disabled since the last start.
    #[inline]
    #[must_use = "the event is only read"]
    pub fn is_disabled(&self) -> bool { REGS.events_disabled().read() != 0 }

    /// Whether a packet ended since the last start.
    #[inline]
    #[must_use = "the event is only read"]
    pub fn is_end(&self) -> bool { REGS.events_end().read() != 0 }

    /// Powers the radio and configures it for BLE 1 Mbit: on the nRF52832
    /// with the fast ramp-up and TIMER1 timing the turnarounds, on the nRF51
    /// with the radio's own interframe timing and the radio trim values of
    /// FICR. The high frequency crystal must be running.
    #[inline]
    #[must_use = "the radio is unusable once dropped"]
    pub fn new(
        radio: Peri<'peripherals, RADIO>,
        #[cfg(feature = "nrf52832")] switch: Peri<'peripherals, TIMER1>,
    ) -> Self {
        sleep::enable();
        REGS.power().write(|w| w.set_power(true));
        chip::radio_trim();
        REGS.mode().write(|w| w.set_mode(Mode::Ble1mbit));
        chip::fast_ramp_up();
        REGS.tifs().write(|w| w.set_tifs(IFS_US));
        switch::init();
        REGS.pcnf0().write(|w| {
            w.set_lflen(LENGTH_BITS);
            w.set_s0len(true);
            w.set_s1len(0);
        });
        REGS.pcnf1().write(|w| {
            w.set_maxlen(chip::ADV_MAXLEN);
            w.set_statlen(0);
            w.set_balen(BASE_ADDRESS_LEN);
            w.set_endian(Endian::Little);
            w.set_whiteen(true);
        });
        REGS.crccnf().write(|w| {
            w.set_len(Len::Three);
            w.set_skipaddr(Skipaddr::Skip);
        });
        REGS.crcpoly().write(|w| w.set_crcpoly(CRC_POLY));
        REGS.txaddress().write(|w| w.set_txaddress(0));
        REGS.rxaddresses().write(|w| w.set_addr0(true));
        REGS.txpower().write(|w| w.set_txpower(Txpower::_0dBm));
        Self {
            _peripheral: radio,
            #[cfg(feature = "nrf52832")]
            _switch: switch,
            #[cfg(feature = "nrf52832")]
            phy: Phy::M1,
        }
    }

    /// Clears the events and arms the radio for a reception started by a
    /// task or a PPI channel, with `turnaround` after the packet.
    ///
    /// # Safety
    ///
    /// As for [`Self::set_buffer`].
    #[inline]
    pub unsafe fn prepare(&mut self, buffer: *mut u8, turnaround: Turnaround) {
        // SAFETY: the caller upholds the contract of `set_buffer`.
        let () = unsafe { self.set_buffer(buffer) };
        self.set_turnaround(turnaround);
        REGS.events_address().write_value(0);
        REGS.events_end().write_value(0);
        REGS.events_disabled().write_value(0);
        REGS.events_rssiend().write_value(0);
        compiler_fence(Ordering::SeqCst);
    }

    /// Points the radio at `buffer` for the reception that the shortcut after
    /// the current transmission starts, and clears that transmission's
    /// address, end and signal strength events. Call it once the
    /// transmission ended, before the reception starts.
    ///
    /// # Safety
    ///
    /// As for [`Self::set_buffer`].
    #[inline]
    pub unsafe fn rearm_receive(&mut self, buffer: *mut u8) {
        // SAFETY: the caller upholds the contract of `set_buffer`.
        let () = unsafe { self.set_buffer(buffer) };
        REGS.events_address().write_value(0);
        REGS.events_end().write_value(0);
        REGS.events_rssiend().write_value(0);
        compiler_fence(Ordering::SeqCst);
    }

    /// Starts receiving now.
    #[inline]
    pub fn receive(&mut self) { REGS.tasks_rxen().write_value(1); }

    /// Received signal strength of the last packet in -dBm, measured when
    /// its access address arrived.
    #[inline]
    #[must_use = "the signal strength is only read"]
    pub fn rssi(&self) -> Option<u8> {
        (REGS.events_rssiend().read() != 0).then(|| REGS.rssisample().read().rssisample())
    }

    /// Sets the access address of the following packets.
    #[inline]
    pub fn set_access_address(&mut self, address: u32) {
        REGS.base0().write_value(address.wrapping_shl(8));
        REGS.prefix0().write(|w| w.set_ap0(address.to_le_bytes().last().copied().unwrap_or_default()));
    }

    /// Sets the packet buffer the radio sends from or receives into by DMA.
    ///
    /// # Safety
    ///
    /// `buffer` must point to RAM holding the whole PDU its header announces
    /// for a transmission, and [`BUFFER_LEN`](crate::pdu::BUFFER_LEN)
    /// writable bytes for a reception. It must stay valid, and the CPU must not
    /// access it while the radio may, until the radio is disabled or given
    /// another buffer.
    #[inline]
    pub unsafe fn set_buffer(&mut self, buffer: *mut u8) {
        compiler_fence(Ordering::SeqCst);
        REGS.packetptr().write_value(u32::try_from(buffer.addr()).unwrap_or_default());
    }

    /// Tunes to a BLE channel index and sets the matching whitening.
    #[inline]
    pub fn set_channel(&mut self, channel: u8) {
        REGS.frequency().write(|w| w.set_frequency(frequency(channel)));
        REGS.datawhiteiv().write(|w| w.set_datawhiteiv(channel | WHITENING_BIT6));
    }

    /// Sets the CRC initial value of the following packets.
    #[inline]
    pub fn set_crc_init(&mut self, init: u32) { REGS.crcinit().write(|w| w.set_crcinit(init)); }

    /// Sets the PHY of the following packets: LE 1M, the only one on the
    /// nRF51. The radio must be disabled.
    #[cfg(feature = "nrf51")]
    #[inline]
    pub fn set_phy(&mut self, phy: Phy) { chip::set_phy(phy); }

    /// Sets the PHY of the following packets. The radio must be disabled.
    #[cfg(feature = "nrf52832")]
    #[inline]
    pub fn set_phy(&mut self, phy: Phy) {
        self.phy = phy;
        chip::set_phy(phy);
    }

    /// Sets the packet layout of the data channels, whose header in RAM
    /// carries the S1 byte the CCM needs, or of the advertising channels.
    #[inline]
    pub fn set_s1_included(&mut self, included: bool) { chip::set_packet_layout(included); }

    /// Sets what the radio does after the current packet.
    #[inline]
    pub fn set_turnaround(&mut self, turnaround: Turnaround) {
        #[cfg(feature = "nrf51")]
        switch::arm(turnaround);
        #[cfg(feature = "nrf52832")]
        switch::arm(self, turnaround);
    }

    /// Sets the transmit power of the following packets in dBm, one of the
    /// levels the radio supports.
    #[inline]
    pub fn set_tx_power(&mut self, dbm: i8) { REGS.txpower().write(|w| w.set_txpower(chip::txpower(dbm))); }

    /// Sleeps until `ready` holds, woken by the radio events in `events`.
    fn sleep_on<Ready>(events: impl Fn(&mut Int), ready: Ready)
    where
        Ready: FnMut() -> bool,
    {
        REGS.intenset().write(&events);
        sleep::until(ready);
        REGS.intenclr().write(events);
        interrupt::RADIO.unpend();
    }

    /// Starts sending now.
    #[inline]
    pub fn transmit(&mut self) { REGS.tasks_txen().write_value(1); }

    /// Sleeps until an access address arrives or `expired` holds, which is
    /// checked on every wake: it must depend on an event that wakes the CPU,
    /// such as the deadline of [`crate::clock::Clock::expire_at`]. Returns
    /// whether the address arrived.
    #[inline]
    pub fn wait_address<Expired>(&mut self, mut expired: Expired) -> bool
    where
        Expired: FnMut() -> bool,
    {
        Self::sleep_on(|w| w.set_address(true), || self.has_address() || expired());
        self.has_address()
    }

    /// Sleeps until the radio is disabled and clears the event.
    #[inline]
    pub fn wait_disabled(&mut self) {
        Self::sleep_on(|w| w.set_disabled(true), || self.is_disabled());
        REGS.events_disabled().write_value(0);
        compiler_fence(Ordering::SeqCst);
    }

    /// Sleeps until a packet ends and clears the event.
    #[inline]
    pub fn wait_end(&mut self) {
        Self::sleep_on(|w| w.set_end(true), || self.is_end());
        REGS.events_end().write_value(0);
        compiler_fence(Ordering::SeqCst);
    }

    /// Sleeps until the turnaround set before the last packet END enabled the
    /// radio again, and clears the disabled event of that packet. Set the
    /// next turnaround only after this, or it replaces the pending one.
    #[inline]
    pub fn wait_switched(&mut self) { switch::wait(); }
}

/// Radio frequency offset from 2400 MHz of a BLE channel index.
const fn frequency(channel: u8) -> u8 {
    match channel {
        0..=10 => 4_u8.saturating_add(channel.saturating_mul(2)),
        11..=36 => 6_u8.saturating_add(channel.saturating_mul(2)),
        38 => 26,
        39 => 80,
        _ => 2,
    }
}

#[cfg(all(test, feature = "nrf52832"))]
mod tests {
    use super::Phy;
    #[test]
    fn turnaround_offsets_match_nrf52832_hal_timing_vectors() {
        assert_eq!(Phy::M2.response_offset_us(Phy::M1), 101);
        assert_eq!(Phy::M1.response_offset_us(Phy::M2), 103);
        assert_eq!(Phy::M1.response_offset_us(Phy::M1), 100);
        assert_eq!(Phy::M2.response_offset_us(Phy::M2), 105);
        // Ready 8 us before the earliest packet: 150 - 41 - 8.
        assert_eq!(Phy::M1.listen_offset_us(), 101);
        assert_eq!(Phy::M2.listen_offset_us(), 101);
    }
}
