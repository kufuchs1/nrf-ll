//! Legacy advertising: the five advertising types, scan responses, the
//! advertising channel map and the filter accept list.

use super::{CHANNELS, LISTEN_US};
use crate::{
    clock::{Clock, reached},
    crypto,
    pdu::{
        ADV_ACCESS_ADDRESS,
        ADV_CRC_INIT,
        ADV_IND,
        ADV_NONCONN_IND,
        ADV_SCAN_IND,
        BUFFER_LEN,
        ConnectInd,
        LegacyAdvertisement,
        Peer,
        SCAN_RSP,
        scan_request,
    },
    radio::{Radio, Turnaround},
};

/// Largest advertising or scan response data.
pub const DATA_MAX: usize = 31;
/// Entries of the filter accept list.
pub const FILTER_LIST_SIZE: usize = 4;
/// Peers in the resolving list.
pub const RESOLVING_LIST_SIZE: usize = 2;

/// Advertising type.
#[derive(Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum Kind {
    /// Connectable and scannable undirected.
    ConnectableUndirected,
    /// Connectable directed, high duty cycle.
    DirectedHighDuty,
    /// Connectable directed, low duty cycle.
    DirectedLowDuty,
    /// Non-connectable and non-scannable undirected.
    NonConnectable,
    /// Scannable undirected.
    Scannable,
}

impl Kind {
    /// The type for an HCI advertising type value.
    #[inline]
    #[must_use = "the type is only decoded"]
    pub const fn from_hci(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::ConnectableUndirected),
            1 => Some(Self::DirectedHighDuty),
            2 => Some(Self::Scannable),
            3 => Some(Self::NonConnectable),
            4 => Some(Self::DirectedLowDuty),
            _ => None,
        }
    }

    /// Whether a central may connect.
    #[inline]
    #[must_use = "the property is only read"]
    pub const fn is_connectable(self) -> bool {
        matches!(self, Self::ConnectableUndirected | Self::DirectedHighDuty | Self::DirectedLowDuty)
    }

    /// Whether the advertising is directed.
    #[inline]
    #[must_use = "the property is only read"]
    pub const fn is_directed(self) -> bool { matches!(self, Self::DirectedHighDuty | Self::DirectedLowDuty) }
}

/// The filter accept list.
#[derive(Clone, Copy)]
pub struct FilterList {
    /// Entries.
    entries: [Option<Peer>; FILTER_LIST_SIZE],
}

impl FilterList {
    /// Adds a device. Returns false if the list is full.
    #[inline]
    pub fn add(&mut self, peer: Peer) -> bool {
        if self.contains(peer) {
            return true;
        }
        self.entries.iter_mut().find(|entry| entry.is_none()).is_some_and(|entry| {
            *entry = Some(peer);
            true
        })
    }

    /// Removes all devices.
    #[inline]
    pub const fn clear(&mut self) { self.entries = [None; FILTER_LIST_SIZE]; }

    /// Whether the list holds a device.
    #[inline]
    #[must_use = "the membership is only checked"]
    pub fn contains(&self, peer: Peer) -> bool { self.entries.contains(&Some(peer)) }

    /// An empty list.
    #[inline]
    #[must_use = "the list is only created"]
    pub const fn new() -> Self { Self { entries: [None; FILTER_LIST_SIZE] } }

    /// Removes a device.
    #[inline]
    pub fn remove(&mut self, peer: Peer) {
        for entry in &mut self.entries {
            if *entry == Some(peer) {
                *entry = None;
            }
        }
    }
}

impl Default for FilterList {
    #[inline]
    fn default() -> Self { Self::new() }
}

/// Peers whose resolvable private addresses are resolved to their identity
/// address, with their identity resolving keys.
#[derive(Clone, Copy)]
pub struct ResolvingList {
    /// Identity address and key of each peer.
    entries: [Option<(Peer, [u8; 16])>; RESOLVING_LIST_SIZE],
}

impl ResolvingList {
    /// Adds or replaces the key of `identity`. Returns false if the list is
    /// full.
    #[inline]
    pub fn add(&mut self, identity: Peer, irk: [u8; 16]) -> bool {
        self.remove(identity);
        let Some(slot) = self.entries.iter_mut().find(|slot| slot.is_none()) else { return false };
        *slot = Some((identity, irk));
        true
    }

    /// Removes every peer.
    #[inline]
    pub const fn clear(&mut self) { self.entries = [None; RESOLVING_LIST_SIZE]; }

    /// The identity address of `address`: the identity whose key generated
    /// it, if it is a resolvable private address of a listed peer.
    fn identity(&self, address: Peer) -> Option<Peer> {
        if !address.random {
            return None;
        }
        self.entries
            .iter()
            .flatten()
            .find(|&&(_, irk)| crypto::resolves(irk, address.address))
            .map(|&(identity, _)| identity)
    }

    /// An empty list.
    #[inline]
    #[must_use = "the list is only created"]
    pub const fn new() -> Self { Self { entries: [None; RESOLVING_LIST_SIZE] } }

    /// Removes `identity`.
    #[inline]
    pub fn remove(&mut self, identity: Peer) {
        for slot in &mut self.entries {
            if slot.is_some_and(|(listed, _)| listed == identity) {
                *slot = None;
            }
        }
    }
}

impl Default for ResolvingList {
    #[inline]
    fn default() -> Self { Self::new() }
}

/// Advertising as the host configured it.
#[derive(Clone, Copy)]
#[non_exhaustive]
pub struct Settings {
    /// Own address as the host set it, the identity address with privacy.
    pub address:       Peer,
    /// Advertising channels, bit 0 for channel 37.
    pub channel_map:   u8,
    /// Advertising data.
    pub data:          [u8; DATA_MAX],
    /// Filter accept list.
    pub filter:        FilterList,
    /// Filter policy: bit 0 filters scan requests, bit 1 connection requests.
    pub filter_policy: u8,
    /// Advertising interval in microseconds.
    pub interval:      u32,
    /// Advertising type.
    pub kind:          Kind,
    /// Length of [`Self::data`].
    pub len:           u8,
    /// Address on air: [`Self::address`], or a resolvable private address
    /// generated when the advertising starts.
    pub own:           Peer,
    /// Target of directed advertising.
    pub peer:          Peer,
    /// The host asked for a resolvable private address.
    pub private:       bool,
    /// Peers whose private addresses the filter accept list resolves.
    pub resolving:     ResolvingList,
    /// Scan response data.
    pub scan_data:     [u8; DATA_MAX],
    /// Length of [`Self::scan_data`].
    pub scan_len:      u8,
}

impl Settings {
    /// Whether a central may connect. With the filter accept list, a
    /// resolvable private address counts as the identity it resolves to.
    fn accepts_connection(&self, central: Peer) -> bool {
        if self.kind.is_directed() {
            return central == self.peer;
        }
        self.kind.is_connectable()
            && (self.filter_policy & 0x02 == 0
                || self.filter.contains(central)
                || self.resolving.identity(central).is_some_and(|identity| self.filter.contains(identity)))
    }

    /// Whether a scanner gets a scan response.
    fn accepts_scan(&self, scanner: Peer) -> bool {
        matches!(self.kind, Kind::ConnectableUndirected | Kind::Scannable)
            && (self.filter_policy & 0x01 == 0 || self.filter.contains(scanner))
    }

    /// The defaults after a reset.
    #[inline]
    #[must_use = "the settings are only created"]
    pub const fn new() -> Self {
        Self {
            address:       Peer::new([0; 6], true),
            channel_map:   0x07,
            data:          [0; DATA_MAX],
            filter:        FilterList::new(),
            filter_policy: 0,
            interval:      1_280_000,
            kind:          Kind::ConnectableUndirected,
            len:           0,
            own:           Peer::new([0; 6], true),
            peer:          Peer::new([0; 6], false),
            private:       false,
            resolving:     ResolvingList::new(),
            scan_data:     [0; DATA_MAX],
            scan_len:      0,
        }
    }

    /// The advertising PDU and the scan response.
    #[inline]
    #[must_use = "the PDUs are only built"]
    pub fn pdus(&self) -> (LegacyAdvertisement, LegacyAdvertisement) {
        let data = self.data.get(..usize::from(self.len)).unwrap_or_default();
        let scan_data = self.scan_data.get(..usize::from(self.scan_len)).unwrap_or_default();
        let primary = match self.kind {
            Kind::ConnectableUndirected => LegacyAdvertisement::undirected(ADV_IND, self.own, data),
            Kind::DirectedHighDuty | Kind::DirectedLowDuty => LegacyAdvertisement::directed(self.own, self.peer),
            Kind::NonConnectable => LegacyAdvertisement::undirected(ADV_NONCONN_IND, self.own, data),
            Kind::Scannable => LegacyAdvertisement::undirected(ADV_SCAN_IND, self.own, data),
        };
        (primary, LegacyAdvertisement::undirected(SCAN_RSP, self.own, scan_data))
    }
}

impl Default for Settings {
    #[inline]
    fn default() -> Self { Self::new() }
}

/// Runs one advertising event on the enabled channels. Returns a valid
/// connection request and the time its packet ended.
#[inline]
pub fn event(
    radio: &mut Radio<'_>,
    clock: &Clock<'_>,
    settings: &Settings,
    pdus: (&LegacyAdvertisement, &LegacyAdvertisement),
    rx: &mut [u8; BUFFER_LEN],
) -> Option<(ConnectInd, u32)> {
    radio.set_access_address(ADV_ACCESS_ADDRESS);
    radio.set_crc_init(ADV_CRC_INIT);
    CHANNELS
        .into_iter()
        .filter(|&(_, bit)| settings.channel_map & bit != 0)
        .find_map(|(channel, _)| on_channel(radio, clock, settings, pdus, rx, channel))
}

/// Sends the advertisement on one channel and serves a request that follows.
fn on_channel(
    radio: &mut Radio<'_>,
    clock: &Clock<'_>,
    settings: &Settings,
    (advertisement, scan_response): (&LegacyAdvertisement, &LegacyAdvertisement),
    rx: &mut [u8; BUFFER_LEN],
    channel: u8,
) -> Option<(ConnectInd, u32)> {
    radio.set_channel(channel);
    let listen = settings.kind != Kind::NonConnectable;
    let after = if listen { Turnaround::Receive } else { Turnaround::None };
    radio.prepare(advertisement.as_bytes().as_ptr().cast_mut(), after);
    radio.transmit();
    radio.wait_end();
    if !listen {
        radio.wait_disabled();
        return None;
    }
    radio.set_buffer(rx.as_mut_ptr());
    radio.wait_disabled();
    radio.set_turnaround(Turnaround::Transmit);
    radio.clear_address();
    let deadline = clock.end_time().wrapping_add(LISTEN_US);
    if !radio.wait_address(|| reached(clock.now(), deadline)) {
        radio.disable();
        return None;
    }
    radio.wait_end();
    let end = clock.end_time();
    let valid = radio.crc_ok();
    if valid
        && let Some(scanner) = scan_request(rx, settings.own)
        && settings.accepts_scan(scanner)
    {
        radio.set_buffer(scan_response.as_bytes().as_ptr().cast_mut());
        radio.wait_disabled();
        radio.set_turnaround(Turnaround::None);
        radio.wait_end();
        radio.wait_disabled();
        return None;
    }
    radio.wait_disabled();
    radio.disable();
    if !valid {
        return None;
    }
    ConnectInd::parse(rx, settings.own)
        .filter(|request| settings.accepts_connection(request.central()))
        .map(|request| (request, end))
}
