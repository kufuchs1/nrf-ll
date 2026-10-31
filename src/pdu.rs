//! Link layer packet formats.

/// Length of a device address.
pub const ADDRESS_LEN: usize = 6;
/// Access address of the advertising channels.
pub const ADV_ACCESS_ADDRESS: u32 = 0x8E89_BED6;
/// CRC initial value on the advertising channels.
pub const ADV_CRC_INIT: u32 = 0x0055_5555;
/// Largest advertising channel payload.
pub const ADV_PAYLOAD_MAX: usize = 255;
/// Size of a packet buffer: header, S1 byte and the largest payload.
pub const BUFFER_LEN: usize = HEADER_LEN + 1 + 255;
/// Length of a PDU header.
pub const HEADER_LEN: usize = 2;
/// Header bit marking the receiver address as random.
const RX_ADD_RANDOM: u8 = 0x80;
/// Header bit marking the sender address as random.
const TX_ADD_RANDOM: u8 = 0x40;
/// PDU type of a connectable undirected advertisement.
pub const ADV_IND: u8 = 0x0;
/// PDU type of a connectable directed advertisement.
pub const ADV_DIRECT_IND: u8 = 0x1;
/// PDU type of a non-connectable undirected advertisement.
pub const ADV_NONCONN_IND: u8 = 0x2;
/// PDU type of a scannable undirected advertisement.
pub const ADV_SCAN_IND: u8 = 0x6;
/// PDU type of a connection request.
const CONNECT_IND: u8 = 0x5;
/// Payload length of a connection request.
const CONNECT_IND_LEN: u8 = 34;
/// Largest connection interval in units of 1.25 ms.
const INTERVAL_MAX: u16 = 3200;
/// Smallest connection interval in units of 1.25 ms.
const INTERVAL_MIN: u16 = 6;
/// Largest peripheral latency.
const LATENCY_MAX: u16 = 499;
/// Largest hop increment.
const HOP_MAX: u8 = 16;
/// Smallest hop increment.
const HOP_MIN: u8 = 5;
/// Advertising PDU header bit: channel selection algorithm 2 supported, or
/// chosen in a connection request.
const CH_SEL: u8 = 0x20;
/// Mask of the PDU type in the first header byte.
const PDU_TYPE_MASK: u8 = 0x0F;
/// PDU type of a scan request.
const SCAN_REQ: u8 = 0x3;
/// Payload length of a scan request.
const SCAN_REQ_LEN: u8 = 12;
/// PDU type of a scan response.
pub const SCAN_RSP: u8 = 0x4;
/// Largest supervision timeout in units of 10 ms.
const TIMEOUT_MAX: u16 = 3200;
/// Smallest supervision timeout in units of 10 ms.
const TIMEOUT_MIN: u16 = 10;
/// Largest transmit window size in units of 1.25 ms.
const WIN_SIZE_MAX: u8 = 8;

/// Data PDU header bit: next expected sequence number.
pub const NESN: u8 = 0x04;
/// Data PDU header bit: sequence number.
pub const SN: u8 = 0x08;
/// Data PDU header bit: more data.
pub const MD: u8 = 0x10;
/// Mask of the logical link identifier in the data PDU header.
pub const LLID_MASK: u8 = 0x03;

/// Logical link identifier of a data PDU.
#[derive(Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum Llid {
    /// Continuation fragment of an L2CAP message, or an empty PDU.
    Continuation,
    /// LL control PDU.
    Control,
    /// Start of an L2CAP message.
    Start,
}

impl Llid {
    /// The header bits.
    #[inline]
    #[must_use = "the bits are only computed"]
    pub const fn bits(self) -> u8 {
        match self {
            Self::Continuation => 1,
            Self::Start => 2,
            Self::Control => 3,
        }
    }
}

/// A device address with its type.
#[derive(Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub struct Peer {
    /// The address, least significant octet first.
    pub address: [u8; ADDRESS_LEN],
    /// Whether the address is random.
    pub random:  bool,
}

impl Peer {
    /// A device address with its type.
    #[inline]
    #[must_use = "the address is only built"]
    pub const fn new(address: [u8; ADDRESS_LEN], random: bool) -> Self { Self { address, random } }
}

/// An advertising channel PDU as the radio sends it: header, then payload,
/// in a buffer of `N` bytes.
pub struct Advertisement<const N: usize> {
    /// Header and payload.
    bytes: [u8; N],
}

/// A PDU of legacy advertising.
pub type LegacyAdvertisement = Advertisement<{ HEADER_LEN + 37 }>;

impl<const N: usize> Advertisement<N> {
    /// The PDU bytes up to the end of the payload.
    #[inline]
    #[must_use = "the bytes are only borrowed"]
    pub fn as_bytes(&self) -> &[u8] {
        let len = usize::from(self.bytes.get(1).copied().unwrap_or_default());
        self.bytes.get(..HEADER_LEN.saturating_add(len)).unwrap_or_default()
    }

    /// A PDU with `header` and the payload `parts` in order. Payload beyond
    /// the buffer is cut off.
    fn build(header: u8, parts: &[&[u8]]) -> Self {
        let mut bytes = [0_u8; N];
        let mut len = 0_usize;
        for part in parts {
            for &byte in *part {
                if let Some(slot) = bytes.get_mut(HEADER_LEN.saturating_add(len))
                    && len < ADV_PAYLOAD_MAX
                {
                    *slot = byte;
                    len = len.saturating_add(1);
                }
            }
        }
        if let Some(header_bytes) = bytes.first_chunk_mut::<HEADER_LEN>() {
            *header_bytes = [header, u8::try_from(len).unwrap_or_default()];
        }
        Self { bytes }
    }

    /// A connectable directed advertisement from `advertiser` to `target`.
    #[inline]
    #[must_use = "the PDU is only built"]
    pub fn directed(advertiser: Peer, target: Peer) -> Self {
        let header = ADV_DIRECT_IND
            | CH_SEL
            | if advertiser.random { TX_ADD_RANDOM } else { 0 }
            | if target.random { RX_ADD_RANDOM } else { 0 };
        Self::build(header, &[&advertiser.address, &target.address])
    }

    /// An undirected advertisement or scan response of PDU type `kind` from
    /// `advertiser`. Data beyond 31 bytes is cut off.
    #[inline]
    #[must_use = "the PDU is only built"]
    pub fn undirected(kind: u8, advertiser: Peer, data: &[u8]) -> Self {
        let ch_sel = if kind == ADV_IND { CH_SEL } else { 0 };
        let header = kind | ch_sel | if advertiser.random { TX_ADD_RANDOM } else { 0 };
        Self::build(header, &[&advertiser.address, data])
    }
}

/// Parameters of a connection request.
#[derive(Clone, Copy)]
#[non_exhaustive]
pub struct ConnectInd {
    /// Access address of the connection.
    pub access_address:   u32,
    /// Used data channels, one bit per channel.
    pub channel_map:      [u8; 5],
    /// CRC initial value of the connection.
    pub crc_init:         u32,
    /// The central chose channel selection algorithm 2.
    pub csa2:             bool,
    /// Hop increment of channel selection algorithm 1.
    pub hop:              u8,
    /// Address of the central.
    pub initiator:        [u8; ADDRESS_LEN],
    /// Whether [`Self::initiator`] is a random address.
    pub initiator_random: bool,
    /// Connection interval in units of 1.25 ms.
    pub interval:         u16,
    /// Peripheral latency in connection events.
    pub latency:          u16,
    /// Central sleep clock accuracy field.
    pub sca:              u8,
    /// Central sleep clock accuracy in ppm.
    pub sca_ppm:          u32,
    /// Supervision timeout in units of 10 ms.
    pub timeout:          u16,
    /// Transmit window offset in units of 1.25 ms.
    pub win_offset:       u16,
    /// Transmit window size in units of 1.25 ms.
    pub win_size:         u8,
}

impl ConnectInd {
    /// The central as a device address with its type.
    #[inline]
    #[must_use = "the address is only read"]
    pub const fn central(&self) -> Peer { Peer::new(self.initiator, self.initiator_random) }

    /// Whether the parameters are within the ranges of the specification.
    fn is_valid(&self) -> bool {
        valid_connection_parameters(self.interval, self.latency, self.timeout, self.win_size, self.win_offset)
            && (HOP_MIN..=HOP_MAX).contains(&self.hop)
            && valid_channel_map(self.channel_map)
            && valid_access_address(self.access_address)
    }

    /// Parses a received advertising channel PDU. Returns `None` unless it
    /// is a connection request to `advertiser` with valid parameters.
    #[inline]
    #[must_use = "the request is only parsed"]
    pub fn parse(pdu: &[u8], advertiser: Peer) -> Option<Self> {
        let (
            Some([kind, len]),
            Some(initiator),
            Some(target),
            Some(access_address),
            Some([crc0, crc1, crc2]),
            Some([win_size, offset0, offset1, interval0, interval1, latency0, latency1, timeout0, timeout1]),
            Some(channel_map),
            Some([hop_sca]),
        ) = (
            field::<2>(pdu, 0),
            field::<ADDRESS_LEN>(pdu, 2),
            field::<ADDRESS_LEN>(pdu, 8),
            field::<4>(pdu, 14),
            field::<3>(pdu, 18),
            field::<9>(pdu, 21),
            field::<5>(pdu, 30),
            field::<1>(pdu, 35),
        )
        else {
            return None;
        };
        if kind & PDU_TYPE_MASK != CONNECT_IND
            || len != CONNECT_IND_LEN
            || Peer::new(target, kind & RX_ADD_RANDOM != 0) != advertiser
        {
            return None;
        }
        let request = Self {
            access_address: u32::from_le_bytes(access_address),
            channel_map,
            crc_init: u32::from_le_bytes([crc0, crc1, crc2, 0]),
            csa2: kind & CH_SEL != 0,
            hop: hop_sca & 0x1F,
            initiator,
            initiator_random: kind & TX_ADD_RANDOM != 0,
            interval: u16::from_le_bytes([interval0, interval1]),
            latency: u16::from_le_bytes([latency0, latency1]),
            sca: hop_sca >> 5,
            sca_ppm: sca_ppm(hop_sca >> 5),
            timeout: u16::from_le_bytes([timeout0, timeout1]),
            win_offset: u16::from_le_bytes([offset0, offset1]),
            win_size,
        };
        request.is_valid().then_some(request)
    }
}

/// Whether a data channel map has at least two channels and no reserved bits.
pub(crate) fn valid_channel_map(map: [u8; 5]) -> bool {
    map.last().is_some_and(|byte| byte & 0xE0 == 0) && map.iter().map(|byte| byte.count_ones()).sum::<u32>() >= 2
}

/// Validates timing both when connecting and when updating an existing link.
pub(crate) fn valid_connection_parameters(
    interval: u16,
    latency: u16,
    timeout: u16,
    win_size: u8,
    win_offset: u16,
) -> bool {
    (INTERVAL_MIN..=INTERVAL_MAX).contains(&interval)
        && (TIMEOUT_MIN..=TIMEOUT_MAX).contains(&timeout)
        && latency <= LATENCY_MAX
        && u32::from(latency).saturating_add(1).saturating_mul(u32::from(interval))
            < u32::from(timeout).saturating_mul(4)
        && (1..=WIN_SIZE_MAX).contains(&win_size)
        && u16::from(win_size) < interval
        && win_offset <= interval
}

/// LE 1M data access address constraints (Core, Vol 6, Part B, 2.1.2).
fn valid_access_address(address: u32) -> bool {
    let bytes = address.to_le_bytes();
    let transitions = address ^ (address >> 1_u32);
    let mut run = 1_u8;
    for bit in 1_u32..32_u32 {
        if ((address >> bit) ^ (address >> bit.saturating_sub(1))) & 1 == 0 {
            run = run.saturating_add(1);
            if run > 6 {
                return false;
            }
        } else {
            run = 1;
        }
    }
    (address ^ ADV_ACCESS_ADDRESS).count_ones() > 1
        && !bytes.iter().all(|byte| Some(byte) == bytes.first())
        && (transitions & 0x7FFF_FFFF).count_ones() <= 24
        && ((transitions >> 26) & 0x1F).count_ones() >= 2
}

/// The scanner of a received scan request to `advertiser`, if it is one.
#[inline]
#[must_use = "the request is only checked"]
pub fn scan_request(pdu: &[u8], advertiser: Peer) -> Option<Peer> {
    let (Some([header, len]), Some(scanner), Some(target)) =
        (field::<2>(pdu, 0), field::<ADDRESS_LEN>(pdu, 2), field::<ADDRESS_LEN>(pdu, 8))
    else {
        return None;
    };
    (header & PDU_TYPE_MASK == SCAN_REQ
        && len == SCAN_REQ_LEN
        && Peer::new(target, header & RX_ADD_RANDOM != 0) == advertiser)
        .then(|| Peer::new(scanner, header & TX_ADD_RANDOM != 0))
}

/// `N` bytes of `bytes` from `offset`, if present.
#[inline]
#[must_use = "the bytes are only copied"]
pub fn field<const N: usize>(bytes: &[u8], offset: usize) -> Option<[u8; N]> {
    bytes.get(offset..).and_then(<[u8]>::first_chunk::<N>).copied()
}

/// Sleep clock accuracy in ppm for a SCA field value.
const fn sca_ppm(field: u8) -> u32 {
    match field {
        0 => 500,
        1 => 250,
        2 => 150,
        3 => 100,
        4 => 75,
        5 => 50,
        6 => 30,
        _ => 20,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_channel_maps_are_rejected() {
        assert!(!valid_channel_map([0; 5]));
        assert!(!valid_channel_map([1, 0, 0, 0, 0]));
        assert!(!valid_channel_map([3, 0, 0, 0, 0x80]));
        assert!(valid_channel_map([3, 0, 0, 0, 0]));
        assert!(valid_channel_map([0xFF, 0xFF, 0xFF, 0xFF, 0x1F]));
    }

    #[test]
    fn supervision_timeout_must_exceed_twice_maximum_latency() {
        assert!(!valid_connection_parameters(40, 0, 10, 1, 0));
        assert!(valid_connection_parameters(39, 0, 10, 1, 0));
        assert!(!valid_connection_parameters(12, 500, 3200, 1, 0));
        assert!(!valid_connection_parameters(5, 0, 100, 1, 0));
        assert!(!valid_connection_parameters(12, 0, 100, 0, 0));
        assert!(!valid_connection_parameters(12, 0, 100, 1, 13));
        assert!(valid_connection_parameters(12, 30, 600, 1, 0));
    }

    #[test]
    fn advertising_and_weak_access_addresses_are_rejected() {
        assert!(!valid_access_address(ADV_ACCESS_ADDRESS));
        for bit in 0..32 {
            assert!(!valid_access_address(ADV_ACCESS_ADDRESS ^ (1 << bit)));
        }
        for address in [0, u32::MAX, 0xAAAA_AAAA, 0x0000_5678, 0xFF00_7F00] {
            assert!(!valid_access_address(address));
        }
        assert!(valid_access_address(0x9A32_8370));
    }

    #[test]
    fn truncated_scan_and_connection_requests_never_parse() {
        let peer = Peer::new([1; 6], true);
        let mut bytes = [0; 36];
        bytes[0] = CONNECT_IND | TX_ADD_RANDOM | RX_ADD_RANDOM;
        bytes[1] = CONNECT_IND_LEN;
        bytes[8..14].copy_from_slice(&peer.address);
        bytes[14..18].copy_from_slice(&0x9A32_8370_u32.to_le_bytes());
        bytes[21] = 1;
        bytes[24] = 12;
        bytes[28..30].copy_from_slice(&600_u16.to_le_bytes());
        bytes[30..35].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0x1F]);
        bytes[35] = 5;
        assert!(!ConnectInd::parse(&bytes, peer).unwrap().csa2);
        bytes[0] |= CH_SEL;
        assert!(ConnectInd::parse(&bytes, peer).unwrap().csa2);
        for len in 0..bytes.len() {
            assert!(ConnectInd::parse(&bytes[..len], peer).is_none());
        }
        bytes[0] = SCAN_REQ | RX_ADD_RANDOM;
        bytes[1] = SCAN_REQ_LEN;
        for len in 0..14 {
            assert!(scan_request(&bytes[..len], peer).is_none());
        }
        assert!(scan_request(&bytes[..14], peer).is_some());
        assert!(scan_request(&bytes[..14], Peer::new([2; 6], true)).is_none());
    }

    #[test]
    fn connectable_advertisements_offer_channel_selection_algorithm_2() {
        let peer = Peer::new([1; 6], true);
        assert_eq!(LegacyAdvertisement::undirected(ADV_IND, peer, &[]).bytes[0] & CH_SEL, CH_SEL);
        assert_eq!(LegacyAdvertisement::directed(peer, peer).bytes[0] & CH_SEL, CH_SEL);
        assert_eq!(LegacyAdvertisement::undirected(ADV_NONCONN_IND, peer, &[]).bytes[0] & CH_SEL, 0);
        assert_eq!(LegacyAdvertisement::undirected(SCAN_RSP, peer, &[]).bytes[0] & CH_SEL, 0);
    }
}
