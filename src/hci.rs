//! Host controller interface: commands and ACL data from the host, events
//! and ACL data to the host, as a [`Transport`] for
//! `bt_hci::controller::ExternalController`.

/// Legacy advertising and filter accept list commands.
mod legacy;

pub use crate::rng::fill as random;
use crate::{
    advertiser::legacy::Settings as LegacySettings,
    connection::FEATURES,
    crypto,
    log::info,
    pdu::{Llid, Peer, valid_connection_parameters},
};
use bt_hci::{
    ReadHciError,
    transport::{PacketKind, PacketToController, PacketToHost, Transport},
};
use core::{cell::RefCell, convert::Infallible, fmt};
use embassy_futures::select::{Either, select};
use embassy_sync::{
    blocking_mutex::{Mutex, raw::CriticalSectionRawMutex},
    channel::Channel,
    signal::Signal,
};
use embassy_time::{Duration, Instant};

/// Handle of the only connection.
pub const CONNECTION_HANDLE: u16 = 0;
/// Largest ACL payload per link layer PDU.
pub const ACL_MAX: usize = 27;
/// ACL buffers towards the air.
const ACL_OUT_BUFFERS: usize = 4;
/// Largest host event: Command Complete with the 64-byte supported-command
/// bitmap.
const PACKET_MAX: usize = 70;
/// Largest packet from the host: a command with the most parameters.
const HOST_PACKET_MAX: usize = 259;

/// Event code: disconnection complete.
const EVENT_DISCONNECTION_COMPLETE: u8 = 0x05;
/// Event code: encryption change.
const EVENT_ENCRYPTION_CHANGE: u8 = 0x08;
/// Authenticated payload timeout expired event.
const EVENT_PAYLOAD_TIMEOUT_EXPIRED: u8 = 0x57;
/// Event mask after a reset: the events of the specification's default.
const EVENT_MASK_DEFAULT: u64 = 0x0000_1FFF_FFFF_FFFF;
/// LE event mask after a reset: the first five LE subevents.
const LE_EVENT_MASK_DEFAULT: u64 = 0x1F;
/// Events the host cannot mask: command complete and status, and the
/// number of completed packets.
const UNMASKABLE_EVENTS: [u8; 3] = [EVENT_COMMAND_COMPLETE, EVENT_COMMAND_STATUS, EVENT_COMPLETED_PACKETS];
/// Authenticated payload timeout after a reset: 30 s in units of 10 ms.
const DEFAULT_PAYLOAD_TIMEOUT: u16 = 3000;
/// Lifetime of a resolvable private address after a reset: the default of
/// LE Set Resolvable Private Address Timeout, 15 minutes.
const PRIVATE_ADDRESS_TIMEOUT: Duration = Duration::from_secs(900);
/// Longest lifetime of a resolvable private address the host can set, in
/// seconds: one hour.
const PRIVATE_ADDRESS_TIMEOUT_MAX: u16 = 0x0E10;
/// Encryption key refresh complete event.
const EVENT_KEY_REFRESH_COMPLETE: u8 = 0x30;
/// Event code: command complete.
const EVENT_COMMAND_COMPLETE: u8 = 0x0E;
/// Event code: command status.
const EVENT_COMMAND_STATUS: u8 = 0x0F;
/// Event code: number of completed packets.
const EVENT_COMPLETED_PACKETS: u8 = 0x13;
/// Event code: LE meta event.
const EVENT_LE_META: u8 = 0x3E;
/// LE PHY update complete subevent.
const LE_PHY_UPDATE_COMPLETE: u8 = 0x0C;
/// LE enhanced connection complete subevent (v1). It carries the local
/// resolvable private address, which pairing needs (Core, Vol 4, Part E,
/// 7.7.65.10); the host enables it in the LE event mask.
const LE_ENHANCED_CONNECTION_COMPLETE: u8 = 0x0A;
/// LE connection complete subevent, sent when the host masked the enhanced
/// one.
const LE_CONNECTION_COMPLETE: u8 = 0x01;
/// LE subevent: connection update complete.
const LE_CONNECTION_UPDATE_COMPLETE: u8 = 0x03;
/// LE subevent: long term key request.
const LE_LTK_REQUEST: u8 = 0x05;
/// LE subevent: remote connection parameter request.
const LE_REMOTE_PARAMETER_REQUEST: u8 = 0x06;

/// Status: success.
const STATUS_SUCCESS: u8 = 0x00;
/// Bit of an accepted LE Connection Update awaiting its complete event.
const QUERY_CONNECTION_UPDATE: u8 = 0x08;
/// Bit of a central's connection parameter request awaiting the host's
/// reply.
const QUERY_REMOTE_PARAMETERS: u8 = 0x10;
/// Status: unknown command.
const STATUS_UNKNOWN_COMMAND: u8 = 0x01;
/// Status: unknown connection identifier.
const STATUS_UNKNOWN_CONNECTION: u8 = 0x02;
/// Status: memory capacity exceeded.
const STATUS_MEMORY_FULL: u8 = 0x07;
/// Status: command disallowed.
const STATUS_DISALLOWED: u8 = 0x0C;
/// Status: connection rejected due to limited resources.
const STATUS_LIMITED_RESOURCES: u8 = 0x0D;
/// Status: unsupported feature or parameter value.
const STATUS_UNSUPPORTED: u8 = 0x11;
/// Status: invalid HCI command parameters.
const STATUS_INVALID_PARAMETERS: u8 = 0x12;
/// Status: advertising timeout.
const STATUS_ADVERTISING_TIMEOUT: u8 = 0x3C;
/// Status: the central lacks a feature the command needs.
const STATUS_UNSUPPORTED_REMOTE_FEATURE: u8 = 0x1A;
/// Smallest advertising interval for undirected and low duty advertising in
/// units of 0.625 ms.
const ADV_INTERVAL_MIN: u16 = 0x0020;
/// Largest advertising interval in units of 0.625 ms.
const ADV_INTERVAL_MAX: u16 = 0x4000;

/// Reasons the host may give for a disconnection (Core, Vol 4, Part E,
/// 7.1.6): authentication failure, remote user terminated, low resources,
/// power off, unsupported remote feature, unacceptable pairing with unit key
/// and unacceptable connection parameters.
const DISCONNECT_REASONS: [u8; 7] = [0x05, 0x13, 0x14, 0x15, 0x1A, 0x29, 0x3B];

/// Commands answered with a command status event.
const ASYNC_COMMANDS: [u16; 6] = [0x0406, 0x041D, 0x2013, 0x2016, 0x2019, 0x2032];

/// HCI transport error.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct TransportError;

#[cfg(feature = "defmt")]
#[expect(clippy::missing_trait_methods, reason = "the provided methods are internal to defmt")]
impl defmt::Format for TransportError {
    #[inline]
    fn format(&self, fmt: defmt::Formatter<'_>) { defmt::write!(fmt, "HCI transport error") }
}

impl fmt::Display for TransportError {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str("HCI transport error") }
}

#[expect(clippy::missing_trait_methods, reason = "the provided methods fit an error without a source")]
impl core::error::Error for TransportError {}

impl embedded_io::Error for TransportError {
    #[inline]
    fn kind(&self) -> embedded_io::ErrorKind { embedded_io::ErrorKind::Other }
}

impl From<ReadHciError<Infallible>> for TransportError {
    #[inline]
    fn from(_: ReadHciError<Infallible>) -> Self { Self }
}

/// An ACL fragment from the host for the air.
#[derive(Clone, Copy)]
#[non_exhaustive]
pub struct AclOut {
    /// Payload.
    pub data:  [u8; ACL_MAX],
    /// Connection generation owning this fragment.
    pub epoch: u32,
    /// Payload length.
    pub len:   u8,
    /// Start or continuation of an L2CAP message.
    pub llid:  Llid,
}

/// A packet to the host.
#[derive(Clone, Copy)]
pub struct Packet {
    /// Packet bytes without the packet indicator.
    bytes: [u8; PACKET_MAX],
    /// Event or ACL data.
    kind:  PacketKind,
    /// Number of valid bytes.
    len:   usize,
}

impl Packet {
    /// An ACL data packet of the connection from a received PDU payload.
    #[inline]
    #[must_use = "the packet is only built"]
    pub fn acl(llid: Llid, payload: &[u8]) -> Self {
        let boundary: u8 = if llid == Llid::Continuation { 0x10 } else { 0x20 };
        let [handle_low, handle_high] = CONNECTION_HANDLE.to_le_bytes();
        let [len_low, len_high] = u16::try_from(payload.len()).unwrap_or_default().to_le_bytes();
        Self::build(PacketKind::AclData, &[handle_low, handle_high | boundary, len_low, len_high], payload)
    }

    /// An LE connection complete event for directed advertising that ended
    /// without a connection.
    #[inline]
    #[must_use = "the packet is only built"]
    pub fn advertising_timeout() -> Self {
        Self::connection_complete(
            STATUS_ADVERTISING_TIMEOUT,
            (Peer::new([0; 6], false), None),
            ConnectionParams::new(0, 0, 0),
            0,
        )
    }

    /// A packet from a header and a body.
    fn build(kind: PacketKind, header: &[u8], body: &[u8]) -> Self {
        let mut bytes = [0_u8; PACKET_MAX];
        let end = header.len().saturating_add(body.len()).min(PACKET_MAX);
        if let Some(target) = bytes.get_mut(..header.len()) {
            target.copy_from_slice(header);
        }
        if let (Some(target), Some(source)) =
            (bytes.get_mut(header.len()..end), body.get(..end.saturating_sub(header.len())))
        {
            target.copy_from_slice(source);
        }
        Self { bytes, kind, len: end }
    }

    /// A command complete event.
    fn command_complete(opcode: u16, status: u8, returned: &[u8]) -> Self {
        let [op_low, op_high] = opcode.to_le_bytes();
        let len = u8::try_from(returned.len().saturating_add(4)).unwrap_or_default();
        Self::build(PacketKind::Event, &[EVENT_COMMAND_COMPLETE, len, 1, op_low, op_high, status], returned)
    }

    /// A command status event.
    fn command_status(opcode: u16, status: u8) -> Self {
        let [op_low, op_high] = opcode.to_le_bytes();
        Self::build(PacketKind::Event, &[EVENT_COMMAND_STATUS, 4, status, 1, op_low, op_high], &[])
    }

    /// A number of completed packets event for the connection.
    #[inline]
    #[must_use = "the packet is only built"]
    pub fn completed_packets(count: u16) -> Self {
        let [handle_low, handle_high] = CONNECTION_HANDLE.to_le_bytes();
        let [count_low, count_high] = count.to_le_bytes();
        Self::build(
            PacketKind::Event,
            &[EVENT_COMPLETED_PACKETS, 5, 1, handle_low, handle_high, count_low, count_high],
            &[],
        )
    }

    /// An LE enhanced connection complete event for a peripheral connection
    /// with `peer`, advertised with the resolvable private address `local`
    /// if there is one.
    #[inline]
    #[must_use = "the packet is only built"]
    pub fn connection_complete(
        status: u8,
        (peer, local): (Peer, Option<[u8; 6]>),
        params: ConnectionParams,
        central_accuracy: u8,
    ) -> Self {
        Self::connection_complete_resolved(status, (peer, local), params, central_accuracy, None)
    }

    /// Connection completion with an optional resolved peer identity.
    #[must_use = "the packet is only built"]
    #[inline]
    pub fn connection_complete_resolved(
        status: u8,
        (peer, local): (Peer, Option<[u8; 6]>),
        params: ConnectionParams,
        central_accuracy: u8,
        identity: Option<Peer>,
    ) -> Self {
        let rpa = identity.map_or([0; 6], |_| peer.address);
        let reported = identity.unwrap_or(peer);
        let [handle_low, handle_high] = CONNECTION_HANDLE.to_le_bytes();
        let [l0, l1, l2, l3, l4, l5] = local.unwrap_or_default();
        let mut body = [0_u8; 30];
        let [interval_low, interval_high] = params.interval.to_le_bytes();
        let [latency_low, latency_high] = params.latency.to_le_bytes();
        let [timeout_low, timeout_high] = params.timeout.to_le_bytes();
        let [p0, p1, p2, p3, p4, p5] = reported.address;
        body.copy_from_slice(&[
            status,
            handle_low,
            handle_high,
            1,
            u8::from(reported.random) | if identity.is_some() { 2 } else { 0 },
            p0,
            p1,
            p2,
            p3,
            p4,
            p5,
            l0,
            l1,
            l2,
            l3,
            l4,
            l5,
            rpa[0],
            rpa[1],
            rpa[2],
            rpa[3],
            rpa[4],
            rpa[5],
            interval_low,
            interval_high,
            latency_low,
            latency_high,
            timeout_low,
            timeout_high,
            central_accuracy,
        ]);
        Self::build(PacketKind::Event, &[EVENT_LE_META, 31, LE_ENHANCED_CONNECTION_COMPLETE], &body)
    }

    /// An LE connection update complete event.
    #[inline]
    #[must_use = "the packet is only built"]
    pub fn connection_update_complete(status: u8, params: ConnectionParams) -> Self {
        let [handle_low, handle_high] = CONNECTION_HANDLE.to_le_bytes();
        let [interval_low, interval_high] = params.interval.to_le_bytes();
        let [latency_low, latency_high] = params.latency.to_le_bytes();
        let [timeout_low, timeout_high] = params.timeout.to_le_bytes();
        Self::build(
            PacketKind::Event,
            &[
                EVENT_LE_META,
                10,
                LE_CONNECTION_UPDATE_COMPLETE,
                status,
                handle_low,
                handle_high,
                interval_low,
                interval_high,
                latency_low,
                latency_high,
                timeout_low,
                timeout_high,
            ],
            &[],
        )
    }

    /// A disconnection complete event.
    #[inline]
    #[must_use = "the packet is only built"]
    pub fn disconnection_complete(reason: u8) -> Self {
        let [handle_low, handle_high] = CONNECTION_HANDLE.to_le_bytes();
        Self::build(
            PacketKind::Event,
            &[EVENT_DISCONNECTION_COMPLETE, 4, STATUS_SUCCESS, handle_low, handle_high, reason],
            &[],
        )
    }

    /// An encryption change event.
    #[inline]
    #[must_use = "the packet is only built"]
    pub fn encryption_change(status: u8, enabled: bool) -> Self {
        let [handle_low, handle_high] = CONNECTION_HANDLE.to_le_bytes();
        Self::build(
            PacketKind::Event,
            &[EVENT_ENCRYPTION_CHANGE, 4, status, handle_low, handle_high, u8::from(enabled)],
            &[],
        )
    }

    /// Whether this is a retained parameter update completion.
    pub(crate) fn is_parameter_update(&self) -> bool {
        self.bytes.first() == Some(&EVENT_LE_META) && self.bytes.get(2) == Some(&LE_CONNECTION_UPDATE_COMPLETE)
    }

    /// Whether this is an authenticated payload timeout event.
    pub(crate) fn is_payload_timeout(&self) -> bool { self.bytes.first() == Some(&EVENT_PAYLOAD_TIMEOUT_EXPIRED) }

    /// Whether this is a retained PHY update completion.
    pub(crate) fn is_phy_update(&self) -> bool {
        self.bytes.first() == Some(&EVENT_LE_META) && self.bytes.get(2) == Some(&LE_PHY_UPDATE_COMPLETE)
    }

    /// An encryption key refresh complete event.
    #[inline]
    #[must_use = "the packet is only built"]
    pub fn key_refresh_complete(status: u8) -> Self {
        let [handle_low, handle_high] = CONNECTION_HANDLE.to_le_bytes();
        Self::build(PacketKind::Event, &[EVENT_KEY_REFRESH_COMPLETE, 3, status, handle_low, handle_high], &[])
    }

    /// The LE connection complete event that carries the same connection
    /// as this LE enhanced connection complete event, without the private
    /// addresses.
    fn legacy_connection_complete(&self) -> Self {
        let common = self.bytes.get(3..14).unwrap_or_default();
        let timing = self.bytes.get(26..33).unwrap_or_default();
        let mut body = [0_u8; 18];
        for (target, source) in body.iter_mut().zip(common.iter().chain(timing)) {
            *target = *source;
        }
        Self::build(PacketKind::Event, &[EVENT_LE_META, 19, LE_CONNECTION_COMPLETE], &body)
    }

    /// An LE long term key request event.
    #[inline]
    #[must_use = "the packet is only built"]
    pub fn ltk_request(rand: [u8; 8], ediv: [u8; 2]) -> Self {
        let [handle_low, handle_high] = CONNECTION_HANDLE.to_le_bytes();
        let [rand0, rand1, rand2, rand3, rand4, rand5, rand6, rand7] = rand;
        let [ediv0, ediv1] = ediv;
        Self::build(
            PacketKind::Event,
            &[
                EVENT_LE_META,
                13,
                LE_LTK_REQUEST,
                handle_low,
                handle_high,
                rand0,
                rand1,
                rand2,
                rand3,
                rand4,
                rand5,
                rand6,
                rand7,
                ediv0,
                ediv1,
            ],
            &[],
        )
    }

    /// An authenticated payload timeout expired event.
    #[inline]
    #[must_use = "the packet is only built"]
    pub fn payload_timeout_expired() -> Self {
        let [handle_low, handle_high] = CONNECTION_HANDLE.to_le_bytes();
        Self::build(PacketKind::Event, &[EVENT_PAYLOAD_TIMEOUT_EXPIRED, 2, handle_low, handle_high], &[])
    }

    /// An LE PHY update complete event: `phy` both ways.
    #[inline]
    #[must_use = "the packet is only built"]
    pub fn phy_update_complete(phy: u8) -> Self { Self::phy_update_complete_pair(phy, phy) }

    /// Reports separate receive and transmit PHYs to the host.
    #[inline]
    #[must_use = "the packet is only built"]
    pub fn phy_update_complete_pair(rx: u8, tx: u8) -> Self { Self::phy_update_result(STATUS_SUCCESS, rx, tx) }

    /// Reports success or failure of a host PHY procedure.
    #[inline]
    #[must_use = "the packet is only built"]
    pub fn phy_update_result(status: u8, rx: u8, tx: u8) -> Self {
        let [handle_low, handle_high] = CONNECTION_HANDLE.to_le_bytes();
        Self::build(
            PacketKind::Event,
            &[EVENT_LE_META, 6, LE_PHY_UPDATE_COMPLETE, status, handle_low, handle_high, tx, rx],
            &[],
        )
    }

    /// Completion of the host's remote feature query.
    #[inline]
    #[must_use = "the packet is only built"]
    pub fn remote_features(features: [u8; 8]) -> Self { Self::remote_features_result(0, features) }

    /// Completion or rejection of a remote feature query.
    #[inline]
    #[must_use = "the packet is only built"]
    pub fn remote_features_result(status: u8, features: [u8; 8]) -> Self {
        Self::build(PacketKind::Event, &[EVENT_LE_META, 12, 4, status, 0, 0], &features)
    }

    /// An LE remote connection parameter request event: the interval range,
    /// latency and supervision timeout the central asks for.
    #[inline]
    #[must_use = "the packet is only built"]
    pub fn remote_parameter_request([min, max, latency, timeout]: [u16; 4]) -> Self {
        let [handle_low, handle_high] = CONNECTION_HANDLE.to_le_bytes();
        let mut bytes =
            [EVENT_LE_META, 11, LE_REMOTE_PARAMETER_REQUEST, handle_low, handle_high, 0, 0, 0, 0, 0, 0, 0, 0];
        for (target, source) in
            bytes.iter_mut().skip(5).zip([min, max, latency, timeout].iter().flat_map(|value| value.to_le_bytes()))
        {
            *target = source;
        }
        Self::build(PacketKind::Event, &bytes, &[])
    }

    /// Completion of the host's remote version query.
    #[inline]
    #[must_use = "the packet is only built"]
    pub fn remote_version(version: [u8; 5]) -> Self { Self::build(PacketKind::Event, &[12, 8, 0, 0, 0], &version) }
}

/// Connection parameters in link layer units.
#[derive(Clone, Copy)]
#[non_exhaustive]
pub struct ConnectionParams {
    /// Interval in units of 1.25 ms.
    pub interval: u16,
    /// Peripheral latency in events.
    pub latency:  u16,
    /// Supervision timeout in units of 10 ms.
    pub timeout:  u16,
}

impl ConnectionParams {
    /// Parameters from their link layer units.
    #[inline]
    #[must_use = "the parameters are only built"]
    pub const fn new(interval: u16, latency: u16, timeout: u16) -> Self { Self { interval, latency, timeout } }
}

/// Host state kept by the controller.
struct HostState {
    /// Host query opcodes already accepted but not completed.
    active_queries:    u8,
    /// Whether a connection exists.
    connected:         bool,
    /// Changes at each link boundary so blocked sends cannot cross sessions.
    epoch:             u32,
    /// Event mask of the host.
    event_mask:        u64,
    /// Event mask page 2 of the host.
    event_mask_page_2: u64,
    /// LE event mask of the host.
    le_event_mask:     u64,
    /// Legacy advertising parameters.
    legacy:            LegacySettings,
    /// Whether the host enabled legacy advertising.
    legacy_enabled:    bool,
    /// A key reply is accepted only after an LTK request was queued.
    ltk_pending:       bool,
    /// Authenticated payload timeout in units of 10 ms.
    payload_timeout:   u16,
    /// Accepted host PHY request, published after Command Status.
    phy_pending:       Option<[u8; 2]>,
    /// Current receive and transmit PHY, updated at the instant.
    phys:              [u8; 2],
    /// Default transmit and receive PHY preferences.
    preferred_phys:    [u8; 2],
    /// The last resolvable private address, the key it was made with and
    /// when it expires. Advertising keeps it until then.
    private_address:   Option<(Peer, [u8; 16], Instant)>,
    /// Lifetime of a resolvable private address.
    private_timeout:   Duration,
    /// Host requests waiting for the link layer (features and version).
    queries:           u8,
    /// First byte of the central's features, zero until known.
    remote_features:   u8,
}

impl HostState {
    /// Whether the host's masks let the event with `code`, and `subevent`
    /// for an LE meta event, through.
    fn allows(&self, code: u8, subevent: u8) -> bool {
        // Page 1 holds the events from 0x01 at bit 0, page 2 those from 0x40.
        let page = if code < 0x40 {
            mask_bit(self.event_mask, code.wrapping_sub(1))
        } else {
            mask_bit(self.event_mask_page_2, code.wrapping_sub(0x40))
        };
        UNMASKABLE_EVENTS.contains(&code)
            || (page && (code != EVENT_LE_META || mask_bit(self.le_event_mask, subevent.wrapping_sub(1))))
    }

    /// A private address is reusable only with the same key, before expiry.
    fn cached_address(&self, key: [u8; 16], now: Instant) -> Option<Peer> {
        let (address, made_with, expires) = self.private_address?;
        (made_with == key && now < expires).then_some(address)
    }

    /// `packet` as the host's event masks let it through: unchanged, as the
    /// LE connection complete event if only that one is enabled, or not at
    /// all (Core, Vol 4, Part E, 7.3.1 and 7.8.1).
    fn deliver(&self, packet: Packet) -> Option<Packet> {
        if !matches!(packet.kind, PacketKind::Event) {
            return Some(packet);
        }
        let [code, _, subevent, ..] = packet.bytes;
        if self.allows(code, subevent) {
            return Some(packet);
        }
        let enhanced = code == EVENT_LE_META && subevent == LE_ENHANCED_CONNECTION_COMPLETE;
        (enhanced && self.allows(code, LE_CONNECTION_COMPLETE)).then(|| packet.legacy_connection_complete())
    }

    /// Overwrites every identity resolving key before it is dropped.
    fn forget_keys(&mut self) {
        if let Some(&mut (_, ref mut key, _)) = self.private_address.as_mut() {
            crypto::wipe(key);
        }
        self.private_address = None;
        self.legacy.resolving.clear();
    }

    /// The state after power-on or a reset, for a link that is `connected`
    /// in its generation `epoch`.
    const fn new(connected: bool, epoch: u32) -> Self {
        Self {
            connected,
            queries: 0,
            active_queries: 0,
            phys: [1, 1],
            preferred_phys: [2, 2],
            phy_pending: None,
            epoch,
            event_mask: EVENT_MASK_DEFAULT,
            event_mask_page_2: 0,
            le_event_mask: LE_EVENT_MASK_DEFAULT,
            legacy: LegacySettings::new(),
            legacy_enabled: false,
            ltk_pending: false,
            payload_timeout: DEFAULT_PAYLOAD_TIMEOUT,
            private_address: None,
            private_timeout: PRIVATE_ADDRESS_TIMEOUT,
            remote_features: 0,
        }
    }
}

/// State shared between the host interface and the link layer.
pub struct Shared {
    /// ACL data received from the air.
    acl_in:          Channel<CriticalSectionRawMutex, Packet, 2>,
    /// ACL data from the host for the air.
    acl_out:         Channel<CriticalSectionRawMutex, AclOut, ACL_OUT_BUFFERS>,
    /// Advertising settings changed.
    changed:         Signal<CriticalSectionRawMutex, ()>,
    /// Disconnection requested by the host, with the reason.
    disconnect:      Signal<CriticalSectionRawMutex, u8>,
    /// Events for the host.
    events:          Channel<CriticalSectionRawMutex, Packet, 4>,
    /// Long term key from the host, `None` if it has none.
    ltk:             Signal<CriticalSectionRawMutex, Option<[u8; 16]>>,
    /// Connection parameters the host asks the central for: interval range,
    /// latency and supervision timeout in link layer units.
    param_request:   Signal<CriticalSectionRawMutex, [u16; 4]>,
    /// The host's answer to a central's connection parameter request: the
    /// parameters to offer, or the reason to reject it.
    parameter_reply: Signal<CriticalSectionRawMutex, Result<[u16; 4], u8>>,
    /// ACL data received from the air for the host.
    /// Reset handshake with the radio executor.
    reset:           Signal<CriticalSectionRawMutex, ()>,
    /// Radio reset completion.
    reset_done:      Signal<CriticalSectionRawMutex, ()>,
    /// Host state.
    state:           Mutex<CriticalSectionRawMutex, RefCell<HostState>>,
    /// Something for the connection arrived from the host.
    wakeup:          Signal<CriticalSectionRawMutex, ()>,
}

impl Default for Shared {
    #[inline]
    fn default() -> Self { Self::new() }
}

impl Shared {
    /// Free places for ACL data towards the host.
    #[inline]
    #[must_use = "the room is only read"]
    pub fn acl_room(&self) -> usize { self.acl_in.free_capacity() }

    /// The advertising to run, if the host enabled it and no connection
    /// exists.
    #[inline]
    #[must_use = "the settings are only read"]
    pub fn advertising(&self) -> Option<LegacySettings> {
        self.state.lock(|cell| {
            let state = cell.borrow();
            (!state.connected && state.legacy_enabled).then_some(state.legacy)
        })
    }

    /// Passes a central's connection parameter request to the host, which
    /// answers with LE Remote Connection Parameter Request Reply or Negative
    /// Reply.
    pub(crate) fn ask_parameters(&self) {
        self.parameter_reply.reset();
        self.state.lock(|cell| cell.borrow_mut().active_queries |= QUERY_REMOTE_PARAMETERS);
    }

    /// Waits until the advertising settings change.
    #[inline]
    pub async fn changed(&self) { self.changed.wait().await; }

    /// Releases a host query slot once its result is retained for delivery.
    pub(crate) fn complete_query(&self, bit: u8) { self.state.lock(|cell| cell.borrow_mut().active_queries &= !bit); }

    /// Completes reset only after the radio has stopped and wiped link keys.
    pub(crate) fn complete_reset(&self) {
        self.set_connected(false);
        self.state.lock(|cell| {
            let mut state = cell.borrow_mut();
            state.forget_keys();
            *state = HostState::new(false, state.epoch.wrapping_add(1));
        });
        while self.events.try_receive().is_ok() {}
        self.reset_done.signal(());
    }

    /// Ends a central's connection parameter request the host was asked
    /// about, answered or not.
    pub(crate) fn end_parameter_request(&self) { self.complete_query(QUERY_REMOTE_PARAMETERS); }

    /// Lets the host start another connection update once the current one
    /// reported its outcome.
    pub(crate) fn finish_param_request(&self) { self.complete_query(QUERY_CONNECTION_UPDATE); }

    /// Whether ACL data from the host waits for the air.
    #[inline]
    #[must_use = "the state is only read"]
    pub fn has_acl_out(&self) -> bool { !self.acl_out.is_empty() }

    /// Whether another received ACL packet fits for the host.
    #[inline]
    #[must_use = "the capacity is only read"]
    pub fn has_room(&self) -> bool { self.acl_in.free_capacity() != 0 }

    /// Whether the host decides on a central's connection parameter
    /// requests: it enabled the LE remote connection parameter request
    /// event, as Zephyr decides. Otherwise the link layer accepts them.
    pub(crate) fn host_decides_parameters(&self) -> bool {
        self.state.lock(|cell| cell.borrow().allows(EVENT_LE_META, LE_REMOTE_PARAMETER_REQUEST))
    }

    /// Creates the shared state.
    #[inline]
    #[must_use = "the state is only created"]
    pub const fn new() -> Self {
        Self {
            reset:           Signal::new(),
            reset_done:      Signal::new(),
            acl_in:          Channel::new(),
            acl_out:         Channel::new(),
            changed:         Signal::new(),
            disconnect:      Signal::new(),
            events:          Channel::new(),
            ltk:             Signal::new(),
            param_request:   Signal::new(),
            parameter_reply: Signal::new(),
            state:           Mutex::new(RefCell::new(HostState::new(false, 0))),
            wakeup:          Signal::new(),
        }
    }

    /// Takes the next ACL fragment for the air if `take` is set and one is
    /// waiting.
    #[inline]
    pub fn next_acl_out_if(&self, take: bool) -> Option<AclOut> {
        if !take {
            return None;
        }
        self.state.lock(|cell| {
            let state = cell.borrow();
            while let Ok(packet) = self.acl_out.try_receive() {
                if state.connected && packet.epoch == state.epoch {
                    return Some(packet);
                }
            }
            None
        })
    }

    /// Gets a stable private address without holding interrupts off during
    /// RNG and AES. Both the HCI task and the link layer may call it: the
    /// link layer can only preempt the HCI task, and whichever address is
    /// cached last is the one advertising moves to at its next event.
    fn own_address(&self, override_key: Option<[u8; 16]>) -> Peer {
        let (configured_key, fallback, lifetime) = self.state.lock(|cell| {
            let state = cell.borrow();
            (
                override_key
                    .or_else(|| {
                        state.legacy.resolving.local_key(state.legacy.kind.is_directed().then_some(state.legacy.peer))
                    })
                    .filter(|_| state.legacy.private),
                state.legacy.address,
                state.private_timeout,
            )
        });
        let Some(key) = configured_key else { return fallback };
        let now = Instant::now();
        if let Some(address) = self.state.lock(|cell| cell.borrow().cached_address(key, now)) {
            return address;
        }
        let mut prand = [0; 3];
        random(&mut prand);
        let address = Peer::new(crypto::resolvable_address(key, prand), true);
        self.state.lock(|cell| {
            cell.borrow_mut().private_address = Some((address, key, now.saturating_add(lifetime)));
        });
        address
    }

    /// The authenticated payload timeout in microseconds.
    #[inline]
    #[must_use = "the timeout is only read"]
    pub fn payload_timeout(&self) -> u32 {
        self.state.lock(|cell| u32::from(cell.borrow().payload_timeout).saturating_mul(10_000))
    }

    /// Default PHY preference for new connections.
    pub(crate) fn preferred_phys(&self) -> [u8; 2] { self.state.lock(|cell| cell.borrow().preferred_phys) }

    /// Passes received ACL data to the host. Returns false if there is no
    /// room.
    #[inline]
    pub fn push_acl_in(&self, packet: Packet) -> bool { self.acl_in.try_send(packet).is_ok() }

    /// Queues an event for the host, waiting for room. An event the host
    /// masked is dropped.
    #[inline]
    pub async fn push_event(&self, packet: Packet) {
        if let Some(event) = self.state.lock(|cell| cell.borrow().deliver(packet)) {
            self.events.send(event).await;
        }
    }

    /// Moves running advertising to a new resolvable private address once
    /// the current one expired, so a device that advertises for long cannot
    /// be followed by its address. Call it before each advertising event,
    /// outside radio events.
    #[inline]
    pub fn refresh_private_address(&self) {
        let private = self.state.lock(|cell| {
            let state = cell.borrow();
            state.legacy_enabled && state.legacy.private && state.legacy.resolving.local_key(None).is_some()
        });
        if !private {
            return;
        }
        let address = self.own_address(None);
        self.state.lock(|cell| {
            let mut state = cell.borrow_mut();
            if state.legacy_enabled && state.legacy.private && state.legacy.own != address {
                state.legacy.own = address;
                info!("new private address");
            }
        });
    }

    /// Queues a key request and authorizes one corresponding host reply. A
    /// host that masked the request has no key to give.
    #[inline]
    pub fn request_ltk(&self, rand: [u8; 8], ediv: [u8; 2]) -> bool {
        self.state.lock(|cell| {
            let mut state = cell.borrow_mut();
            if !state.connected || state.ltk_pending {
                return false;
            }
            if !state.allows(EVENT_LE_META, LE_LTK_REQUEST) {
                self.ltk.signal(None);
                return true;
            }
            if self.events.try_send(Packet::ltk_request(rand, ediv)).is_err() {
                return false;
            }
            state.ltk_pending = true;
            true
        })
    }

    /// Queues a connection parameter request as the host's LE Connection
    /// Update does.
    #[cfg(test)]
    pub(crate) fn request_params(&self, params: [u16; 4]) { self.param_request.signal(params); }

    /// Queues host information queries in state-machine regression tests.
    #[cfg(test)]
    pub(crate) fn request_queries(&self, bits: u8) { self.state.lock(|cell| cell.borrow_mut().queries |= bits); }

    /// Waits for reset even when radio cleanup is blocked by host backpressure.
    pub(crate) async fn reset_requested(&self) { self.reset.wait().await; }

    /// Forgets earlier wakeups.
    #[inline]
    pub fn reset_wakeup(&self) { self.wakeup.reset(); }

    /// Records the start or end of the connection. Advertising stops when a
    /// connection starts.
    #[inline]
    pub fn set_connected(&self, connected: bool) {
        self.state.lock(|cell| {
            let mut state = cell.borrow_mut();
            if state.connected != connected {
                state.epoch = state.epoch.wrapping_add(1);
                state.ltk_pending = false;
                state.remote_features = 0;
                state.queries = 0;
                state.active_queries = 0;
                state.phys = [1, 1];
                state.phy_pending = None;
            }
            state.connected = connected;
            if connected {
                state.legacy_enabled = false;
            }
        });
        if !connected {
            while self.acl_out.try_receive().is_ok() {}
            while self.acl_in.try_receive().is_ok() {}
            self.disconnect.reset();
            self.ltk.reset();
            self.param_request.reset();
            self.parameter_reply.reset();
            self.wakeup.reset();
        }
    }

    /// Publishes the current receive and transmit PHY for HCI Read PHY.
    pub(crate) fn set_phys(&self, rx: u8, tx: u8) { self.state.lock(|cell| cell.borrow_mut().phys = [rx, tx]); }

    /// Records the first feature byte of the central, which decides whether
    /// the connection parameters request procedure can be used.
    #[inline]
    pub fn set_remote_features(&self, features: u8) {
        self.state.lock(|cell| cell.borrow_mut().remote_features = features);
    }

    /// Wakes the controller for a reset, including waits under host
    /// backpressure.
    pub(crate) fn signal_reset(&self) {
        self.reset.signal(());
        self.changed.signal(());
        self.wakeup.signal(());
    }

    /// Ends advertising that ran out of time.
    #[inline]
    pub fn stop_advertising(&self) {
        self.state.lock(|cell| {
            let mut state = cell.borrow_mut();
            state.legacy_enabled = false;
        });
    }

    /// Takes the next ACL packet for the host, as its bytes.
    #[cfg(test)]
    pub(crate) fn take_acl_in(&self) -> Option<[u8; PACKET_MAX]> {
        self.acl_in.try_receive().ok().map(|packet| packet.bytes)
    }

    /// Takes a pending disconnection request.
    #[inline]
    pub fn take_disconnect(&self) -> Option<u8> { self.disconnect.try_take() }

    /// Takes the host's answer to a long term key request.
    #[inline]
    pub fn take_ltk(&self) -> Option<Option<[u8; 16]>> { self.ltk.try_take() }

    /// Takes connection parameters the host asks the central for.
    #[inline]
    pub fn take_param_request(&self) -> Option<[u16; 4]> { self.param_request.try_take() }

    /// Takes the host's answer to a central's connection parameter request.
    pub(crate) fn take_parameter_reply(&self) -> Option<Result<[u16; 4], u8>> { self.parameter_reply.try_take() }

    /// Takes a host-requested transmit and receive PHY preference.
    pub(crate) fn take_phy_request(&self) -> Option<[u8; 2]> {
        self.state.lock(|cell| cell.borrow_mut().phy_pending.take())
    }

    /// Collects accepted host queries after their command status was queued.
    pub(crate) fn take_queries(&self) -> u8 { self.state.lock(|cell| core::mem::take(&mut cell.borrow_mut().queries)) }

    /// Takes a pending host reset at a radio-safe boundary.
    pub(crate) fn take_reset(&self) -> bool { self.reset.try_take().is_some() }

    /// Queues an event for the host. Returns false if there is no room; an
    /// event the host masked counts as delivered.
    #[inline]
    pub fn try_push_event(&self, packet: Packet) -> bool {
        self.state.lock(|cell| cell.borrow().deliver(packet)).is_none_or(|event| self.events.try_send(event).is_ok())
    }

    /// Waits until the host passes something to the connection.
    #[inline]
    pub async fn wakeup(&self) { self.wakeup.wait().await; }

    /// Shared state whose host enabled every event, as TrouBLE enables all
    /// the events this controller sends.
    #[cfg(test)]
    pub(crate) fn with_all_events() -> Self {
        let shared = Self::new();
        shared.state.lock(|cell| {
            let mut state = cell.borrow_mut();
            state.event_mask = u64::MAX;
            state.event_mask_page_2 = u64::MAX;
            state.le_event_mask = u64::MAX;
        });
        shared
    }
}

/// The host side of the controller.
pub struct Hci<'shared> {
    /// State shared with the link layer.
    shared: &'shared Shared,
}

impl<'shared> Hci<'shared> {
    /// Runs an advertising or filter accept list command. Returns the status
    /// and the length of the return parameters written to `returned`.
    fn advertising_command(&self, opcode: u16, params: &[u8], returned: &mut [u8; 8]) -> (u8, usize) {
        // Prepare entropy and AES outside the shared-state critical section.
        let own = (opcode == 0x200A && params == [1]).then(|| self.shared.own_address(None));
        let (status, len, enable) = self.shared.state.lock(|cell| {
            let mut state = cell.borrow_mut();
            let connected = state.connected;
            let enabled = state.legacy_enabled;
            let result = legacy::command(&mut state.legacy, (opcode, params, returned), enabled, connected);
            if let (STATUS_SUCCESS, _, Some(enable)) = result {
                if enable
                    && !enabled
                    && let Some(address) = own
                {
                    state.legacy.own = address;
                }
                state.legacy_enabled = enable;
            }
            result
        });
        if status == STATUS_SUCCESS
            && let Some(value) = enable
        {
            self.shared.changed.signal(());
            info!("advertising {}", value);
        }
        (status, len)
    }

    /// Answers a command.
    async fn command(&self, packet: &[u8]) -> Result<(), TransportError> {
        let Some((&[op_low, op_high, declared], params)) = packet.split_first_chunk::<3>() else {
            return Err(TransportError);
        };
        if usize::from(declared) != params.len() {
            return Err(TransportError);
        }
        let opcode = u16::from_le_bytes([op_low, op_high]);
        if opcode == 0x0C03 && params.is_empty() {
            self.shared.reset_done.reset();
            self.shared.signal_reset();
            self.shared.reset_done.wait().await;
            self.shared.events.send(Packet::command_complete(opcode, STATUS_SUCCESS, &[])).await;
            return Ok(());
        }
        if opcode == 0x1002 && params.is_empty() {
            let mut supported = [0_u8; 64];
            for (octet, bits) in [
                (0, 0x20),
                (2, 0x80),
                (5, 0xC0),
                (10, 0x60),
                (14, 0x28),
                (15, 0x02),
                (22, 0x04),
                (25, 0xF7),
                (26, 0xC3),
                (27, 0xA7),
                (28, 0x0E),
                (32, 0x30),
                (33, 0x30),
                (34, 0x38),
                (35, 0x76),
                (39, 0x04),
            ] {
                if let Some(byte) = supported.get_mut(octet) {
                    *byte = bits;
                }
            }
            self.shared.events.send(Packet::command_complete(opcode, STATUS_SUCCESS, &supported)).await;
            return Ok(());
        }
        if opcode == 0x2018 && params.is_empty() {
            let mut returned = [0; 8];
            crate::rng::fill_async(&mut returned).await;
            self.shared.events.send(Packet::command_complete(opcode, STATUS_SUCCESS, &returned)).await;
            return Ok(());
        }
        let event = if ASYNC_COMMANDS.contains(&opcode) {
            Packet::command_status(opcode, self.command_async(opcode, params))
        } else {
            let mut returned = [0_u8; 8];
            let (status, len) = self.command_sync(opcode, params, &mut returned);
            Packet::command_complete(opcode, status, returned.get(..len).unwrap_or_default())
        };
        self.shared.events.send(event).await;
        if event.bytes.get(2) == Some(&STATUS_SUCCESS) && matches!(opcode, 0x041D | 0x2016) {
            self.shared.state.lock(|cell| cell.borrow_mut().queries |= if opcode == 0x2016 { 1 } else { 2 });
            self.shared.wakeup.signal(());
        }
        if opcode == 0x2032
            && event.bytes.get(2) == Some(&STATUS_SUCCESS)
            && let Some(preferences) = params.get(2..5).and_then(phy_preferences)
        {
            self.shared.state.lock(|cell| cell.borrow_mut().phy_pending = Some(preferences));
            self.shared.wakeup.signal(());
        }
        Ok(())
    }

    /// Starts a command answered with a command status. Returns the status.
    fn command_async(&self, opcode: u16, params: &[u8]) -> u8 {
        if opcode == 0x2013 {
            return self.connection_update(params);
        }
        if matches!(opcode, 0x041D | 0x2016) {
            if params.len() != 2 {
                return STATUS_INVALID_PARAMETERS;
            }
            return self.shared.state.lock(|cell| {
                let mut state = cell.borrow_mut();
                let bit = if opcode == 0x2016 { 1 } else { 2 };
                if !state.connected || params != CONNECTION_HANDLE.to_le_bytes() {
                    STATUS_UNKNOWN_CONNECTION
                } else if state.active_queries & bit != 0 {
                    STATUS_DISALLOWED
                } else {
                    state.active_queries |= bit;
                    STATUS_SUCCESS
                }
            });
        }
        if opcode == 0x2032 {
            if params.len() != 7
                || params.get(2..5).and_then(phy_preferences).is_none()
                || params
                    .get(5..7)
                    .is_none_or(|bytes| bytes.first().is_none_or(|&option| option > 2) || bytes.last() != Some(&0))
            {
                return STATUS_INVALID_PARAMETERS;
            }
            return self.shared.state.lock(|cell| {
                let mut state = cell.borrow_mut();
                if !state.connected || params.get(..2) != Some(CONNECTION_HANDLE.to_le_bytes().as_slice()) {
                    STATUS_UNKNOWN_CONNECTION
                } else if state.active_queries & 4 != 0 {
                    STATUS_DISALLOWED
                } else {
                    state.active_queries |= 4;
                    STATUS_SUCCESS
                }
            });
        }
        if opcode != 0x0406 {
            info!("unsupported command {=u16:#06x}", opcode);
            return STATUS_UNSUPPORTED;
        }
        let Some(&[low, high, reason]) = params.first_chunk::<3>().filter(|_| params.len() == 3) else {
            return STATUS_INVALID_PARAMETERS;
        };
        let connected = self.shared.state.lock(|state| state.borrow().connected);
        if !connected || u16::from_le_bytes([low, high]) != CONNECTION_HANDLE {
            return STATUS_UNKNOWN_CONNECTION;
        }
        if !DISCONNECT_REASONS.contains(&reason) {
            return STATUS_INVALID_PARAMETERS;
        }
        self.shared.disconnect.signal(reason);
        self.shared.wakeup.signal(());
        STATUS_SUCCESS
    }

    /// Runs a command answered with a command complete. Returns the status
    /// and the length of the return parameters written to `returned`.
    fn command_sync(&self, opcode: u16, params: &[u8], returned: &mut [u8; 8]) -> (u8, usize) {
        if matches!(opcode, 0x1001 | 0x1002 | 0x1003 | 0x1009 | 0x2002 | 0x2003 | 0x2018 | 0x201C) && !params.is_empty()
        {
            return (STATUS_INVALID_PARAMETERS, 0);
        }
        match opcode {
            0x1001 | 0x1003 | 0x1009 | 0x201C | 0x2030 => self.information_command(opcode, params, returned),
            // Peer addresses in the resolving list are resolved whenever it
            // holds their key, so enabling resolution changes nothing.
            0x0C31 => {
                if params == [0] {
                    (STATUS_SUCCESS, 0)
                } else {
                    (STATUS_UNSUPPORTED, 0)
                }
            },
            0x0C33 => (if params.len() == 7 { STATUS_SUCCESS } else { STATUS_INVALID_PARAMETERS }, 0),
            0x202D | 0x204E => (self.privacy_command(opcode, params), 0),
            0x2020 | 0x2021 => self.parameter_reply_command(opcode, params, returned),
            0x0C01 | 0x0C63 | 0x2001 => (self.event_mask_command(opcode, params), 0),
            0x202E => (self.private_timeout_command(params), 0),
            0x0C7B | 0x0C7C => self.payload_timeout_command(opcode, params, returned),
            0x2027..=0x2029 => (self.resolving_command(opcode, params), 0),
            0x0C03 => (STATUS_INVALID_PARAMETERS, 0),
            0x2031 => {
                let Some(preferences) = phy_preferences(params) else { return (STATUS_INVALID_PARAMETERS, 0) };
                self.shared.state.lock(|cell| cell.borrow_mut().preferred_phys = preferences);
                (STATUS_SUCCESS, 0)
            },
            0x2002 => {
                let [len_low, len_high] = u16::try_from(ACL_MAX).unwrap_or_default().to_le_bytes();
                returned.get_mut(..3).map_or((STATUS_SUCCESS, 0), |target| {
                    target.copy_from_slice(&[len_low, len_high, u8::try_from(ACL_OUT_BUFFERS).unwrap_or(1)]);
                    (STATUS_SUCCESS, 3)
                })
            },
            0x2003 => {
                for (target, source) in returned.iter_mut().zip(FEATURES) {
                    *target = source;
                }
                (STATUS_SUCCESS, 8)
            },
            0x2005..=0x200A | 0x200F..=0x2012 => self.advertising_command(opcode, params, returned),

            0x201A | 0x201B => {
                let expected = if opcode == 0x201A { 18 } else { 2 };
                if params.len() != expected {
                    return (STATUS_INVALID_PARAMETERS, 2);
                }
                if let (Some(target), Some(handle)) = (returned.get_mut(..2), params.get(..2)) {
                    target.copy_from_slice(handle);
                }
                let status = self.shared.state.lock(|cell| {
                    let mut state = cell.borrow_mut();
                    if !state.connected || params.get(..2) != Some(CONNECTION_HANDLE.to_le_bytes().as_slice()) {
                        return STATUS_UNKNOWN_CONNECTION;
                    }
                    if !state.ltk_pending {
                        return STATUS_DISALLOWED;
                    }
                    let key = if opcode == 0x201A {
                        params.get(2..).and_then(<[u8]>::first_chunk::<16>).copied()
                    } else {
                        None
                    };
                    state.ltk_pending = false;
                    self.shared.ltk.signal(key);
                    self.shared.wakeup.signal(());
                    STATUS_SUCCESS
                });
                (status, 2)
            },
            _ => {
                info!("unknown command {=u16:#06x}", opcode);
                (STATUS_UNKNOWN_COMMAND, 0)
            },
        }
    }

    /// Asks the central for new connection parameters (LE Connection
    /// Update). Returns the status: an unsupported remote feature makes the
    /// host use the L2CAP request instead.
    fn connection_update(&self, params: &[u8]) -> u8 {
        let Some(&[handle0, handle1, min0, min1, max0, max1, latency0, latency1, timeout0, timeout1, _, _, _, _]) =
            params.first_chunk::<14>().filter(|_| params.len() == 14)
        else {
            return STATUS_INVALID_PARAMETERS;
        };
        let (connected, features, busy) = self.shared.state.lock(|cell| {
            let state = cell.borrow();
            (state.connected, state.remote_features, state.active_queries & QUERY_CONNECTION_UPDATE != 0)
        });
        if !connected || u16::from_le_bytes([handle0, handle1]) != CONNECTION_HANDLE {
            return STATUS_UNKNOWN_CONNECTION;
        }
        // One update at a time, as in Zephyr: a second request would replace
        // the first, whose complete event the host then never gets.
        if busy {
            return STATUS_DISALLOWED;
        }
        if features & 0x02 == 0 {
            return STATUS_UNSUPPORTED_REMOTE_FEATURE;
        }
        let [min, max, latency, timeout] =
            [[min0, min1], [max0, max1], [latency0, latency1], [timeout0, timeout1]].map(u16::from_le_bytes);
        if min > max || !valid_connection_parameters(max, latency, timeout, 1, 0) || min < 6 {
            return STATUS_INVALID_PARAMETERS;
        }
        self.shared.state.lock(|cell| cell.borrow_mut().active_queries |= QUERY_CONNECTION_UPDATE);
        self.shared.param_request.signal([min, max, latency, timeout]);
        self.shared.wakeup.signal(());
        STATUS_SUCCESS
    }

    /// Sets the event mask (0x0C01), its page 2 (0x0C63) or the LE event
    /// mask (0x2001). Returns the status.
    fn event_mask_command(&self, opcode: u16, params: &[u8]) -> u8 {
        let Some(&bytes) = params.first_chunk::<8>().filter(|_| params.len() == 8) else {
            return STATUS_INVALID_PARAMETERS;
        };
        let mask = u64::from_le_bytes(bytes);
        self.shared.state.lock(|cell| {
            let mut state = cell.borrow_mut();
            match opcode {
                0x0C01 => state.event_mask = mask,
                0x0C63 => state.event_mask_page_2 = mask,
                _ => state.le_event_mask = mask,
            }
        });
        STATUS_SUCCESS
    }

    /// Answers controller identity and capability queries.
    fn information_command(&self, opcode: u16, params: &[u8], returned: &mut [u8; 8]) -> (u8, usize) {
        match opcode {
            0x1001 if params.is_empty() => {
                returned.copy_from_slice(&[0x0B, 0, 0, 0x0B, 0xFF, 0xFF, 0, 0]);
                (STATUS_SUCCESS, 8)
            },
            0x1003 if params.is_empty() => {
                returned[4] = 0x60; // LE supported, BR/EDR not supported.
                (STATUS_SUCCESS, 8)
            },
            0x1009 if params.is_empty() => {
                use embassy_nrf::pac::{FICR, ficr::vals::Deviceaddrtype};
                // Never present a factory random address as a public identity.
                // LE-only controllers without a public address return zero.
                if FICR.deviceaddrtype().read().deviceaddrtype() == Deviceaddrtype::Public {
                    let low = FICR.deviceaddr(0).read().to_le_bytes();
                    let high = FICR.deviceaddr(1).read().to_le_bytes();
                    returned[..4].copy_from_slice(&low);
                    returned[4..6].copy_from_slice(&high[..2]);
                }
                (STATUS_SUCCESS, 6)
            },
            0x2030 => {
                if params.len() != 2 {
                    return (STATUS_INVALID_PARAMETERS, 0);
                }
                self.shared.state.lock(|cell| {
                    let state = cell.borrow();
                    if !state.connected || params != CONNECTION_HANDLE.to_le_bytes() {
                        return (STATUS_UNKNOWN_CONNECTION, 0);
                    }
                    let [rx, tx] = state.phys;
                    returned[..4].copy_from_slice(&[0, 0, tx, rx]);
                    (STATUS_SUCCESS, 4)
                })
            },
            0x201C if params.is_empty() => {
                // Standalone legacy advertising states and peripheral
                // connection.
                returned[..2].copy_from_slice(&[0x8F, 0]);
                (STATUS_SUCCESS, 8)
            },
            _ => (STATUS_INVALID_PARAMETERS, 0),
        }
    }

    /// Creates the host interface.
    #[inline]
    #[must_use = "the interface is only created"]
    pub const fn new(shared: &'shared Shared) -> Self { Self { shared } }

    /// Takes the host's answer to a central's connection parameter request:
    /// LE Remote Connection Parameter Request Reply (0x2020) with the
    /// parameters to offer, or Negative Reply (0x2021) with the reason.
    /// Returns the status and the handle.
    fn parameter_reply_command(&self, opcode: u16, params: &[u8], returned: &mut [u8; 8]) -> (u8, usize) {
        let Some(&[handle0, handle1]) = params.first_chunk::<2>() else { return (STATUS_INVALID_PARAMETERS, 0) };
        let reply = if opcode == 0x2020 {
            let Some(&[_, _, min0, min1, max0, max1, latency0, latency1, timeout0, timeout1, _, _, _, _]) =
                params.first_chunk::<14>().filter(|_| params.len() == 14)
            else {
                return (STATUS_INVALID_PARAMETERS, 0);
            };
            let [min, max, latency, timeout] =
                [[min0, min1], [max0, max1], [latency0, latency1], [timeout0, timeout1]].map(u16::from_le_bytes);
            if min > max || min < 6 || !valid_connection_parameters(max, latency, timeout, 1, 0) {
                return (STATUS_INVALID_PARAMETERS, 0);
            }
            Ok([min, max, latency, timeout])
        } else {
            let Some(&[_, _, reason]) = params.first_chunk::<3>().filter(|_| params.len() == 3) else {
                return (STATUS_INVALID_PARAMETERS, 0);
            };
            Err(reason)
        };
        returned[0] = handle0;
        returned[1] = handle1;
        let status = self.shared.state.lock(|cell| {
            let mut state = cell.borrow_mut();
            if !state.connected || u16::from_le_bytes([handle0, handle1]) != CONNECTION_HANDLE {
                STATUS_UNKNOWN_CONNECTION
            } else if state.active_queries & QUERY_REMOTE_PARAMETERS == 0 {
                STATUS_DISALLOWED
            } else {
                // One answer per request.
                state.active_queries &= !QUERY_REMOTE_PARAMETERS;
                STATUS_SUCCESS
            }
        });
        if status == STATUS_SUCCESS {
            self.shared.parameter_reply.signal(reply);
            self.shared.wakeup.signal(());
        }
        (status, 2)
    }

    /// Runs an authenticated payload timeout command: reading (0x0C7B) and
    /// writing (0x0C7C) the timeout. Returns the status and the length of
    /// the return parameters.
    fn payload_timeout_command(&self, opcode: u16, params: &[u8], returned: &mut [u8; 8]) -> (u8, usize) {
        let expected = if opcode == 0x0C7B { 2 } else { 4 };
        let Some(&[handle0, handle1]) = params.first_chunk::<2>().filter(|_| params.len() == expected) else {
            return (STATUS_INVALID_PARAMETERS, 0);
        };
        if u16::from_le_bytes([handle0, handle1]) != CONNECTION_HANDLE {
            return (STATUS_UNKNOWN_CONNECTION, 0);
        }
        if !self.shared.state.lock(|cell| cell.borrow().connected) {
            return (STATUS_UNKNOWN_CONNECTION, 0);
        }
        let timeout = params.get(2..4).and_then(<[u8]>::first_chunk::<2>).map(|&bytes| u16::from_le_bytes(bytes));
        if timeout == Some(0) {
            return (STATUS_INVALID_PARAMETERS, 0);
        }
        let current = self.shared.state.lock(|cell| {
            let mut state = cell.borrow_mut();
            if let Some(value) = timeout {
                state.payload_timeout = value;
            }
            state.payload_timeout
        });
        let [timeout0, timeout1] = current.to_le_bytes();
        let response = [handle0, handle1, timeout0, timeout1];
        let len = if opcode == 0x0C7B { 4 } else { 2 };
        for (target, source) in returned.iter_mut().zip(response.iter().take(len)) {
            *target = *source;
        }
        (STATUS_SUCCESS, len)
    }

    /// Applies address resolution enable and per-peer privacy modes.
    fn privacy_command(&self, opcode: u16, params: &[u8]) -> u8 {
        self.shared.state.lock(|cell| {
            let mut state = cell.borrow_mut();
            if state.legacy_enabled {
                return STATUS_DISALLOWED;
            }
            if opcode == 0x202D {
                let &[enable] = params else { return STATUS_INVALID_PARAMETERS };
                if enable > 1 {
                    return STATUS_INVALID_PARAMETERS;
                }
                state.legacy.resolution_enabled = enable == 1;
            } else {
                let &[kind, addr0, addr1, addr2, addr3, addr4, addr5, mode] = params else {
                    return STATUS_INVALID_PARAMETERS;
                };
                if kind > 1 || mode > 1 {
                    return STATUS_INVALID_PARAMETERS;
                }
                if !state
                    .legacy
                    .resolving
                    .set_mode(Peer::new([addr0, addr1, addr2, addr3, addr4, addr5], kind == 1), mode == 1)
                {
                    return STATUS_UNKNOWN_CONNECTION;
                }
            }
            STATUS_SUCCESS
        })
    }

    /// Sets the lifetime of resolvable private addresses (LE Set Resolvable
    /// Private Address Timeout). The current address keeps its expiry.
    fn private_timeout_command(&self, params: &[u8]) -> u8 {
        let Some(&bytes) = params.first_chunk::<2>().filter(|_| params.len() == 2) else {
            return STATUS_INVALID_PARAMETERS;
        };
        let seconds = u16::from_le_bytes(bytes);
        if !(1..=PRIVATE_ADDRESS_TIMEOUT_MAX).contains(&seconds) {
            return STATUS_INVALID_PARAMETERS;
        }
        self.shared.state.lock(|cell| cell.borrow_mut().private_timeout = Duration::from_secs(u64::from(seconds)));
        STATUS_SUCCESS
    }

    /// Runs LE Remote Connection Parameter Request Reply or Negative Reply.
    /// Returns the status.
    #[cfg(test)]
    pub(crate) fn reply_parameters(&self, opcode: u16, params: &[u8]) -> u8 {
        self.parameter_reply_command(opcode, params, &mut [0; 8]).0
    }

    /// Runs a resolving list command: add (0x2027), remove (0x2028) or clear
    /// (0x2029). Returns the status.
    fn resolving_command(&self, opcode: u16, params: &[u8]) -> u8 {
        if self.shared.state.lock(|cell| {
            let state = cell.borrow();
            state.legacy_enabled && state.legacy.resolution_enabled
        }) {
            return STATUS_DISALLOWED;
        }
        match opcode {
            0x2027 => {
                let (Some(&[peer_type, a0, a1, a2, a3, a4, a5]), Some(peer_irk), Some(local)) = (
                    params.first_chunk::<7>(),
                    params.get(7..).and_then(<[u8]>::first_chunk::<16>),
                    params.get(23..).and_then(<[u8]>::first_chunk::<16>),
                ) else {
                    return STATUS_INVALID_PARAMETERS;
                };
                if params.len() != 39 || peer_type > 1 {
                    return STATUS_INVALID_PARAMETERS;
                }
                let peer = Peer::new([a0, a1, a2, a3, a4, a5], peer_type == 1);
                if !self.shared.state.lock(|cell| cell.borrow().legacy.resolving.can_add(peer)) {
                    return STATUS_MEMORY_FULL;
                }
                let needs_address = *local != [0; 16]
                    && self.shared.state.lock(|cell| {
                        let state = cell.borrow();
                        state.legacy_enabled && state.legacy.private && state.legacy.own == state.legacy.address
                    });
                let own = needs_address.then(|| self.shared.own_address(Some(*local)));
                let added = self.shared.state.lock(|cell| {
                    let mut state = cell.borrow_mut();
                    if *local != [0; 16] {
                        // Advertising that started before the key arrived
                        // moves to a private address now.
                        if let Some(address) = own {
                            state.legacy.own = address;
                        }
                    }
                    state.legacy.resolving.add_keys(peer, *peer_irk, *local)
                });
                if added { STATUS_SUCCESS } else { STATUS_MEMORY_FULL }
            },
            0x2028 => {
                let Some(&[peer_type, a0, a1, a2, a3, a4, a5]) = params
                    .first_chunk::<7>()
                    .filter(|_| params.len() == 7 && params.first().is_some_and(|&kind| kind <= 1))
                else {
                    return STATUS_INVALID_PARAMETERS;
                };
                let peer = Peer::new([a0, a1, a2, a3, a4, a5], peer_type == 1);
                self.shared.state.lock(|cell| {
                    let mut state = cell.borrow_mut();
                    state.legacy.resolving.remove(peer);
                    if let Some(&mut (_, ref mut key, _)) = state.private_address.as_mut() {
                        crypto::wipe(key);
                    }
                    state.private_address = None;
                });
                STATUS_SUCCESS
            },
            _ => {
                if !params.is_empty() {
                    return STATUS_INVALID_PARAMETERS;
                }
                self.shared.state.lock(|cell| {
                    cell.borrow_mut().forget_keys();
                });
                STATUS_SUCCESS
            },
        }
    }

    /// Passes ACL data from the host to the link layer.
    async fn send_acl(&self, packet: &[u8]) -> Result<(), TransportError> {
        let Some((&[low, flags, len_low, len_high], payload)) = packet.split_first_chunk::<4>() else {
            return Err(TransportError);
        };
        let handle = u16::from_le_bytes([low, flags & 0x0F]);
        if handle != CONNECTION_HANDLE
            || flags & 0xC0 != 0
            || flags & 0x30 == 0x30
            || payload.len() > ACL_MAX
            || payload.len() != usize::from(u16::from_le_bytes([len_low, len_high]))
        {
            return Err(TransportError);
        }
        let epoch = self
            .shared
            .state
            .lock(|cell| {
                let state = cell.borrow();
                state.connected.then_some(state.epoch)
            })
            .ok_or(TransportError)?;
        let llid = if payload.is_empty() || (flags >> 4_u8) & 0x03 == 0x01 { Llid::Continuation } else { Llid::Start };
        let mut data = [0_u8; ACL_MAX];
        let len = payload.len();
        if let (Some(target), Some(source)) = (data.get_mut(..len), payload.get(..len)) {
            target.copy_from_slice(source);
        }
        self.shared.acl_out.send(AclOut { data, epoch, len: u8::try_from(len).unwrap_or_default(), llid }).await;
        let still_connected = self.shared.state.lock(|cell| {
            let state = cell.borrow();
            state.connected && state.epoch == epoch
        });
        if !still_connected {
            return Err(TransportError);
        }
        self.shared.wakeup.signal(());
        Ok(())
    }
}

impl embedded_io::ErrorType for Hci<'_> {
    type Error = TransportError;
}

impl Transport for Hci<'_> {
    #[inline]
    async fn read<'buffer, P>(&self, rx: &'buffer mut [u8]) -> Result<P, Self::Error>
    where
        P: PacketToHost<'buffer>,
    {
        let packet = match select(self.shared.events.receive(), self.shared.acl_in.receive()).await {
            Either::First(packet) | Either::Second(packet) => packet,
        };
        let mut bytes = packet.bytes.get(..packet.len).unwrap_or_default();
        P::read_hci(packet.kind, &mut bytes, rx).map_err(TransportError::from)
    }

    #[inline]
    async fn write<P>(&self, tx: &P) -> Result<(), Self::Error>
    where
        P: PacketToController,
    {
        let mut buffer = [0_u8; HOST_PACKET_MAX];
        let size = tx.size().min(HOST_PACKET_MAX);
        let Some(bytes) = buffer.get_mut(..size) else { return Err(TransportError) };
        if tx.write_hci(&mut *bytes).is_err() {
            return Err(TransportError);
        }
        match P::KIND {
            PacketKind::Cmd => self.command(bytes).await?,
            PacketKind::AclData => self.send_acl(bytes).await?,
            PacketKind::SyncData | PacketKind::Event | PacketKind::IsoData => return Err(TransportError),
        }
        Ok(())
    }
}

/// Validates the common `All_PHYs`, `TX_PHYs` and `RX_PHYs` fields.
fn phy_preferences(params: &[u8]) -> Option<[u8; 2]> {
    let &[all, tx, rx] = params else { return None };
    if all > 3 {
        return None;
    }
    let transmit = if all & 1 != 0 { 3 } else { tx };
    let receive = if all & 2 != 0 { 3 } else { rx };
    ((1..=3).contains(&transmit) && (1..=3).contains(&receive)).then_some([transmit, receive])
}

/// Whether `bit` is set in an event mask.
fn mask_bit(mask: u64, bit: u8) -> bool { bit < 64 && mask & 1_u64.wrapping_shl(u32::from(bit)) != 0 }

#[cfg(test)]
mod tests {
    use super::*;
    use core::{
        future::Future,
        pin::pin,
        task::{Context, Poll, Waker},
    };

    #[test]
    fn reset_waits_for_radio_shutdown_and_clears_old_queues() {
        let shared = Shared::new();
        shared.set_connected(true);
        assert!(shared.try_push_event(Packet::completed_packets(2)));
        let hci = Hci::new(&shared);
        let mut reset = pin!(hci.command(&[3, 12, 0]));
        let mut context = Context::from_waker(Waker::noop());
        assert!(reset.as_mut().poll(&mut context).is_pending());
        assert!(shared.state.lock(|cell| cell.borrow().connected));
        assert!(shared.take_reset());
        shared.complete_reset();
        assert!(reset.as_mut().poll(&mut context).is_ready());
        let event = shared.events.try_receive().unwrap();
        assert_eq!(&event.bytes[..6], &[14, 4, 1, 3, 12, 0]);
        assert!(shared.events.try_receive().is_err());
        assert!(!shared.state.lock(|cell| cell.borrow().connected));
    }

    #[test]
    fn a_second_connection_update_waits_for_the_first_to_complete() {
        let shared = Shared::new();
        shared.set_connected(true);
        shared.set_remote_features(0x02);
        let hci = Hci::new(&shared);
        let update = [0, 0, 6, 0, 12, 0, 0, 0, 100, 0, 0, 0, 0, 0];
        assert_eq!(hci.command_async(0x2013, &update), STATUS_SUCCESS);
        assert_eq!(hci.command_async(0x2013, &update), STATUS_DISALLOWED);
        assert_eq!(shared.take_param_request(), Some([6, 12, 0, 100]));
        shared.finish_param_request();
        assert_eq!(hci.command_async(0x2013, &update), STATUS_SUCCESS);
        // A link that ends forgets the request.
        shared.set_connected(false);
        shared.set_connected(true);
        shared.set_remote_features(0x02);
        assert_eq!(hci.command_async(0x2013, &update), STATUS_SUCCESS);
    }

    #[test]
    fn privacy_enable_mode_and_list_changes_are_enforced() {
        let shared = Shared::new();
        let hci = Hci::new(&shared);
        let mut returned = [0; 8];
        let mut add = [0; 39];
        add[0] = 1;
        add[1..7].copy_from_slice(&[1; 6]);
        assert_eq!(hci.command_sync(0x2027, &add, &mut returned).0, STATUS_SUCCESS);
        assert_eq!(hci.command_sync(0x204E, &[1, 1, 1, 1, 1, 1, 1, 1], &mut returned).0, STATUS_SUCCESS);
        assert_eq!(hci.command_sync(0x202D, &[1], &mut returned).0, STATUS_SUCCESS);
        shared.state.lock(|cell| cell.borrow_mut().legacy_enabled = true);
        assert_eq!(hci.command_sync(0x2029, &[], &mut returned).0, STATUS_DISALLOWED);
        assert_eq!(hci.command_sync(0x202D, &[0], &mut returned).0, STATUS_DISALLOWED);
        shared.state.lock(|cell| cell.borrow_mut().legacy_enabled = false);
        assert_eq!(hci.command_sync(0x202D, &[2], &mut returned).0, STATUS_INVALID_PARAMETERS);
        assert_eq!(hci.command_sync(0x202D, &[0], &mut returned).0, STATUS_SUCCESS);
        assert!(!shared.state.lock(|cell| cell.borrow().legacy.resolution_enabled));
    }

    #[test]
    fn resolved_connection_event_reports_identity_and_peer_rpa() {
        let on_air = Peer::new([1, 2, 3, 4, 5, 0x40], true);
        let identity = Peer::new([6; 6], false);
        let packet = Packet::connection_complete_resolved(
            0,
            (on_air, Some([7; 6])),
            ConnectionParams::new(12, 0, 600),
            0,
            Some(identity),
        );
        assert_eq!(packet.bytes[7], 2);
        assert_eq!(&packet.bytes[8..14], &identity.address);
        assert_eq!(&packet.bytes[20..26], &on_air.address);
    }

    #[test]
    fn supported_commands_fit_and_do_not_claim_scanning_or_central_role() {
        let shared = Shared::new();
        let hci = Hci::new(&shared);
        assert!(run(hci.command(&[2, 16, 0])).is_ok());
        let packet = shared.events.try_receive().unwrap();
        assert_eq!(packet.len, 70);
        assert_eq!(packet.bytes[1], 68);
        assert_eq!(packet.bytes[6 + 26] & 0x3C, 0);
        assert_ne!(packet.bytes[6 + 5] & 0x80, 0);
    }

    #[test]
    fn host_phy_command_validates_and_publishes_only_after_status() {
        let shared = Shared::new();
        shared.set_connected(true);
        let hci = Hci::new(&shared);
        assert!(run(hci.command(&[0x32, 0x20, 7, 0, 0, 0, 1, 2, 0, 0])).is_ok());
        let status = shared.events.try_receive().unwrap();
        assert_eq!(&status.bytes[..6], &[15, 4, 0, 1, 0x32, 0x20]);
        assert_eq!(shared.take_phy_request(), Some([1, 2]));
        assert_eq!(hci.command_async(0x2032, &[0, 0, 0, 1, 2, 0, 0]), STATUS_DISALLOWED);
        shared.complete_query(4);
        assert_eq!(hci.command_async(0x2032, &[0, 0, 0, 4, 2, 0, 0]), STATUS_INVALID_PARAMETERS);
        let mut returned = [0; 8];
        assert_eq!(hci.command_sync(0x2031, &[3, 0, 0], &mut returned).0, STATUS_SUCCESS);
        assert_eq!(shared.preferred_phys(), [3, 3]);
    }

    #[test]
    fn authenticated_timeout_commands_require_a_live_connection() {
        let shared = Shared::new();
        let hci = Hci::new(&shared);
        let mut returned = [0; 8];
        assert_eq!(hci.command_sync(0x0C7B, &[0, 0], &mut returned).0, STATUS_UNKNOWN_CONNECTION);
        assert_eq!(hci.command_sync(0x0C7C, &[0, 0, 100, 0], &mut returned).0, STATUS_UNKNOWN_CONNECTION);
        assert_eq!(shared.payload_timeout(), u32::from(DEFAULT_PAYLOAD_TIMEOUT) * 10_000);
        shared.set_connected(true);
        assert_eq!(hci.command_sync(0x0C7C, &[0, 0, 100, 0], &mut returned).0, STATUS_SUCCESS);
        assert_eq!(shared.payload_timeout(), 1_000_000);
        assert_eq!(hci.command_sync(0x0C7B, &[0, 0], &mut returned), (STATUS_SUCCESS, 4));
        assert_eq!(&returned[..4], &[0, 0, 100, 0]);
    }

    fn run<F: Future>(future: F) -> F::Output {
        let mut future = pin!(future);
        match future.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(result) => result,
            Poll::Pending => panic!("operation unexpectedly blocked"),
        }
    }

    #[test]
    fn cached_private_address_survives_restarts_but_not_expiry_or_key_changes() {
        let shared = Shared::new();
        let address = Peer::new([1, 2, 3, 4, 5, 0x40], true);
        shared.state.lock(|cell| {
            let mut state = cell.borrow_mut();
            state.private_address = Some((address, [7; 16], Instant::from_secs(900)));
            assert!(state.cached_address([7; 16], Instant::from_secs(3)) == Some(address));
            assert!(state.cached_address([7; 16], Instant::from_secs(15)) == Some(address));
            assert!(state.cached_address([7; 16], Instant::from_secs(899)) == Some(address));
            assert!(state.cached_address([7; 16], Instant::from_secs(900)) == None);
            assert!(state.cached_address([8; 16], Instant::from_secs(15)) == None);
        });
    }

    #[test]
    fn connection_complete_reports_the_local_private_address() {
        use bt_hci::{FromHciBytes as _, event::le::LeEnhancedConnectionComplete};
        let central = Peer::new([1, 2, 3, 4, 5, 6], true);
        let local = [0xAA, 0xFB, 0x0D, 0x94, 0x81, 0x70];
        let packet =
            Packet::connection_complete(STATUS_SUCCESS, (central, Some(local)), ConnectionParams::new(12, 0, 600), 5);
        assert_eq!(&packet.bytes[..3], &[EVENT_LE_META, 31, LE_ENHANCED_CONNECTION_COMPLETE]);
        let event = LeEnhancedConnectionComplete::from_hci_bytes_complete(&packet.bytes[3..packet.len]).unwrap();
        assert_eq!(event.peer_addr.raw(), &central.address);
        assert_eq!(event.local_resolvable_private_addr.raw(), &local);
        assert_eq!(event.peer_resolvable_private_addr.raw(), &[0; 6]);
        assert_eq!(event.conn_interval.as_micros(), 15_000);
        let identity =
            Packet::connection_complete(STATUS_SUCCESS, (central, None), ConnectionParams::new(12, 0, 600), 5);
        let event = LeEnhancedConnectionComplete::from_hci_bytes_complete(&identity.bytes[3..identity.len]).unwrap();
        assert_eq!(event.local_resolvable_private_addr.raw(), &[0; 6]);
    }

    #[test]
    fn blocked_acl_write_cannot_enter_the_next_connection() {
        let shared = Shared::new();
        shared.set_connected(true);
        let hci = Hci::new(&shared);
        let packet = [0, 0x20, 1, 0, 42];
        for _ in 0..ACL_OUT_BUFFERS {
            run(hci.send_acl(&packet)).unwrap();
        }
        let pending = hci.send_acl(&packet);
        let mut pending = pin!(pending);
        let mut cx = Context::from_waker(Waker::noop());
        assert!(pending.as_mut().poll(&mut cx).is_pending());
        shared.set_connected(false);
        shared.set_connected(true);
        assert!(matches!(pending.as_mut().poll(&mut cx), Poll::Ready(Err(_))));
        assert!(shared.next_acl_out_if(true).is_none());
        run(hci.send_acl(&[0, 0x20, 1, 0, 99])).unwrap();
        assert_eq!(shared.next_acl_out_if(true).unwrap().data[0], 99);
    }

    #[test]
    fn malformed_acl_is_rejected_without_truncation_or_queue_changes() {
        let shared = Shared::new();
        shared.set_connected(true);
        let hci = Hci::new(&shared);
        for packet in [
            &[][..],
            &[0, 0x20, 2, 0, 42][..],
            &[1, 0x20, 1, 0, 42][..],
            &[0, 0x30, 1, 0, 42][..],
            &[0, 0xA0, 1, 0, 42][..],
        ] {
            assert!(run(hci.send_acl(packet)).is_err());
        }
        let mut oversized = [0; 4 + ACL_MAX + 1];
        oversized[1] = 0x20;
        oversized[2] = (ACL_MAX + 1).try_into().unwrap();
        assert!(run(hci.send_acl(&oversized)).is_err());
        assert!(!shared.has_acl_out());
        run(hci.send_acl(&[0, 0x20, 0, 0])).unwrap();
        assert!(shared.next_acl_out_if(true).unwrap().llid == Llid::Continuation);
    }

    #[test]
    fn key_reply_requires_the_right_handle_an_exact_length_and_a_pending_request() {
        let shared = Shared::with_all_events();
        shared.set_connected(true);
        let hci = Hci::new(&shared);
        let mut returned = [0; 8];
        let mut params = [0xAA; 18];
        params[..2].fill(0);
        assert_eq!(hci.command_sync(0x201A, &params, &mut returned).0, STATUS_DISALLOWED);
        assert!(shared.request_ltk([0; 8], [0; 2]));
        assert_eq!(hci.command_sync(0x201A, &params[..17], &mut returned).0, STATUS_INVALID_PARAMETERS);
        params[0] = 1;
        assert_eq!(hci.command_sync(0x201A, &params, &mut returned).0, STATUS_UNKNOWN_CONNECTION);
        assert!(shared.take_ltk().is_none());
        params[0] = 0;
        assert_eq!(hci.command_sync(0x201A, &params, &mut returned).0, STATUS_SUCCESS);
        assert_eq!(shared.take_ltk(), Some(Some([0xAA; 16])));
        assert_eq!(hci.command_sync(0x201A, &params, &mut returned).0, STATUS_DISALLOWED);
        assert!(shared.request_ltk([0; 8], [0; 2]));
        assert_eq!(hci.command_sync(0x201B, &[0, 0], &mut returned).0, STATUS_SUCCESS);
        assert_eq!(shared.take_ltk(), Some(None));
    }

    #[test]
    fn disconnect_commands_and_command_lengths_are_validated() {
        let shared = Shared::new();
        shared.set_connected(true);
        let hci = Hci::new(&shared);
        assert!(run(hci.command(&[0x09, 0x10, 1])).is_err());
        assert!(shared.events.try_receive().is_err());
        assert_eq!(hci.command_async(0x0406, &[0, 0]), STATUS_INVALID_PARAMETERS);
        assert_eq!(hci.command_async(0x0406, &[1, 0, 0x13]), STATUS_UNKNOWN_CONNECTION);
        assert!(shared.take_disconnect().is_none());
        assert_eq!(hci.command_async(0x0406, &[0, 0, 0x16]), STATUS_INVALID_PARAMETERS);
        assert!(shared.take_disconnect().is_none());
        assert_eq!(hci.command_async(0x0406, &[0, 0, 0x13]), STATUS_SUCCESS);
        assert_eq!(shared.take_disconnect(), Some(0x13));
    }

    #[test]
    fn reset_forgets_keys_settings_and_the_link() {
        let shared = Shared::new();
        shared.set_connected(true);
        let hci = Hci::new(&shared);
        let mut returned = [0; 8];
        let mut add = [0_u8; 39];
        add[0] = 1;
        add[1..7].copy_from_slice(&[1, 2, 3, 4, 5, 0xC6]);
        add[7..23].fill(0x11);
        add[23..39].fill(0x22);
        assert_eq!(hci.command_sync(0x2027, &add, &mut returned).0, STATUS_SUCCESS);
        assert_eq!(hci.command_sync(0x0C7C, &[0, 0, 100, 0], &mut returned).0, STATUS_SUCCESS);
        assert_eq!(hci.command_sync(0x202E, &[60, 0], &mut returned).0, STATUS_SUCCESS);
        let epoch = shared.state.lock(|cell| cell.borrow().epoch);
        shared.complete_reset();
        shared.state.lock(|cell| {
            let state = cell.borrow();
            assert!(state.legacy.resolving.is_empty());
            assert_eq!(state.payload_timeout, DEFAULT_PAYLOAD_TIMEOUT);
            assert_eq!(state.private_timeout, PRIVATE_ADDRESS_TIMEOUT);
            assert!(!state.connected);
            assert_ne!(state.epoch, epoch);
        });
    }

    /// The events in the host queue, by code and LE subevent.
    fn queued(shared: &Shared) -> ([u8; 4], usize) {
        let mut codes = [0; 4];
        let mut count = 0;
        while let Ok(packet) = shared.events.try_receive() {
            codes[count] = if packet.bytes[0] == EVENT_LE_META { packet.bytes[2] } else { packet.bytes[0] };
            count += 1;
        }
        (codes, count)
    }

    #[test]
    fn masked_events_are_dropped_and_only_unmaskable_ones_pass_by_default() {
        let shared = Shared::new();
        shared.set_connected(true);
        assert!(shared.try_push_event(Packet::connection_update_complete(0, ConnectionParams::new(12, 0, 600))));
        assert!(shared.try_push_event(Packet::payload_timeout_expired()));
        assert!(shared.try_push_event(Packet::encryption_change(0, true)));
        assert!(shared.try_push_event(Packet::completed_packets(1)));
        assert_eq!(queued(&shared), ([EVENT_ENCRYPTION_CHANGE, EVENT_COMPLETED_PACKETS, 0, 0], 2));
        // LE meta events are off by default: a key request cannot reach the
        // host, which then has no key.
        assert!(shared.request_ltk([0; 8], [0; 2]));
        assert_eq!(shared.take_ltk(), Some(None));
        assert_eq!(queued(&shared).1, 0);
        let hci = Hci::new(&shared);
        let mut returned = [0; 8];
        assert_eq!(hci.command_sync(0x0C01, &[0; 7], &mut returned).0, STATUS_INVALID_PARAMETERS);
        assert_eq!(hci.command_sync(0x0C01, &(1_u64 << 61).to_le_bytes(), &mut returned).0, STATUS_SUCCESS);
        assert_eq!(hci.command_sync(0x0C63, &(1_u64 << 23).to_le_bytes(), &mut returned).0, STATUS_SUCCESS);
        assert!(shared.try_push_event(Packet::payload_timeout_expired()));
        assert!(shared.try_push_event(Packet::connection_update_complete(0, ConnectionParams::new(12, 0, 600))));
        assert!(shared.try_push_event(Packet::disconnection_complete(0x13)));
        assert_eq!(queued(&shared), ([EVENT_PAYLOAD_TIMEOUT_EXPIRED, LE_CONNECTION_UPDATE_COMPLETE, 0, 0], 2));
    }

    #[test]
    fn a_host_without_the_enhanced_event_gets_the_plain_connection_complete() {
        use bt_hci::{FromHciBytes as _, event::le::LeConnectionComplete};
        let shared = Shared::new();
        let hci = Hci::new(&shared);
        let mut returned = [0; 8];
        assert_eq!(hci.command_sync(0x0C01, &(1_u64 << 61).to_le_bytes(), &mut returned).0, STATUS_SUCCESS);
        let central = Peer::new([1, 2, 3, 4, 5, 6], true);
        let event = || {
            Packet::connection_complete(STATUS_SUCCESS, (central, Some([9; 6])), ConnectionParams::new(12, 4, 600), 5)
        };
        assert!(shared.try_push_event(event()));
        let packet = shared.events.try_receive().unwrap();
        assert_eq!(&packet.bytes[..3], &[EVENT_LE_META, 19, LE_CONNECTION_COMPLETE]);
        let parsed = LeConnectionComplete::from_hci_bytes_complete(&packet.bytes[3..packet.len]).unwrap();
        assert_eq!(parsed.peer_addr.raw(), &central.address);
        assert_eq!(parsed.conn_interval.as_micros(), 15_000);
        assert_eq!(parsed.peripheral_latency, 4);
        assert_eq!(parsed.supervision_timeout.as_millis(), 6000);
        assert_eq!(hci.command_sync(0x2001, &(1_u64 << 9).to_le_bytes(), &mut returned).0, STATUS_SUCCESS);
        assert!(shared.try_push_event(event()));
        assert_eq!(&shared.events.try_receive().unwrap().bytes[..3], &[
            EVENT_LE_META,
            31,
            LE_ENHANCED_CONNECTION_COMPLETE
        ]);
        assert_eq!(hci.command_sync(0x2001, &[0; 8], &mut returned).0, STATUS_SUCCESS);
        assert!(shared.try_push_event(event()));
        assert!(shared.events.try_receive().is_err());
    }

    #[test]
    fn the_private_address_timeout_is_checked_and_kept() {
        let shared = Shared::new();
        let hci = Hci::new(&shared);
        let mut returned = [0; 8];
        for params in [&[0, 0][..], &[0x11, 0x0E][..], &[60][..]] {
            assert_eq!(hci.command_sync(0x202E, params, &mut returned).0, STATUS_INVALID_PARAMETERS);
        }
        assert_eq!(hci.command_sync(0x202E, &[0x10, 0x0E], &mut returned).0, STATUS_SUCCESS);
        assert_eq!(shared.state.lock(|cell| cell.borrow().private_timeout), Duration::from_secs(3600));
    }

    #[test]
    fn a_full_event_queue_does_not_authorize_an_unsolicited_key_reply() {
        let shared = Shared::with_all_events();
        shared.set_connected(true);
        for _ in 0..4 {
            assert!(shared.try_push_event(Packet::completed_packets(1)));
        }
        assert!(!shared.request_ltk([0; 8], [0; 2]));
        assert_eq!(Hci::new(&shared).command_sync(0x201B, &[0, 0], &mut [0; 8]).0, STATUS_DISALLOWED);
    }

    #[test]
    fn disconnect_drops_data_and_pending_secrets_from_the_previous_link() {
        let shared = Shared::new();
        shared.set_connected(true);
        assert!(shared.push_acl_in(Packet::acl(Llid::Start, &[1, 2, 3])));
        assert!(shared.acl_out.try_send(AclOut { data: [0; ACL_MAX], epoch: 1, len: 1, llid: Llid::Start }).is_ok());
        shared.ltk.signal(Some([0xAA; 16]));
        shared.disconnect.signal(0x13);
        shared.set_connected(false);
        assert!(shared.acl_in.try_receive().is_err());
        assert!(shared.next_acl_out_if(true).is_none());
        assert!(shared.take_ltk().is_none());
        assert!(shared.take_disconnect().is_none());
    }
}
