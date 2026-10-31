//! Peripheral side of a connection: connection events, acknowledgement, link
//! encryption and the LL control procedures a central starts.

/// Async, single-use encryption response entropy.
mod entropy;

/// Control procedures beyond encryption.
mod procedures;

use crate::{
    channel::{Hopping, UsedChannels},
    clock::{Clock, reached},
    crypto::{self, CONFIG_LEN, SCRATCH_LEN},
    hci::{ConnectionParams, Packet, Shared},
    log::info,
    pdu::{BUFFER_LEN, ConnectInd, LLID_MASK, Llid, NESN, SN, field, valid_channel_map, valid_connection_parameters},
    power_control::{DEFAULT_LEVEL, LEVELS_DBM, PowerControl},
    radio::{Phy, Radio, Turnaround},
};
use core::future::pending;
use embassy_futures::select::{Either, select};
use entropy::Prefetch;

/// Largest payload of a queued PDU.
const CONTROL_PAYLOAD_MAX: usize = 27;
/// Data PDU header in RAM: header, length and the RFU byte the CCM needs.
const DATA_HEADER_LEN: usize = 3;
/// Size of a data PDU buffer with a MIC.
const DATA_BUFFER_LEN: usize = DATA_HEADER_LEN + CONTROL_PAYLOAD_MAX + MIC_LEN;
/// Error code: MIC failure.
const ERROR_MIC_FAILURE: u8 = 0x3D;
/// Error code: PIN or key missing.
const ERROR_KEY_MISSING: u8 = 0x06;
/// Error code: unsupported remote feature.
const ERROR_UNSUPPORTED_FEATURE: u8 = 0x1A;
/// Error code: invalid link layer parameters.
const ERROR_INVALID_PARAMETERS: u8 = 0x1E;
/// Error code: controller hardware failure.
const ERROR_HARDWARE_FAILURE: u8 = 0x03;
/// Error code: link layer response timeout.
const ERROR_RESPONSE_TIMEOUT: u8 = 0x22;
/// Status of a request that succeeded.
const STATUS_SUCCESS: u8 = 0x00;
/// Error code: PDU not allowed in the current procedure.
const ERROR_PDU_NOT_ALLOWED: u8 = 0x24;
/// Error code: instant passed.
const ERROR_INSTANT_PASSED: u8 = 0x28;
/// Error code: unsupported link layer parameter value.
const ERROR_UNSUPPORTED_VALUE: u8 = 0x20;
/// Error code: connection failed to be established, no packet from the
/// central within six connection events.
const ERROR_FAILED_TO_ESTABLISH: u8 = 0x3E;
/// Error: unacceptable connection parameters.
const ERROR_UNACCEPTABLE_PARAMETERS: u8 = 0x3B;
/// Time the host gets to answer a central's connection parameter request,
/// well within the central's procedure timeout.
const HOST_REPLY_US: u32 = 30_000_000;
/// Maximum time allowed for an encryption procedure.
const PROCEDURE_TIMEOUT_US: u32 = 40_000_000;
/// Supported link layer features.
///
/// LE encryption, the connection parameters request procedure, the extended
/// reject indication, the peripheral-initiated feature exchange and LE ping
/// (bits 0 to 4), the LE 2M PHY (bit 8), channel selection algorithm 2 (bit
/// 14) and LE power control (bits 33 and 34).
pub const FEATURES: [u8; 8] = [0x1F, 0x41, 0, 0, 0x06, 0, 0, 0];
/// Data length response payload: 27 octets and 328 us both ways.
const LENGTH: [u8; 8] = [27, 0, 0x48, 0x01, 27, 0, 0x48, 0x01];
/// Length of a message integrity check.
const MIC_LEN: usize = 4;
/// Connection parameter change at an instant.
const OP_CONNECTION_UPDATE_IND: u8 = 0x00;
/// Channel map change at an instant.
const OP_CHANNEL_MAP_IND: u8 = 0x01;
/// Connection termination.
const OP_TERMINATE_IND: u8 = 0x02;
/// Encryption request.
const OP_ENC_REQ: u8 = 0x03;
/// Encryption response.
const OP_ENC_RSP: u8 = 0x04;
/// Start of encryption request.
const OP_START_ENC_REQ: u8 = 0x05;
/// Start of encryption response.
const OP_START_ENC_RSP: u8 = 0x06;
/// Answer to an unsupported control PDU.
const OP_UNKNOWN_RSP: u8 = 0x07;
/// Feature exchange request from the central.
const OP_FEATURE_REQ: u8 = 0x08;
/// Feature exchange response.
const OP_FEATURE_RSP: u8 = 0x09;
/// Version exchange.
const OP_VERSION_IND: u8 = 0x0C;
/// Request to pause encryption for a key refresh.
const OP_PAUSE_ENC_REQ: u8 = 0x0A;
/// Answer to [`OP_PAUSE_ENC_REQ`], from both sides.
const OP_PAUSE_ENC_RSP: u8 = 0x0B;
/// Rejection of a procedure.
const OP_REJECT_IND: u8 = 0x0D;
/// Request to change the transmit power, with the sender's.
const OP_POWER_CONTROL_REQ: u8 = 0x23;
/// Answer to [`OP_POWER_CONTROL_REQ`].
const OP_POWER_CONTROL_RSP: u8 = 0x24;
/// Report of a change of the own transmit power.
const OP_POWER_CHANGE_IND: u8 = 0x25;
/// Feature exchange started by the peripheral.
const OP_PERIPHERAL_FEATURE_REQ: u8 = 0x0E;
/// Connection parameter request, from either side.
const OP_CONNECTION_PARAM_REQ: u8 = 0x0F;
/// Answer to [`OP_CONNECTION_PARAM_REQ`].
const OP_CONNECTION_PARAM_RSP: u8 = 0x10;
/// Rejection of a procedure, naming its opcode.
const OP_REJECT_EXT_IND: u8 = 0x11;
/// Ping request.
const OP_PING_REQ: u8 = 0x12;
/// Ping response.
const OP_PING_RSP: u8 = 0x13;
/// Data length request.
const OP_LENGTH_REQ: u8 = 0x14;
/// Data length response.
const OP_LENGTH_RSP: u8 = 0x15;
/// PHY preferences, starting the PHY update procedure.
const OP_PHY_REQ: u8 = 0x16;
/// PHY preferences answering [`OP_PHY_REQ`].
const OP_PHY_RSP: u8 = 0x17;
/// PHY change at an instant.
const OP_PHY_UPDATE_IND: u8 = 0x18;
/// PHYs this side prefers for both directions: LE 2M.
const PREFERRED_PHYS: u8 = 0x02;
/// Interval of the connection statistics log.
const REPORT_INTERVAL_US: u32 = 10_000_000;
/// Header bit: more data follows.
const MD: u8 = 0x10;
/// Our sleep clock accuracy in ppm: the calibrated RC oscillator.
const OWN_SCA_PPM: u32 = 500;
/// Queued PDUs.
const QUEUE_LEN: usize = 4;
/// Radio ramp-up time.
const RAMP_UP_US: u32 = crate::radio::RX_READY_US;
/// Extra listening before the earliest expected packet.
const RX_MARGIN_US: u32 = 30;
/// Extra listening after the latest expected access address.
const RX_TAIL_US: u32 = 30;
/// Microseconds per 10 ms unit.
const UNIT_10MS_US: u32 = 10_000;
/// Microseconds per 1.25 ms unit.
const UNIT_1250_US: u32 = 1250;
/// Version exchange payload: Bluetooth 5.2, the first with LE power
/// control, no company, subversion 0.
const VERSION: [u8; 5] = [0x0B, 0xFF, 0xFF, 0x00, 0x00];
/// Fixed part of the window widening in microseconds.
const WIDENING_FIXED_US: u32 = 16;
/// Interframe space.
const T_IFS_US: u32 = 150;
/// Time left before the next event for processing the packets of this one.
const EVENT_GUARD_US: u32 = 500;
/// Received packets with a payload held for processing after the event.
const RX_SLOTS: usize = 3;

/// Why a connection ended.
#[derive(Clone, Copy)]
#[non_exhaustive]
pub enum Ended {
    /// A controller error ended the link immediately.
    Error(u8),
    /// The host terminated the connection with this error code.
    Local(u8),
    /// The supervision timeout expired.
    Lost,
    /// The host reset the controller; no disconnection event is emitted.
    Reset,
    /// The central terminated the connection with this error code.
    Terminated(u8),
}

/// Counters of a connection.
#[derive(Clone, Copy, Default)]
#[non_exhaustive]
pub struct Stats {
    /// Packets received with a CRC error.
    pub crc_errors: u32,
    /// Connection events.
    pub events:     u32,
    /// Connection events without a packet from the central.
    pub missed:     u32,
    /// New data PDUs received.
    pub received:   u32,
    /// Connection events skipped with peripheral latency.
    pub skipped:    u32,
}

/// State of the encryption start procedure.
#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    /// A validated request waits for its prefetched, single-use random block.
    AwaitingEntropy {
        /// Central random number for the host's key lookup.
        rand: [u8; 8],
        /// Central encrypted diversifier for the host's key lookup.
        ediv: [u8; 2],
    },
    /// The host is asked for the long term key.
    AwaitingKey {
        /// Whether the key request event reached the host.
        requested: bool,
        /// Random number of the request.
        rand:      [u8; 8],
        /// Encrypted diversifier of the request.
        ediv:      [u8; 2],
    },
    /// Our encrypted pause response was sent; the central's plain one is
    /// expected.
    AwaitingPauseResponse,
    /// The start request was sent and the peer must authenticate its reply.
    AwaitingStartResponse,
    /// No procedure running.
    Idle,
    /// Encryption is paused both ways; the central starts it again with the
    /// new key.
    Paused,
    /// Our pause response is queued, still encrypted.
    Pausing,
    /// Encryption is being started.
    Starting,
}

/// A procedure this side starts once.
#[derive(Clone, Copy, Eq, PartialEq)]
enum Request {
    /// Asked, or answered or refused by the central: nothing more to do.
    Done,
    /// Not asked yet.
    NotStarted,
    /// Asked; the central answers until the deadline.
    Requested(u32),
}

/// Kind of encryption start.
#[derive(Clone, Copy, Eq, PartialEq)]
enum Procedure {
    /// The first start of the connection.
    First,
    /// A key refresh after a pause.
    Refresh,
}

/// Link encryption state.
struct Encryption {
    /// IV of the session.
    iv:         [u8; 8],
    /// State of the start procedure.
    phase:      Phase,
    /// Whether the start is the first or refreshes the key.
    procedure:  Procedure,
    /// CCM configuration for received packets.
    rx_config:  [u8; CONFIG_LEN],
    /// Packet counter of the next new received packet.
    rx_counter: u64,
    /// Whether received packets are encrypted.
    rx_on:      bool,
    /// CCM scratch area.
    scratch:    [u8; SCRATCH_LEN],
    /// Session key diversifier.
    skd:        [u8; 16],
    /// CCM configuration for sent packets.
    tx_config:  [u8; CONFIG_LEN],
    /// Packet counter of the next new sent packet.
    tx_counter: u64,
    /// Whether sent packets are encrypted.
    tx_on:      bool,
    /// Whether the PDU being sent is encrypted. Fixed when it is loaded, so
    /// retransmissions keep the packet counter it was given, or stay plain.
    tx_sealed:  bool,
}

impl Encryption {
    /// Forgets the keys, the IVs and the session key diversifier of the
    /// link.
    fn wipe(&mut self) {
        crypto::wipe(&mut self.iv);
        crypto::wipe(&mut self.rx_config);
        crypto::wipe(&mut self.scratch);
        crypto::wipe(&mut self.skd);
        crypto::wipe(&mut self.tx_config);
    }
}

/// Where the next packet from the central is expected.
#[derive(Clone, Copy)]
enum Expect {
    /// At the anchor `interval` after the last one.
    Anchor,
    /// Within a transmit window: start time of the first packet, and size.
    Window {
        /// Earliest packet start.
        start: u32,
        /// Window length.
        size:  u32,
    },
}

/// A central's connection parameter request waiting for an answer.
#[derive(Clone, Copy)]
struct RemoteRequest {
    /// Whether the host was asked, and until when it may answer.
    asked:  Option<u32>,
    /// The request's parameters, whose offsets the response repeats.
    params: [u8; 23],
}

/// A received PDU in plain text, waiting to be processed.
#[derive(Clone, Copy)]
struct Pending {
    /// Header and payload.
    bytes:     [u8; DATA_BUFFER_LEN],
    /// Whether it came encrypted.
    encrypted: bool,
}

/// A PDU waiting to be sent.
#[derive(Clone, Copy)]
struct Queued {
    /// Payload.
    data: [u8; CONTROL_PAYLOAD_MAX],
    /// Payload length.
    len:  u8,
    /// Logical link identifier.
    llid: Llid,
}

/// Kind of the PDU being sent.
#[derive(Clone, Copy, Eq, PartialEq)]
enum TxKind {
    /// ACL data from the host.
    Acl,
    /// LL control PDU.
    Control,
    /// Empty PDU.
    Empty,
    /// Termination requested by the host.
    Terminate,
}

/// Connection parameters taking effect at an instant.
#[derive(Clone, Copy)]
struct Update {
    /// Event counter at which they take effect.
    instant:    u16,
    /// New interval in microseconds.
    interval:   u32,
    /// New peripheral latency in events.
    latency:    u16,
    /// New parameters in link layer units.
    params:     ConnectionParams,
    /// Whether the update answers a request of the host, which then learns
    /// of it even without a change.
    requested:  bool,
    /// New supervision timeout in microseconds.
    timeout:    u32,
    /// Transmit window offset in microseconds.
    win_offset: u32,
    /// Transmit window size in microseconds.
    win_size:   u32,
}

/// An established connection.
pub struct Connection {
    /// Fatal controller error; no further packets may be sent.
    abort:                  Option<u8>,
    /// Access address time of the last received packet.
    anchor:                 u32,
    /// Event counter of [`Self::anchor`].
    anchor_counter:         u16,
    /// Transmit power level the central last learned.
    announced_power:        [usize; 2],
    /// The central's features, once known.
    central_features:       Option<[u8; 8]>,
    /// Channel map update and its instant.
    channel_update:         Option<(UsedChannels, u16)>,
    /// ACL packets acknowledged and not yet reported to the host.
    completed:              u16,
    /// Counter of the next connection event.
    counter:                u16,
    /// Largest deviation of a received anchor from its expected time since
    /// the last report, and the window widening it was received with, in
    /// microseconds.
    drift:                  (i32, u32),
    /// Link encryption.
    encryption:             Encryption,
    /// Security notification retained until the host event queue has room.
    encryption_change:      Option<(u8, bool)>,
    /// Deadline for accepting the first packet of a new connection.
    establishment_deadline: Option<u32>,
    /// Where the next packet is expected.
    expect:                 Expect,
    /// Rejected feature query awaiting host notification.
    feature_error:          Option<u8>,
    /// The feature exchange this side starts.
    features_request:       Request,
    /// Channel selection.
    hopping:                Hopping,
    /// PHY preferences requested by the host until completion.
    host_phy:               Option<[u8; 2]>,
    /// Host queries pending completion.
    host_queries:           u8,
    /// Connection interval in microseconds.
    interval:               u32,
    /// Time the last valid packet was received.
    last_valid:             u32,
    /// Peripheral latency in events.
    latency:                u16,
    /// Used data channels.
    map:                    UsedChannels,
    /// Next expected sequence number.
    nesn:                   bool,
    /// Transmit PHY to apply with the next PHY instant.
    next_tx_phy:            Phy,
    /// Ordered host notifications retained while its queue is full.
    notifications:          [Option<Packet>; 3],
    /// Deadline of the host's connection parameter request, while it runs.
    param_request:          Option<u32>,
    /// Status of the host's connection parameter request to report when it
    /// ended without an update: a failure, or success for parameters already
    /// in place.
    param_status:           Option<u8>,
    /// Pending connection parameter update.
    param_update:           Option<Update>,
    /// Time of the last packet with a valid MIC, once encrypted, and
    /// whether a ping asked for one since.
    payload_timer:          Option<(u32, bool)>,
    /// Received packets with a payload, in order, waiting for processing
    /// after the event.
    pending:                [Option<Pending>; RX_SLOTS],
    /// PHY both ways.
    phy:                    Phy,
    /// The PHY update this side asks for.
    phy_request:            Request,
    /// PHY procedure completion awaiting notification.
    phy_status:             Option<u8>,
    /// PHY change and its instant.
    phy_update:             Option<(Phy, u16)>,
    /// Response deadline of our `LL_PING_REQ` (Core, Vol 6, Part B, 5.2).
    ping_request:           Option<u32>,
    /// Transmit power control.
    power:                  [PowerControl; 2],
    /// PHY mask for which the peer has requested power control.
    power_reporting:        u8,
    /// PHY preference for this connection.
    preferred_phys:         [u8; 2],
    /// Deadline of the current encryption procedure, if any.
    procedure_deadline:     Option<u32>,
    /// PDUs waiting to be sent.
    queue:                  [Option<Queued>; QUEUE_LEN],
    /// Whether the received PDU is new and has to be processed.
    received:               bool,
    /// A central's connection parameter request waiting for an answer.
    remote_request:         Option<RemoteRequest>,
    /// Time of the next statistics log.
    report_at:              u32,
    /// Counters and crystal restarts at the last statistics log.
    reported:               (Stats, u32),
    /// Decrypted received PDU.
    rx_plain:               [u8; BUFFER_LEN],
    /// Sum of both sleep clock accuracies in ppm.
    sca_ppm:                u32,
    /// Events skipped in a row.
    skipped:                u16,
    /// Sequence number of the PDU in [`Self::tx`].
    sn:                     bool,
    /// Counters.
    stats:                  Stats,
    /// Termination requested by the host, and whether it was acknowledged.
    terminate:              Option<(u8, bool)>,
    /// Local termination cannot be prolonged by incoming keepalive packets.
    terminate_deadline:     Option<u32>,
    /// Termination received from the central.
    terminated:             Option<u8>,
    /// Supervision timeout in microseconds.
    timeout:                u32,
    /// PDU being sent until acknowledged, unencrypted.
    tx:                     [u8; DATA_BUFFER_LEN],
    /// Kind of [`Self::tx`].
    tx_kind:                TxKind,
    /// Transmit PHY, independent of the receive PHY.
    tx_phy:                 Phy,
    /// Encrypted copy of [`Self::tx`] as sent.
    tx_sealed:              [u8; DATA_BUFFER_LEN],
    /// Remote version, retained once our only version response is queued.
    version:                Option<[u8; 5]>,
    /// Version procedure state, including its response deadline.
    version_request:        Request,
}

impl Connection {
    /// Processes NESN independently of whether the peer retransmitted its
    /// payload. CRC validation is done by the caller; new encrypted data also
    /// needs its MIC.
    fn acknowledge(&mut self, header: u8, shared: &Shared) -> Option<()> {
        if (header & NESN != 0) == self.sn {
            // The central did not hear our last packet. Its first packet of
            // the connection acknowledges nothing yet.
            if self.stats.received != 0 {
                for_phy_mut(&mut self.power, self.tx_phy).on_loss();
            }
        } else {
            self.sn = !self.sn;
            match self.tx_kind {
                TxKind::Acl => self.completed = self.completed.saturating_add(1),
                TxKind::Terminate => {
                    if let Some((reason, false)) = self.terminate {
                        self.terminate = Some((reason, true));
                    }
                },
                TxKind::Control | TxKind::Empty => {},
            }
            self.load_next(shared);
            if self.abort.is_some() {
                return None;
            }
        }
        Some(())
    }

    /// Applies parameter and channel map updates due at the current event.
    #[inline(never)]
    fn apply_instants(&mut self, shared: &Shared) {
        if let Some((map, instant)) = self.channel_update
            && instant == self.counter
        {
            self.map = map;
            self.channel_update = None;
            info!("channel map updated");
        }
        if let Some((phy, instant)) = self.phy_update
            && instant == self.counter
        {
            self.phy = phy;
            self.tx_phy = self.next_tx_phy;
            shared.set_phys(self.phy.hci(), self.tx_phy.hci());
            self.host_phy = None;
            shared.complete_query(4);
            self.phy_update = None;
            self.notify(Packet::phy_update_complete_pair(phy.hci(), self.tx_phy.hci()), shared);
            info!("PHY now {}M", phy.hci());
        }
        if let Some(update) = self.param_update
            && update.instant == self.counter
        {
            let old_anchor = self.expected_anchor();
            self.expect = Expect::Window {
                start: old_anchor.wrapping_sub(self.phy.address_offset_us()).wrapping_add(update.win_offset),
                size:  update.win_size,
            };
            let changed =
                self.interval != update.interval || self.latency != update.latency || self.timeout != update.timeout;
            self.interval = update.interval;
            self.latency = update.latency;
            self.timeout = update.timeout;
            self.param_update = None;
            // The host learns of updates that change something or that it
            // asked for (Core, Vol 6, Part B, 5.1.1).
            if changed || update.requested {
                self.notify(Packet::connection_update_complete(STATUS_SUCCESS, update.params), shared);
            }
            if update.requested {
                shared.finish_param_request();
            }
            info!("connection interval now {} us", update.interval);
        }
    }

    /// Prepares the decryption of the next received packet, if the link is
    /// encrypted. Returns false and ends the link if the counter ran out.
    fn arm_decryption(&mut self, rx: &mut [u8; BUFFER_LEN]) -> bool {
        if !self.encryption.rx_on {
            return true;
        }
        if !crypto::set_counter(&mut self.encryption.rx_config, self.encryption.rx_counter) {
            self.abort = Some(ERROR_MIC_FAILURE);
            return false;
        }
        let pointers = (rx.as_mut_ptr(), self.rx_plain.as_mut_ptr());
        let scratch = &mut self.encryption.scratch;
        // SAFETY: the configuration, scratch and both buffers live in this
        // connection or are borrowed for the exchange, which ends the
        // decryption with `wait_decrypted`, `stop` or `disarm`.
        let () = unsafe { crypto::arm_decrypt(&self.encryption.rx_config, pointers, scratch, self.phy) };
        true
    }

    /// Whether the current event can pass without listening: nothing to send
    /// or acknowledge and no procedure running. As in Zephyr, latency also
    /// stops while a connection or PHY update waits for its instant, so the
    /// anchor is fresh when the timing or the PHY changes.
    fn can_skip(&self, shared: &Shared) -> bool {
        matches!(self.expect, Expect::Anchor)
            && self.param_update.is_none()
            && self.phy_update.is_none()
            && self.tx_kind == TxKind::Empty
            && self.queue.iter().all(Option::is_none)
            && self.terminate.is_none()
            && self.encryption.phase == Phase::Idle
            && self.encryption_change.is_none()
            && self.notifications.iter().all(Option::is_none)
            && !shared.has_acl_out()
    }

    /// Latest time an event that began at `anchor` may still exchange
    /// packets: the next event's receive window opens no earlier than one
    /// interval later, less its widening and setup.
    fn close_by(&self, anchor: u32) -> u32 {
        anchor
            .wrapping_add(self.interval)
            .wrapping_sub(self.widening(self.interval))
            .wrapping_sub(self.phy.address_offset_us())
            .wrapping_sub(RAMP_UP_US)
            .wrapping_sub(RX_MARGIN_US)
            .wrapping_sub(EVENT_GUARD_US)
    }

    /// Advances the encryption start procedure with the host's answer.
    #[inline(never)]
    fn drive_encryption(&mut self, shared: &Shared, entropy: &Prefetch) {
        if let Phase::AwaitingEntropy { rand, ediv } = self.encryption.phase {
            let Some(material) = entropy.take() else { return };
            self.finish_encryption_request(rand, ediv, &material);
        }
        let Phase::AwaitingKey { requested, rand, ediv } = self.encryption.phase else { return };
        if !requested {
            if shared.request_ltk(rand, ediv) {
                self.encryption.phase = Phase::AwaitingKey { requested: true, rand, ediv };
            }
            return;
        }
        match shared.take_ltk() {
            Some(Some(mut ltk)) => {
                let session = crypto::session_key(ltk, self.encryption.skd);
                crypto::wipe(&mut ltk);
                let Some(mut key) = session else {
                    self.abort = Some(ERROR_HARDWARE_FAILURE);
                    return;
                };
                self.encryption.rx_config = crypto::config(key, self.encryption.iv, true);
                self.encryption.tx_config = crypto::config(key, self.encryption.iv, false);
                crypto::wipe(&mut key);
                self.encryption.rx_counter = 0;
                self.encryption.tx_counter = 0;
                crypto::enable();
                self.enqueue(Llid::Control, &[OP_START_ENC_REQ]);
                self.encryption.phase = Phase::Starting;
            },
            Some(None) if self.encryption.procedure == Procedure::Refresh => {
                // The link stays paused without a key: end it.
                self.abort = Some(ERROR_KEY_MISSING);
            },
            Some(None) => {
                self.enqueue(Llid::Control, &[OP_REJECT_IND, ERROR_KEY_MISSING]);
                self.encryption.phase = Phase::Idle;
                self.procedure_deadline = None;
                self.encryption_change = Some((ERROR_KEY_MISSING, false));
            },
            None => {},
        }
    }

    /// Services host traffic before the next radio event.
    fn drive_host(&mut self, now: u32, shared: &Shared, entropy: &Prefetch) {
        self.drive_encryption(shared, entropy);
        self.drive_remote_request(now, shared);
        self.service_queries(now, shared);
        self.start_procedures(now, shared);
    }

    /// Determines timeouts without allowing received traffic to postpone a
    /// pending local disconnect or the initial connection establishment.
    fn ended(&self, now: u32) -> Option<Ended> {
        if let Some(reason) = self.abort {
            return Some(Ended::Error(reason));
        }
        if self.procedure_deadline.is_some_and(|deadline| reached(now, deadline)) {
            return Some(Ended::Error(ERROR_RESPONSE_TIMEOUT));
        }
        if let Some((reason, acknowledged)) = self.terminate
            && (acknowledged || self.terminate_deadline.is_some_and(|deadline| reached(now, deadline)))
        {
            return Some(Ended::Local(reason));
        }
        if let Some(reason) = self.terminated {
            return Some(Ended::Terminated(reason));
        }
        if self.establishment_deadline.is_some_and(|deadline| reached(now, deadline)) {
            return Some(Ended::Error(ERROR_FAILED_TO_ESTABLISH));
        }
        if reached(now, self.last_valid.wrapping_add(self.timeout)) {
            return Some(Ended::Lost);
        }
        None
    }

    /// Queues a control PDU.
    fn enqueue(&mut self, llid: Llid, payload: &[u8]) {
        let mut data = [0_u8; CONTROL_PAYLOAD_MAX];
        let len = payload.len().min(CONTROL_PAYLOAD_MAX);
        if let (Some(target), Some(source)) = (data.get_mut(..len), payload.get(..len)) {
            target.copy_from_slice(source);
        }
        if let Some(slot) = self.queue.iter_mut().find(|slot| slot.is_none()) {
            *slot = Some(Queued { data, len: u8::try_from(len).unwrap_or_default(), llid });
        } else {
            // Losing a control response would strand the peer in a procedure.
            self.abort = Some(ERROR_RESPONSE_TIMEOUT);
        }
    }

    /// Runs the connection event: receives the central's packets and
    /// answers each, for as long as either side has more data and another
    /// exchange fits before the next event (Core, Vol 6, Part B, 4.5.6).
    /// Returns the access address time of the first packet, which sets the
    /// anchor even for a packet with a CRC error or a retransmission (Core,
    /// Vol 6, Part B, 4.5.5).
    fn exchange(
        &mut self,
        radio: &mut Radio<'_>,
        clock: &mut Clock<'_>,
        rx: &mut [u8; BUFFER_LEN],
        (enable, deadline): (u32, u32),
        shared: &Shared,
    ) -> Option<u32> {
        let asymmetric = self.phy != self.tx_phy;
        // SAFETY: `rx` is a full packet buffer borrowed for this whole
        // exchange, which disables the radio on every path out.
        let () =
            unsafe { radio.prepare(rx.as_mut_ptr(), if asymmetric { Turnaround::None } else { Turnaround::Transmit }) };
        if !self.arm_decryption(rx) {
            return None;
        }
        if !clock.receive_at(enable) {
            clock.cancel_start();
            radio.disable();
            crypto::disarm();
            return None;
        }
        clock.wait_started();
        if !Self::wait_address(radio, clock, deadline) {
            radio.disable();
            crypto::disarm();
            return None;
        }
        let anchor = clock.address_time();
        let close_by = self.close_by(anchor);
        loop {
            radio.wait_end();
            let fits = !asymmetric && reached(close_by, clock.now().wrapping_add(self.exchange_us()));
            let Some(more) = self.respond(radio, rx, clock.address_time(), fits, shared) else {
                radio.disable();
                crypto::disarm();
                return None;
            };
            if asymmetric {
                // The other PHY is set while the radio is disabled, and the
                // answer started from TIMER0 in its place.
                radio.wait_disabled();
                radio.set_phy(self.tx_phy);
                if !clock.transmit_at(clock.end_time().wrapping_add(self.tx_phy.response_offset_us(self.phy))) {
                    crypto::disarm();
                    self.abort = Some(ERROR_HARDWARE_FAILURE);
                    return None;
                }
            } else {
                // The switch started the answer; the next turnaround follows
                // its end.
                radio.wait_switched();
                radio.set_turnaround(if more { Turnaround::Receive } else { Turnaround::None });
            }
            radio.wait_end();
            clock.cancel_start();
            if !more {
                break;
            }
            // The switch starts receiving one interframe space after the
            // end; the buffer and the decryption are ready before.
            // SAFETY: as for `prepare` above.
            let () = unsafe { radio.rearm_receive(rx.as_mut_ptr()) };
            if !self.arm_decryption(rx) {
                radio.disable();
                crypto::disarm();
                return Some(anchor);
            }
            radio.wait_switched();
            radio.set_turnaround(Turnaround::Transmit);
            let listen_until = clock
                .end_time()
                .wrapping_add(T_IFS_US)
                .wrapping_add(self.phy.address_offset_us())
                .wrapping_add(RX_TAIL_US);
            if !Self::wait_address(radio, clock, listen_until) {
                radio.disable();
                crypto::disarm();
                return Some(anchor);
            }
        }
        radio.wait_disabled();
        crypto::disarm();
        Some(anchor)
    }

    /// Air time of a full exchange after the current packet: our answer, and
    /// one more packet each way, at their longest.
    fn exchange_us(&self) -> u32 {
        let packet = |phy: Phy| {
            // Header, the longest payload with its MIC, and the CRC.
            let bytes = u32::try_from(DATA_BUFFER_LEN).unwrap_or(u32::MAX).saturating_add(3);
            phy.address_offset_us().saturating_add(bytes.saturating_mul(8).checked_div(phy.hci().into()).unwrap_or(0))
        };
        packet(self.tx_phy)
            .saturating_mul(2)
            .saturating_add(packet(self.phy))
            .saturating_add(T_IFS_US.saturating_mul(3))
    }

    /// Updates the encryption phases and the anchor after an exchange whose
    /// access address arrived at `address`.
    fn exchanged(&mut self, address: u32) {
        if self.encryption.phase == Phase::Starting
            && self.tx_kind == TxKind::Control
            && self.tx.get(DATA_HEADER_LEN) == Some(&OP_START_ENC_REQ)
        {
            self.encryption.rx_on = true;
            self.encryption.phase = Phase::AwaitingStartResponse;
        }
        // After our encrypted pause response the central answers in
        // plain text.
        if self.encryption.phase == Phase::Pausing
            && self.tx_kind == TxKind::Control
            && self.tx.get(DATA_HEADER_LEN) == Some(&OP_PAUSE_ENC_RSP)
        {
            self.encryption.rx_on = false;
            self.encryption.phase = Phase::AwaitingPauseResponse;
        }
        if matches!(self.expect, Expect::Anchor) {
            let expected = self.expected_anchor();
            let drift = address.wrapping_sub(expected).cast_signed();
            if drift.unsigned_abs() >= self.drift.0.unsigned_abs() {
                self.drift = (drift, self.widening(expected.wrapping_sub(self.anchor)));
            }
        }
        self.anchor = address;
        self.anchor_counter = self.counter;
        self.expect = Expect::Anchor;
    }

    /// Access address time expected at the current event from the last
    /// anchor.
    fn expected_anchor(&self) -> u32 {
        let events = u32::from(self.counter.wrapping_sub(self.anchor_counter));
        self.anchor.wrapping_add(self.interval.wrapping_mul(events))
    }

    /// Consumes one complete prefetched block; no hardware RNG work runs here.
    fn finish_encryption_request(&mut self, rand: [u8; 8], ediv: [u8; 2], material: &entropy::Material) {
        let mut response = [0_u8; 13];
        if let Some(code) = response.first_mut() {
            *code = OP_ENC_RSP;
        }
        if let Some(own) = response.get_mut(1..) {
            own.copy_from_slice(material.bytes());
        }
        let (own_skd, own_iv) = material.bytes().split_at(8);
        if let Some(target) = self.encryption.skd.get_mut(8..) {
            target.copy_from_slice(own_skd);
        }
        if let Some(target) = self.encryption.iv.get_mut(4..) {
            target.copy_from_slice(own_iv);
        }
        self.enqueue(Llid::Control, &response);
        self.encryption.phase = Phase::AwaitingKey { requested: false, rand, ediv };
    }

    /// Drains retained notifications before the final disconnection event.
    pub(crate) async fn flush_after_disconnect(&mut self, shared: &Shared) -> bool {
        for slot in &mut self.notifications {
            if let Some(event) = slot.take()
                && matches!(
                    embassy_futures::select::select(shared.push_event(event), shared.reset_requested()).await,
                    embassy_futures::select::Either::Second(())
                )
            {
                return false;
            }
        }
        true
    }

    /// Flushes retained events in order as host capacity becomes available.
    fn flush_notifications(&mut self, shared: &Shared) {
        while let Some(event) = self.notifications.first().copied().flatten() {
            if !shared.try_push_event(event) {
                break;
            }
            self.notifications.rotate_left(1);
            if let Some(last) = self.notifications.last_mut() {
                *last = None;
            }
        }
    }

    /// Answers a control PDU from the central.
    #[expect(clippy::rest_pattern_accessible_field, reason = "the phase is matched by variant only")]
    fn handle_control(&mut self, payload: &[u8], encrypted: bool) {
        let Some((&code, params)) = payload.split_first() else { return };
        // While encryption starts or pauses, the central may only take the
        // procedure on or end the link (Core, Vol 6, Part B, 5.1.3). Any
        // other answer would be queued in front of the next step.
        let (allowed, can_answer) = match self.encryption.phase {
            Phase::AwaitingEntropy { .. } => (code == OP_TERMINATE_IND, false),
            Phase::Starting | Phase::AwaitingStartResponse => {
                (matches!(code, OP_START_ENC_RSP | OP_TERMINATE_IND), false)
            },
            Phase::Pausing | Phase::AwaitingPauseResponse => {
                (matches!(code, OP_PAUSE_ENC_RSP | OP_TERMINATE_IND), false)
            },
            Phase::Paused => (matches!(code, OP_ENC_REQ | OP_TERMINATE_IND), false),
            Phase::AwaitingKey { .. } | Phase::Idle => (true, true),
        };
        if !allowed {
            self.abort = Some(ERROR_PDU_NOT_ALLOWED);
            return;
        }
        if control_len(code).is_some_and(|len| params.len() != len) {
            // A PDU of the wrong length counts as one this side does not
            // know, as in other controllers, unless an answer would get
            // in the way of a running encryption procedure.
            if can_answer {
                self.enqueue(Llid::Control, &[OP_UNKNOWN_RSP, code]);
            } else {
                self.abort = Some(ERROR_INVALID_PARAMETERS);
            }
            return;
        }
        match code {
            OP_CONNECTION_UPDATE_IND | OP_CONNECTION_PARAM_REQ | OP_CONNECTION_PARAM_RSP => {
                self.handle_parameters(code, params);
            },
            OP_CHANNEL_MAP_IND => {
                if let Some([map0, map1, map2, map3, map4, instant0, instant1]) = field::<7>(params, 0) {
                    let map = [map0, map1, map2, map3, map4];
                    let instant = u16::from_le_bytes([instant0, instant1]);
                    if !valid_channel_map(map) {
                        self.abort = Some(ERROR_INVALID_PARAMETERS);
                    } else if !future_instant(self.counter, instant) {
                        self.abort = Some(ERROR_INSTANT_PASSED);
                    } else if self.channel_update.is_some() || self.param_update.is_some() || self.phy_update.is_some()
                    {
                        self.abort = Some(ERROR_PDU_NOT_ALLOWED);
                    } else {
                        self.channel_update = Some((UsedChannels::new(map), instant));
                    }
                }
            },
            OP_TERMINATE_IND => self.terminated = Some(params.first().copied().unwrap_or_default()),
            OP_ENC_REQ | OP_START_ENC_RSP | OP_PAUSE_ENC_REQ | OP_PAUSE_ENC_RSP => {
                self.handle_encryption(code, params, encrypted);
            },
            OP_PHY_REQ | OP_PHY_UPDATE_IND => self.handle_phy(code, params),
            OP_POWER_CONTROL_REQ => self.handle_power(params),
            OP_UNKNOWN_RSP | OP_REJECT_EXT_IND | OP_REJECT_IND => self.handle_rejection(code, params),
            OP_FEATURE_REQ | OP_FEATURE_RSP => self.handle_features(code, params),
            OP_VERSION_IND if self.version.is_none() => {
                let mut response = [OP_VERSION_IND, 0, 0, 0, 0, 0];
                if let Some(target) = response.get_mut(1..) {
                    target.copy_from_slice(&VERSION);
                }
                if !matches!(self.version_request, Request::Requested(_)) {
                    self.enqueue(Llid::Control, &response);
                }
                self.version_request = Request::Done;
                self.version = params.first_chunk::<5>().copied();
            },
            OP_LENGTH_REQ => {
                let mut response = [OP_LENGTH_RSP, 0, 0, 0, 0, 0, 0, 0, 0];
                if let Some(target) = response.get_mut(1..) {
                    target.copy_from_slice(&LENGTH);
                }
                self.enqueue(Llid::Control, &response);
            },
            OP_PING_REQ => self.enqueue(Llid::Control, &[OP_PING_RSP]),
            OP_PING_RSP => self.ping_request = None,
            OP_VERSION_IND | OP_LENGTH_RSP | OP_PHY_RSP | OP_POWER_CONTROL_RSP | OP_POWER_CHANGE_IND => {},
            _ => self.enqueue(Llid::Control, &[OP_UNKNOWN_RSP, code]),
        }
        info!("control {=u8:#04x}", code);
    }

    /// Answers a control PDU of the encryption start and pause procedures.
    fn handle_encryption(&mut self, code: u8, params: &[u8], encrypted: bool) {
        match code {
            OP_ENC_REQ => {
                let refresh = self.encryption.phase == Phase::Paused;
                let fresh = self.encryption.phase == Phase::Idle && !self.encryption.rx_on && !self.encryption.tx_on;
                if !refresh && !fresh {
                    self.abort = Some(ERROR_PDU_NOT_ALLOWED);
                    return;
                }
                self.encryption.procedure = if refresh { Procedure::Refresh } else { Procedure::First };
                self.procedure_deadline = Some(self.last_valid.wrapping_add(PROCEDURE_TIMEOUT_US));
                self.start_encryption(params);
            },
            OP_START_ENC_RSP => {
                if !encrypted || self.encryption.phase != Phase::AwaitingStartResponse || !self.encryption.rx_on {
                    self.abort = Some(ERROR_PDU_NOT_ALLOWED);
                    return;
                }
                self.encryption.tx_on = true;
                self.encryption.phase = Phase::Idle;
                self.procedure_deadline = None;
                self.payload_timer = Some((self.last_valid, false));
                self.enqueue(Llid::Control, &[OP_START_ENC_RSP]);
                self.encryption_change = Some((0, true));
                info!("link encrypted");
            },
            OP_PAUSE_ENC_REQ => {
                let on = self.encryption.rx_on && self.encryption.tx_on;
                if !encrypted || !on || self.encryption.phase != Phase::Idle {
                    self.abort = Some(ERROR_PDU_NOT_ALLOWED);
                    return;
                }
                self.procedure_deadline = Some(self.last_valid.wrapping_add(PROCEDURE_TIMEOUT_US));
                self.enqueue(Llid::Control, &[OP_PAUSE_ENC_RSP]);
                self.encryption.phase = Phase::Pausing;
            },
            OP_PAUSE_ENC_RSP => {
                if encrypted || self.encryption.phase != Phase::AwaitingPauseResponse {
                    self.abort = Some(ERROR_PDU_NOT_ALLOWED);
                    return;
                }
                self.encryption.tx_on = false;
                // Only an empty PDU can wait here, with nothing to seal.
                if self.tx_kind == TxKind::Empty {
                    self.encryption.tx_sealed = false;
                }
                self.encryption.phase = Phase::Paused;
                info!("encryption paused for a key refresh");
            },
            _ => {},
        }
    }

    /// Loads the next queued control PDU, ACL data from the host or an empty
    /// PDU into [`Self::tx`]. ACL data waits while encryption starts.
    fn load_next(&mut self, shared: &Shared) {
        let queued = self.queue.first_mut().and_then(Option::take);
        self.queue.rotate_left(1);
        let take_acl = queued.is_none() && self.encryption.phase == Phase::Idle;
        let (kind, llid, data, len) = match (queued, shared.next_acl_out_if(take_acl)) {
            (Some(control), _) => {
                let kind =
                    if control.data.first() == Some(&OP_TERMINATE_IND) { TxKind::Terminate } else { TxKind::Control };
                (kind, control.llid, control.data, control.len)
            },
            (None, Some(acl)) => (TxKind::Acl, acl.llid, acl.data, acl.len),
            (None, None) => (TxKind::Empty, Llid::Continuation, [0; CONTROL_PAYLOAD_MAX], 0),
        };
        if let (Some(target), Some(source)) = (
            self.tx.get_mut(DATA_HEADER_LEN..DATA_HEADER_LEN.saturating_add(usize::from(len))),
            data.get(..usize::from(len)),
        ) {
            target.copy_from_slice(source);
        }
        if let Some(header) = self.tx.first_chunk_mut::<DATA_HEADER_LEN>() {
            *header = [llid.bits(), len, 0];
        }
        if self.encryption.tx_on && len != 0 {
            if !crypto::set_counter(&mut self.encryption.tx_config, self.encryption.tx_counter) {
                self.abort = Some(ERROR_MIC_FAILURE);
                return;
            }
            self.encryption.tx_counter = self.encryption.tx_counter.saturating_add(1);
        }
        self.encryption.tx_sealed = self.encryption.tx_on;
        self.tx_kind = kind;
    }

    /// Starts a connection from a request whose packet ended at `end`.
    #[inline]
    #[must_use = "the connection does nothing until run"]
    pub fn new(request: &ConnectInd, end: u32) -> Self {
        let interval = u32::from(request.interval).saturating_mul(UNIT_1250_US);
        let start =
            end.wrapping_add(UNIT_1250_US).wrapping_add(u32::from(request.win_offset).saturating_mul(UNIT_1250_US));
        Self {
            abort: None,
            notifications: [None; 3],
            anchor: end,
            anchor_counter: 0,
            announced_power: [DEFAULT_LEVEL; 2],
            central_features: None,
            channel_update: None,
            completed: 0,
            counter: 0,
            drift: (0_i32, 0_u32),
            hopping: if request.csa2 { Hopping::csa2(request.access_address) } else { Hopping::new(request.hop) },
            encryption: Encryption {
                iv:         [0; 8],
                phase:      Phase::Idle,
                procedure:  Procedure::First,
                rx_config:  [0; CONFIG_LEN],
                rx_counter: 0,
                rx_on:      false,
                scratch:    [0; SCRATCH_LEN],
                skd:        [0; 16],
                tx_config:  [0; CONFIG_LEN],
                tx_counter: 0,
                tx_on:      false,
                tx_sealed:  false,
            },
            encryption_change: None,
            establishment_deadline: Some(start.wrapping_add(interval.saturating_mul(6))),
            features_request: Request::NotStarted,
            expect: Expect::Window { start, size: u32::from(request.win_size).saturating_mul(UNIT_1250_US) },
            interval,
            last_valid: end,
            latency: request.latency,
            map: UsedChannels::new(request.channel_map),
            nesn: false,
            param_request: None,
            param_status: None,
            param_update: None,
            payload_timer: None,
            ping_request: None,
            phy: Phy::M1,
            tx_phy: Phy::M1,
            next_tx_phy: Phy::M1,
            phy_request: Request::NotStarted,
            phy_update: None,
            power: [PowerControl::new(); 2],
            power_reporting: 0,
            procedure_deadline: None,
            report_at: end.wrapping_add(REPORT_INTERVAL_US),
            reported: (Stats::default(), 0),
            queue: [None; QUEUE_LEN],
            pending: [None; RX_SLOTS],
            remote_request: None,
            received: false,
            rx_plain: [0; BUFFER_LEN],
            sca_ppm: request.sca_ppm.saturating_add(OWN_SCA_PPM),
            skipped: 0,
            sn: false,
            stats: Stats::default(),
            terminate: None,
            terminate_deadline: None,
            terminated: None,
            timeout: u32::from(request.timeout).saturating_mul(UNIT_10MS_US),
            tx: [0; DATA_BUFFER_LEN],
            tx_kind: TxKind::Empty,
            tx_sealed: [0; DATA_BUFFER_LEN],
            version: None,
            version_request: Request::NotStarted,
            host_queries: 0,
            feature_error: None,
            host_phy: None,
            phy_status: None,
            preferred_phys: [PREFERRED_PHYS; 2],
        }
    }

    /// Counts a missed event and moves an expected transmit window to the
    /// next event.
    fn note_miss(&mut self, channel: u8, window: (u32, u32)) {
        self.stats.missed = self.stats.missed.wrapping_add(1);
        // Tells timing from the radio: how long since the last packet, how
        // long the radio listened, and whether a transmit window after a
        // parameter update was expected.
        info!(
            "missed event {}: channel {}, {} events and {} us after the last packet, listened {} us, window {}, 2M {}",
            self.counter,
            channel,
            self.counter.wrapping_sub(self.anchor_counter),
            window.1.wrapping_sub(self.anchor),
            window.1.wrapping_sub(window.0),
            !matches!(self.expect, Expect::Anchor),
            self.phy == Phy::M2
        );
        if let Expect::Window { start, size } = self.expect {
            self.expect = Expect::Window { start: start.wrapping_add(self.interval), size };
        }
    }

    /// Retains a host notification without blocking radio progress.
    pub(crate) fn notify(&mut self, event: Packet, shared: &Shared) {
        if self.notifications.iter().all(Option::is_none) && shared.try_push_event(event) {
            return;
        }
        if let Some(slot) = self.notifications.iter_mut().find(|slot| slot.is_none()) {
            *slot = Some(event);
        } else {
            self.abort = Some(ERROR_HARDWARE_FAILURE);
        }
    }

    /// Passes the packets received in the event on, in order, and reports
    /// acknowledged ACL data.
    #[inline(never)]
    fn process(&mut self, rx: &[u8; BUFFER_LEN], encrypted: bool, shared: &Shared) {
        self.flush_notifications(shared);
        if self.received {
            self.stash(rx, encrypted);
        }
        while let Some(mut packet) = self.pending.first_mut().and_then(Option::take) {
            self.pending.rotate_left(1);
            let [header, length, ..] = packet.bytes;
            let len = usize::from(length);
            match packet.bytes.get(DATA_HEADER_LEN..DATA_HEADER_LEN.saturating_add(len)) {
                Some(payload) if header & LLID_MASK == Llid::Control.bits() => {
                    self.handle_control(payload, packet.encrypted);
                },
                Some(payload) if len != 0 => {
                    let kind = if header & LLID_MASK == Llid::Start.bits() { Llid::Start } else { Llid::Continuation };
                    _ = shared.push_acl_in(Packet::acl(kind, payload));
                },
                Some(_) | None => {},
            }
            crypto::wipe(&mut packet.bytes);
        }
        if let Some((status, enabled)) = self.encryption_change {
            let event = if self.encryption.procedure == Procedure::Refresh {
                Packet::key_refresh_complete(status)
            } else {
                Packet::encryption_change(status, enabled)
            };
            if shared.try_push_event(event) {
                self.encryption_change = None;
                self.encryption.procedure = Procedure::First;
            }
        }
        self.report_parameters(shared);
        if self.completed != 0 && shared.try_push_event(Packet::completed_packets(self.completed)) {
            self.completed = 0;
        }
    }

    /// Validates new data before delivery. Duplicate payloads use the previous
    /// CCM counter and must not be delivered or consume another nonce. Their
    /// NESN still acknowledges TX, as in the Core receive sequence and Zephyr.
    fn receive(&mut self, header: u8, len: u8, mic_ok: bool, address: u32, shared: &Shared) -> Option<bool> {
        let llid = header & LLID_MASK;
        let maximum = CONTROL_PAYLOAD_MAX.saturating_add(if self.encryption.rx_on { MIC_LEN } else { 0 });
        if llid == 0 || usize::from(len) > maximum || (len == 0 && llid != Llid::Continuation.bits()) {
            self.abort = Some(ERROR_INVALID_PARAMETERS);
            return None;
        }
        let duplicate = (header & SN != 0) != self.nesn;
        if duplicate && self.encryption.rx_on {
            self.last_valid = address;
            self.acknowledge(header, shared)?;
            return Some(false);
        }
        if self.encryption.rx_on && len != 0 && (usize::from(len) <= MIC_LEN || !mic_ok) {
            self.abort = Some(ERROR_MIC_FAILURE);
            return None;
        }
        // Once the central asked to start or pause encryption, it sends no
        // data until encryption runs again (Core, Vol 6, Part B, 5.1.3). Data
        // now could be plain text injected into a link the host trusts as
        // encrypted: end the link before acknowledging it.
        if llid != Llid::Control.bits() && len != 0 && self.encryption.phase != Phase::Idle {
            self.abort = Some(ERROR_MIC_FAILURE);
            return None;
        }
        if self.encryption.rx_on && len != 0 && self.payload_timer.is_some() {
            self.payload_timer = Some((address, false));
        }
        self.last_valid = address;
        self.establishment_deadline = None;
        self.acknowledge(header, shared)?;
        // A payload waits for processing after the event; data also needs
        // room towards the host for itself and every packet before it.
        let pending = self.pending.iter().flatten().count();
        let data = header & LLID_MASK != Llid::Control.bits();
        let room = len == 0 || (pending < RX_SLOTS && (!data || shared.acl_room() > pending));
        if !duplicate && room {
            self.nesn = !self.nesn;
            self.received = true;
        }
        Some(!duplicate)
    }

    /// Logs the counters since the last call.
    fn report(&mut self, (late, lead): (u32, u32)) {
        let (last, last_late) = self.reported;
        info!(
            "10 s: {} events, {} skipped, {} missed, {} crc errors, {} packets, {} late crystal (lead {} us), {} dBm, drift {} of +-{} us",
            self.stats.events.wrapping_sub(last.events),
            self.stats.skipped.wrapping_sub(last.skipped),
            self.stats.missed.wrapping_sub(last.missed),
            self.stats.crc_errors.wrapping_sub(last.crc_errors),
            self.stats.received.wrapping_sub(last.received),
            late.wrapping_sub(last_late),
            lead,
            tx_power(for_phy_mut(&mut self.power, self.tx_phy).level()),
            self.drift.0,
            self.drift.1
        );
        self.drift = (0_i32, 0_u32);
        self.reported = (self.stats, late);
        self.report_at = self.report_at.wrapping_add(REPORT_INTERVAL_US);
    }

    /// Acknowledges the received packet, keeps a new one for processing
    /// after the event, and selects and seals the answer. Runs within the
    /// interframe space. A packet with a CRC error is answered too, with the
    /// unacknowledged packet again (Core, Vol 6, Part B, 4.5.6). Returns
    /// `None` if no answer may be sent, and otherwise whether the event goes
    /// on after the answer: when either side has more data and `fits`, the
    /// next exchange fits before the next event. A CRC error, a control PDU,
    /// a packet without room, or a running encryption or termination
    /// procedure closes it.
    fn respond(
        &mut self,
        radio: &mut Radio<'_>,
        rx: &[u8; BUFFER_LEN],
        address: u32,
        fits: bool,
        shared: &Shared,
    ) -> Option<bool> {
        let mut open =
            fits && self.encryption.phase == Phase::Idle && self.terminate.is_none() && self.terminated.is_none();
        let mut central_more = false;
        if radio.crc_ok() {
            let header = rx.first().copied().unwrap_or_default();
            let len = rx.get(1).copied().unwrap_or_default();
            let mic_ok = if self.encryption.rx_on && len != 0 {
                let Some(valid) = crypto::wait_decrypted() else {
                    self.abort = Some(ERROR_HARDWARE_FAILURE);
                    return None;
                };
                valid
            } else {
                true
            };
            if let Some(rssi) = radio.rssi() {
                for_phy_mut(&mut self.power, self.tx_phy).on_packet(rssi);
            }
            let fresh = self.receive(header, len, mic_ok, address, shared)?;
            central_more = header & MD != 0;
            if self.received {
                // A control PDU can change what the next packets mean: it
                // is handled before the central sends more.
                open &= header & LLID_MASK != Llid::Control.bits();
                self.stash(rx, self.encryption.rx_on);
            } else if fresh {
                // No room for it: the central sends it again next event.
                open = false;
            } else {
                // A retransmission acknowledges our packet only.
            }
        } else {
            self.stats.crc_errors = self.stats.crc_errors.wrapping_add(1);
            // Its length may be corrupt: the decryption is not waited for.
            if self.encryption.rx_on {
                crypto::stop();
            }
            open = false;
        }
        let ours_more = self.queue.iter().any(Option::is_some) || shared.has_acl_out();
        if let Some(tx_header) = self.tx.first_mut() {
            let flags = if self.sn { SN } else { 0 }
                | if self.nesn { NESN } else { 0 }
                | if open && ours_more { MD } else { 0 };
            *tx_header = (*tx_header & LLID_MASK) | flags;
        }
        if self.encryption.tx_sealed {
            let pointers = (self.tx.as_ptr(), self.tx_sealed.as_mut_ptr());
            let scratch = &mut self.encryption.scratch;
            // SAFETY: the configuration, scratch and buffers belong to this
            // connection, which disarms the CCM before the exchange returns
            // and wipes them only after the radio and the CCM stopped.
            let () = unsafe { crypto::arm_encrypt(&self.encryption.tx_config, pointers, scratch, self.tx_phy) };
            // SAFETY: as above; the exchange disables the radio before it
            // returns.
            let () = unsafe { radio.set_buffer(self.tx_sealed.as_mut_ptr()) };
        } else {
            crypto::disarm();
            // SAFETY: the transmit buffer belongs to this connection, and the
            // exchange disables the radio before it returns.
            let () = unsafe { radio.set_buffer(self.tx.as_mut_ptr()) };
        }
        Some(open && (central_more || ours_more))
    }

    /// Runs connection events until the connection ends, exchanging data and
    /// events with the host through `shared`.
    #[inline]
    pub async fn run(
        &mut self,
        radio: &mut Radio<'_>,
        clock: &mut Clock<'_>,
        rx: &mut [u8; BUFFER_LEN],
        shared: &Shared,
    ) -> (Ended, Stats) {
        let entropy = Prefetch::new();
        match select(self.run_events(radio, clock, rx, shared, &entropy), entropy.run()).await {
            Either::First(result) => result,
            Either::Second(never) => never,
        }
    }

    /// Schedules radio events independently of entropy collection progress.
    async fn run_events(
        &mut self,
        radio: &mut Radio<'_>,
        clock: &mut Clock<'_>,
        rx: &mut [u8; BUFFER_LEN],
        shared: &Shared,
        entropy: &Prefetch,
    ) -> (Ended, Stats) {
        radio.set_s1_included(true);
        self.load_next(shared);
        let ended = loop {
            if shared.take_reset() {
                break Ended::Reset;
            }
            self.flush_notifications(shared);
            crate::health::checkpoint(10);
            // Flash runs between two events, with the radio parked.
            if crate::maintenance::pending() {
                crate::maintenance::service(clock, radio).await;
                crate::health::checkpoint(10);
            }
            if let Some(ended) = self.ended(clock.now()) {
                break ended;
            }
            if self.terminate.is_none()
                && let Some(reason) = shared.take_disconnect()
            {
                self.enqueue(Llid::Control, &[OP_TERMINATE_IND, reason]);
                self.terminate = Some((reason, false));
                self.terminate_deadline = Some(clock.now().wrapping_add(self.timeout));
            }
            self.drive_host(clock.now(), shared, entropy);
            if let Some(reason) = self.abort {
                break Ended::Error(reason);
            }
            self.apply_instants(shared);
            let channel = self.hopping.channel(&self.map, self.counter);
            let window = self.window();
            // An anchor that passed during a flash pause is skipped, as with
            // latency; a transmit window is searched in the miss path below.
            if matches!(self.expect, Expect::Anchor) && reached(clock.now(), window.0) {
                self.stats.skipped = self.stats.skipped.wrapping_add(1);
                self.counter = self.counter.wrapping_add(1);
                continue;
            }
            shared.reset_wakeup();
            if self.skipped < self.latency && self.can_skip(shared) {
                if clock.idle_until(window.0, shared.wakeup()).await {
                    self.skipped = self.skipped.saturating_add(1);
                    self.stats.skipped = self.stats.skipped.wrapping_add(1);
                    self.counter = self.counter.wrapping_add(1);
                    continue;
                }
                self.skipped = self.latency;
            }
            clock.sleep_until(window.0, pending::<()>()).await;
            if !clock.ensure_crystal().await && reached(clock.now(), window.0) {
                self.stats.skipped = self.stats.skipped.wrapping_add(1);
                self.counter = self.counter.wrapping_add(1);
                continue;
            }
            self.skipped = 0;
            radio.set_channel(channel);
            radio.set_phy(self.phy);
            radio.set_tx_power(tx_power(for_phy_mut(&mut self.power, self.tx_phy).level()));
            self.stats.events = self.stats.events.wrapping_add(1);
            let encrypted = self.encryption.rx_on;
            if let Some(address) = self.exchange(radio, clock, rx, window, shared) {
                self.exchanged(address);
            } else {
                self.note_miss(channel, window);
            }
            self.process(rx, encrypted, shared);
            if let Some(ended) = self.ended(clock.now()) {
                break ended;
            }
            if reached(clock.now(), self.report_at) {
                self.report((clock.late(), clock.lead()));
            }
            self.counter = self.counter.wrapping_add(1);
        };
        crypto::disable();
        self.encryption.wipe();
        crypto::wipe(&mut self.rx_plain);
        for packet in &mut self.pending {
            if let Some(held) = packet.as_mut() {
                crypto::wipe(&mut held.bytes);
            }
            *packet = None;
        }
        crypto::wipe(&mut self.tx);
        crypto::wipe(&mut self.tx_sealed);
        radio.set_s1_included(false);
        radio.set_tx_power(tx_power(DEFAULT_LEVEL));
        radio.set_phy(Phy::M1);
        (ended, self.stats)
    }

    /// Drives host information requests independently of link encryption.
    fn service_queries(&mut self, now: u32, shared: &Shared) {
        if self.notifications.iter().any(Option::is_some) {
            return;
        }
        self.host_queries |= shared.take_queries();
        if !matches!(self.phy_request, Request::Requested(_))
            && self.phy_update.is_none()
            && let Some(preferences) = shared.take_phy_request()
        {
            self.host_phy = Some(preferences);
            self.preferred_phys = preferences;
            self.phy_request = Request::NotStarted;
        }
        if let Some(status) = self.phy_status.take() {
            self.notify(Packet::phy_update_result(status, self.phy.hci(), self.tx_phy.hci()), shared);
            self.host_phy = None;
            shared.complete_query(4);
        }
        if let Some(error) = self.feature_error.take() {
            self.notify(Packet::remote_features_result(error, [0; 8]), shared);
            self.host_queries &= !1;
            shared.complete_query(1);
        }
        if self.host_queries & 1 != 0 {
            if let Some(features) = self.central_features {
                self.notify(Packet::remote_features(features), shared);
                self.host_queries &= !1;
                shared.complete_query(1);
            } else if self.features_request == Request::Done {
                self.features_request = Request::NotStarted;
            } else {
                // The outstanding feature procedure will answer this query.
            }
        }
        if self.host_queries & 2 != 0 {
            if let Some(version) = self.version {
                self.notify(Packet::remote_version(version), shared);
                self.host_queries &= !2;
                shared.complete_query(2);
            } else if self.version_request == Request::NotStarted
                && self.encryption.phase == Phase::Idle
                && self.queue.iter().all(Option::is_none)
            {
                let mut version = [OP_VERSION_IND, 0, 0, 0, 0, 0];
                if let Some(bytes) = version.get_mut(1..) {
                    bytes.copy_from_slice(&VERSION);
                }
                self.enqueue(Llid::Control, &version);
                self.version_request = Request::Requested(now.wrapping_add(PROCEDURE_TIMEOUT_US));
            } else {
                // Wait for encryption or the outstanding version response.
            }
        }
        if matches!(self.version_request, Request::Requested(deadline) if reached(now, deadline)) {
            self.abort = Some(ERROR_RESPONSE_TIMEOUT);
        }
    }

    /// Applies the default PHY preference when establishing a new link.
    pub(crate) const fn set_preferred_phys(&mut self, preferences: [u8; 2]) { self.preferred_phys = preferences; }

    /// Answers an encryption request: sends the peripheral's session key
    /// diversifier and IV and asks the host for the long term key.
    fn start_encryption(&mut self, params: &[u8]) {
        let (Some(rand), Some(ediv), Some(central_skd), Some(central_iv)) =
            (field::<8>(params, 0), field::<2>(params, 8), field::<8>(params, 10), field::<4>(params, 18))
        else {
            self.enqueue(Llid::Control, &[OP_REJECT_IND, ERROR_UNSUPPORTED_FEATURE]);
            return;
        };
        crypto::wipe(&mut self.encryption.skd);
        crypto::wipe(&mut self.encryption.iv);
        if let Some(target) = self.encryption.skd.get_mut(..8) {
            target.copy_from_slice(&central_skd);
        }
        if let Some(target) = self.encryption.iv.get_mut(..4) {
            target.copy_from_slice(&central_iv);
        }
        self.encryption.phase = Phase::AwaitingEntropy { rand, ediv };
    }

    /// Counts the new packet just accepted, and keeps one with a payload,
    /// in plain text, for [`Self::process`] after the event. Its CCM
    /// counter is used up at once, as the next packet of the event may be
    /// decrypted before then.
    fn stash(&mut self, rx: &[u8; BUFFER_LEN], encrypted: bool) {
        self.received = false;
        self.stats.received = self.stats.received.wrapping_add(1);
        let mut bytes = [0_u8; DATA_BUFFER_LEN];
        // Empty PDUs have no MIC and need not produce a CCM output packet.
        let source = if encrypted && rx.get(1) != Some(&0) { self.rx_plain.as_slice() } else { rx.as_slice() };
        if let Some(chunk) = source.first_chunk::<DATA_BUFFER_LEN>() {
            bytes = *chunk;
        }
        let [header, len, ..] = bytes;
        if encrypted && len != 0 {
            self.encryption.rx_counter = self.encryption.rx_counter.saturating_add(1);
        }
        if len != 0 || header & MD != 0 {
            self.skipped = self.latency;
        }
        if len != 0
            && let Some(slot) = self.pending.iter_mut().find(|slot| slot.is_none())
        {
            *slot = Some(Pending { bytes, encrypted });
        }
        crypto::wipe(&mut bytes);
    }

    /// Sleeps until an access address arrives or `deadline` passes, woken by
    /// a timer compare instead of polling. Returns whether one arrived.
    fn wait_address(radio: &mut Radio<'_>, clock: &Clock<'_>, deadline: u32) -> bool {
        clock.expire_at(deadline);
        let heard = radio.wait_address(|| clock.expired(deadline));
        clock.stop_expiry();
        heard
    }

    /// Window widening after `elapsed` microseconds since the last anchor,
    /// at most half the interval less the interframe space (Core, Vol 6,
    /// Part B, 4.5.7), as Zephyr limits it: wider windows would overlap the
    /// neighbouring events.
    fn widening(&self, elapsed: u32) -> u32 {
        let drift = u64::from(elapsed).saturating_mul(u64::from(self.sca_ppm)).div_ceil(1_000_000);
        let limit = (self.interval >> 1_u32).saturating_sub(T_IFS_US);
        u32::try_from(drift).unwrap_or(u32::MAX).saturating_add(WIDENING_FIXED_US).min(limit)
    }

    /// Radio start and access address deadline of the current event.
    fn window(&self) -> (u32, u32) {
        let (earliest, latest) = match self.expect {
            Expect::Anchor => {
                let expected = self.expected_anchor();
                (expected, expected)
            },
            Expect::Window { start, size } => {
                let earliest = start.wrapping_add(self.phy.address_offset_us());
                (earliest, earliest.wrapping_add(size))
            },
        };
        let widening = self.widening(latest.wrapping_sub(self.anchor));
        let enable = earliest
            .wrapping_sub(widening)
            .wrapping_sub(self.phy.address_offset_us())
            .wrapping_sub(RAMP_UP_US)
            .wrapping_sub(RX_MARGIN_US);
        (enable, latest.wrapping_add(widening).wrapping_add(RX_TAIL_US))
    }
}

/// Parses the parameters of a connection update.
fn parse_update(bytes: &[u8]) -> Option<Update> {
    let [win_size, offset0, offset1, interval0, interval1, latency0, latency1, timeout0, timeout1, instant0, instant1] =
        field::<11>(bytes, 0)?;
    let params = ConnectionParams::new(
        u16::from_le_bytes([interval0, interval1]),
        u16::from_le_bytes([latency0, latency1]),
        u16::from_le_bytes([timeout0, timeout1]),
    );
    if !valid_connection_parameters(
        params.interval,
        params.latency,
        params.timeout,
        win_size,
        u16::from_le_bytes([offset0, offset1]),
    ) {
        return None;
    }
    Some(Update {
        instant: u16::from_le_bytes([instant0, instant1]),
        interval: u32::from(u16::from_le_bytes([interval0, interval1])).saturating_mul(UNIT_1250_US),
        latency: params.latency,
        params,
        requested: false,
        timeout: u32::from(u16::from_le_bytes([timeout0, timeout1])).saturating_mul(UNIT_10MS_US),
        win_offset: u32::from(u16::from_le_bytes([offset0, offset1])).saturating_mul(UNIT_1250_US),
        win_size: u32::from(win_size).saturating_mul(UNIT_1250_US),
    })
}

/// Selects per-PHY state without indexing or a fallible conversion.
const fn for_phy_mut<Value>(values: &mut [Value; 2], phy: Phy) -> &mut Value {
    let &mut [ref mut one, ref mut two] = values;
    match phy {
        Phy::M1 => one,
        Phy::M2 => two,
    }
}

/// Transmit power in dBm of power control level `level`.
fn tx_power(level: usize) -> i8 { LEVELS_DBM.get(level).copied().unwrap_or_default() }

/// Whether an instant is still ahead of the current event: the event at it
/// is running already, and the specification counts a distance of 32767 or
/// more as passed.
const fn future_instant(now: u16, instant: u16) -> bool {
    let distance = instant.wrapping_sub(now);
    distance != 0 && distance < 0x7FFF
}

/// Exact parameter lengths of the control PDUs this controller understands.
const fn control_len(code: u8) -> Option<usize> {
    match code {
        OP_CONNECTION_UPDATE_IND => Some(11),
        OP_CHANNEL_MAP_IND => Some(7),
        OP_TERMINATE_IND | OP_UNKNOWN_RSP | OP_REJECT_IND => Some(1),
        OP_ENC_REQ => Some(22),
        OP_ENC_RSP => Some(12),
        OP_START_ENC_REQ | OP_START_ENC_RSP | OP_PAUSE_ENC_REQ | OP_PAUSE_ENC_RSP | OP_PING_REQ | OP_PING_RSP => {
            Some(0)
        },
        OP_FEATURE_REQ | OP_FEATURE_RSP | OP_PERIPHERAL_FEATURE_REQ | OP_LENGTH_REQ | OP_LENGTH_RSP => Some(8),
        OP_VERSION_IND => Some(5),
        OP_PHY_REQ | OP_PHY_RSP | OP_REJECT_EXT_IND => Some(2),
        OP_CONNECTION_PARAM_REQ | OP_CONNECTION_PARAM_RSP => Some(23),
        OP_PHY_UPDATE_IND | OP_POWER_CONTROL_RSP | OP_POWER_CHANGE_IND => Some(4),
        OP_POWER_CONTROL_REQ => Some(3),
        _ => None,
    }
}

#[cfg(test)] mod tests;
