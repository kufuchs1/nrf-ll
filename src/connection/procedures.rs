//! LL control procedures beyond encryption: connection parameters, feature
//! exchange, PHY update and the answers that refuse a procedure.

use super::{
    Connection,
    ERROR_INSTANT_PASSED,
    ERROR_INVALID_PARAMETERS,
    ERROR_PDU_NOT_ALLOWED,
    ERROR_RESPONSE_TIMEOUT,
    ERROR_UNSUPPORTED_FEATURE,
    ERROR_UNSUPPORTED_VALUE,
    FEATURES,
    OP_CONNECTION_PARAM_REQ,
    OP_CONNECTION_PARAM_RSP,
    OP_CONNECTION_UPDATE_IND,
    OP_FEATURE_RSP,
    OP_PERIPHERAL_FEATURE_REQ,
    OP_PHY_REQ,
    OP_PHY_RSP,
    OP_PING_REQ,
    OP_POWER_CHANGE_IND,
    OP_POWER_CONTROL_REQ,
    OP_POWER_CONTROL_RSP,
    OP_REJECT_EXT_IND,
    OP_REJECT_IND,
    OP_UNKNOWN_RSP,
    PROCEDURE_TIMEOUT_US,
    Phase,
    Request,
    STATUS_SUCCESS,
    UNIT_10MS_US,
    UNIT_1250_US,
    for_phy_mut,
    future_instant,
    parse_update,
    tx_power,
};
use crate::{
    clock::reached,
    hci::{ConnectionParams, Packet, Shared},
    log::info,
    pdu::{Llid, field, valid_connection_parameters},
    power_control::LEVELS_DBM,
    radio::Phy,
};

/// Acceptable power reduction when no packet has been measured yet.
const UNKNOWN_REDUCTION: u8 = 0xFF;
/// Error code: different transaction collision, another procedure with an
/// instant runs.
const ERROR_DIFFERENT_TRANSACTION: u8 = 0x2A;
/// Offset field of a connection parameter request without a preference.
const NO_OFFSET: [u8; 2] = [0xFF, 0xFF];

#[expect(clippy::multiple_inherent_impl, reason = "the procedures live in their own file")]
impl Connection {
    /// Tells a central that supports power control about a change of the
    /// own transmit power.
    fn announce_power(&mut self) {
        let level = for_phy_mut(&mut self.power, self.tx_phy).level();
        let supports = self.central_features.is_some_and(|[_, _, _, _, power, ..]| power & 0x02 != 0);
        let free = self.encryption.phase == Phase::Idle && self.queue.iter().all(Option::is_none);
        if level == *for_phy_mut(&mut self.announced_power, self.tx_phy)
            || !supports
            || !free
            || self.power_reporting & self.tx_phy.hci() == 0
        {
            return;
        }
        let before = i32::from(tx_power(*for_phy_mut(&mut self.announced_power, self.tx_phy)));
        let now = tx_power(level);
        let delta = i8::try_from(i32::from(now).saturating_sub(before)).unwrap_or_default();
        self.enqueue(Llid::Control, &[
            OP_POWER_CHANGE_IND,
            self.tx_phy.hci(),
            limit_flags(level),
            delta.cast_unsigned(),
            now.cast_unsigned(),
        ]);
        *for_phy_mut(&mut self.announced_power, self.tx_phy) = level;
    }

    /// Keeps authenticated packets coming (LE Ping): pings the central when
    /// three quarters of the authenticated payload timeout passed without a
    /// packet with a valid MIC, and tells the host when all of it passed.
    fn check_payload(&mut self, now: u32, shared: &Shared) {
        let Some((last, pinged)) = self.payload_timer else { return };
        let timeout = shared.payload_timeout();
        let elapsed = now.wrapping_sub(last);
        if elapsed >= timeout {
            // Retained until the host takes it; dropped by the delivery only
            // if the host did not enable it in event mask page 2.
            if !self.notifications.iter().flatten().any(Packet::is_payload_timeout) {
                self.notify(Packet::payload_timeout_expired(), shared);
            }
            self.payload_timer = Some((now, false));
            info!("authenticated payload timeout expired");
        } else if !pinged
            && self.ping_request.is_none()
            && elapsed >= timeout.saturating_sub(timeout >> 2_u32)
            && self.encryption.phase == Phase::Idle
            && self.queue.iter().all(Option::is_none)
        {
            self.enqueue(Llid::Control, &[OP_PING_REQ]);
            self.payload_timer = Some((last, true));
            self.ping_request = Some(now.wrapping_add(PROCEDURE_TIMEOUT_US));
        } else {
            // Authenticated traffic is recent enough.
        }
    }

    /// Current connection parameters in link layer units.
    pub(super) fn current_params(&self) -> ConnectionParams {
        ConnectionParams::new(
            u16::try_from(self.interval.checked_div(UNIT_1250_US).unwrap_or(0)).unwrap_or(u16::MAX),
            self.latency,
            u16::try_from(self.timeout.checked_div(UNIT_10MS_US).unwrap_or(0)).unwrap_or(u16::MAX),
        )
    }

    /// Answers the feature exchange of the central, and takes its answer to
    /// ours. The first byte holds the features both sides use.
    pub(super) fn handle_features(&mut self, code: u8, params: &[u8]) {
        let Some(&features) = params.first_chunk::<8>() else { return };
        let [central, ..] = features;
        self.central_features = Some(features);
        if code == OP_FEATURE_RSP {
            self.features_request = Request::Done;
            return;
        }
        let mut response = [OP_FEATURE_RSP, 0, 0, 0, 0, 0, 0, 0, 0];
        for (target, source) in response.iter_mut().skip(1).zip(FEATURES) {
            *target = source;
        }
        if let Some(first) = response.get_mut(1) {
            *first &= central;
        }
        self.enqueue(Llid::Control, &response);
    }

    /// Takes connection updates, answers the central's parameter requests
    /// and takes its answer to the host's.
    pub(super) fn handle_parameters(&mut self, code: u8, params: &[u8]) {
        match code {
            OP_CONNECTION_UPDATE_IND => {
                let Some(mut update) = parse_update(params) else {
                    self.abort = Some(ERROR_INVALID_PARAMETERS);
                    return;
                };
                if !future_instant(self.counter, update.instant) {
                    self.abort = Some(ERROR_INSTANT_PASSED);
                } else if self.param_update.is_some()
                    || self.phy_update.is_some()
                    || self.channel_update.is_some()
                    || self.notifications.iter().flatten().any(Packet::is_parameter_update)
                {
                    self.abort = Some(ERROR_PDU_NOT_ALLOWED);
                } else {
                    // The update answers a request of the host; the host
                    // learns the outcome at the instant.
                    update.requested = self.param_request.take().is_some();
                    self.param_update = Some(update);
                }
            },
            OP_CONNECTION_PARAM_RSP => {
                // Only a peripheral sends this PDU; a central answers our
                // request with UPDATE_IND or REJECT_EXT_IND (Core 5.1.7.2).
                self.abort = Some(ERROR_PDU_NOT_ALLOWED);
            },
            OP_CONNECTION_PARAM_REQ => {
                if !valid_request(params) {
                    self.enqueue(Llid::Control, &[
                        OP_REJECT_EXT_IND,
                        OP_CONNECTION_PARAM_REQ,
                        ERROR_INVALID_PARAMETERS,
                    ]);
                } else if self.param_update.is_some()
                    || self.phy_update.is_some()
                    || self.channel_update.is_some()
                    || self.notifications.iter().flatten().any(Packet::is_parameter_update)
                {
                    self.enqueue(Llid::Control, &[
                        OP_REJECT_EXT_IND,
                        OP_CONNECTION_PARAM_REQ,
                        ERROR_DIFFERENT_TRANSACTION,
                    ]);
                } else {
                    // Any parameters the central proposes suit the device.
                    let mut response = [0_u8; 24];
                    for (target, source) in
                        response.iter_mut().zip(core::iter::once(&OP_CONNECTION_PARAM_RSP).chain(params))
                    {
                        *target = *source;
                    }
                    self.enqueue(Llid::Control, &response);
                }
            },
            _ => {},
        }
    }

    /// Answers the PDUs of the PHY update procedure.
    pub(super) fn handle_phy(&mut self, code: u8, params: &[u8]) {
        if code == OP_PHY_REQ {
            if field::<2>(params, 0).is_none_or(|[tx, rx]| tx.trailing_zeros() >= 2 || rx.trailing_zeros() >= 2) {
                self.enqueue(Llid::Control, &[OP_REJECT_EXT_IND, OP_PHY_REQ, ERROR_UNSUPPORTED_VALUE]);
                return;
            }
            // The central's procedure takes the place of ours.
            self.phy_request = Request::Requested(self.last_valid.wrapping_add(PROCEDURE_TIMEOUT_US));
            let [tx, rx] = self.preferred_phys;
            self.enqueue(Llid::Control, &[OP_PHY_RSP, tx, rx]);
            return;
        }
        let Some([to_peripheral, to_central, instant0, instant1]) = field::<4>(params, 0) else { return };
        self.phy_request = Request::Done;
        if to_peripheral == 0 && to_central == 0 {
            if self.host_phy.is_some() {
                self.phy_status = Some(STATUS_SUCCESS);
            }
            return;
        }
        let keep = self.phy.hci();
        let receive = Phy::from_bits(if to_peripheral == 0 { keep } else { to_peripheral });
        let send = Phy::from_bits(if to_central == 0 { self.tx_phy.hci() } else { to_central });
        // Each direction keeps its own PHY. Asymmetric exchanges disable
        // the RX-to-TX shortcut and use a compensated TIMER/PPI start.
        let (Some(phy), Some(other)) = (receive, send) else {
            self.abort = Some(ERROR_UNSUPPORTED_VALUE);
            return;
        };
        let instant = u16::from_le_bytes([instant0, instant1]);
        if !future_instant(self.counter, instant) {
            self.abort = Some(ERROR_INSTANT_PASSED);
        } else if self.phy_update.is_some()
            || self.param_update.is_some()
            || self.channel_update.is_some()
            || self.notifications.iter().flatten().any(Packet::is_phy_update)
        {
            self.abort = Some(ERROR_PDU_NOT_ALLOWED);
        } else if phy != self.phy || other != self.tx_phy {
            self.next_tx_phy = other;
            self.phy_update = Some((phy, instant));
        } else if self.host_phy.is_some() {
            self.phy_status = Some(STATUS_SUCCESS);
        } else {
            // The PHY stays: nothing changes at the instant, and the host,
            // which did not ask, learns nothing (Core, Vol 4, Part E,
            // 7.7.65.12).
        }
    }

    /// Answers the central's request to change the own transmit power by a
    /// delta, with the power now used and how far the central could lower
    /// its own. An unknown acceptable reduction is reported as 0xFF.
    pub(super) fn handle_power(&mut self, params: &[u8]) {
        let Some([phy, delta, central_power]) = field::<3>(params, 0) else { return };
        let error = if Phy::from_bits(phy).is_none() {
            Some(ERROR_UNSUPPORTED_VALUE)
        } else if central_power == 126 {
            Some(ERROR_INVALID_PARAMETERS)
        } else {
            None
        };
        if let Some(reason) = error {
            self.enqueue(Llid::Control, &[OP_REJECT_EXT_IND, OP_POWER_CONTROL_REQ, reason]);
            return;
        }
        let Some(request_phy) = Phy::from_bits(phy) else { return };
        let before = tx_power(for_phy_mut(&mut self.power, request_phy).level());
        let requested = if delta == 0x7F {
            i32::from(i8::MAX)
        } else {
            i32::from(before).saturating_add(i32::from(delta.cast_signed()))
        };
        // Round upward to the lowest available power at least as high as
        // requested.
        let requested_level = LEVELS_DBM.iter().copied().find(|&level| i32::from(level) >= requested).unwrap_or(4);
        for_phy_mut(&mut self.power, request_phy).move_to(i32::from(requested_level));
        self.power_reporting |= phy;
        let level = for_phy_mut(&mut self.power, request_phy).level();
        let now = tx_power(level);
        let change = i8::try_from(i32::from(now).saturating_sub(i32::from(before))).unwrap_or_default();
        let reduction = UNKNOWN_REDUCTION;
        self.enqueue(Llid::Control, &[
            OP_POWER_CONTROL_RSP,
            limit_flags(level),
            change.cast_unsigned(),
            now.cast_unsigned(),
            reduction,
        ]);
        *for_phy_mut(&mut self.announced_power, request_phy) = level;
    }

    /// Takes the central's refusal of a procedure of ours: an unknown
    /// response or a rejection naming the procedure, or a plain rejection,
    /// which can only answer a connection parameter request.
    pub(super) const fn handle_rejection(&mut self, code: u8, params: &[u8]) {
        let (opcode, error) = match (code, params) {
            (OP_UNKNOWN_RSP, &[opcode]) => (opcode, ERROR_UNSUPPORTED_FEATURE),
            (OP_REJECT_EXT_IND, &[opcode, error]) => (opcode, error),
            (OP_REJECT_IND, &[error]) => (OP_CONNECTION_PARAM_REQ, error),
            _ => return,
        };
        match opcode {
            OP_PHY_REQ => {
                self.phy_request = Request::Done;
                if self.host_phy.is_some() {
                    self.phy_status = Some(error);
                }
            },
            OP_PERIPHERAL_FEATURE_REQ => {
                self.features_request = Request::Done;
                if self.host_queries & 1 != 0 {
                    self.feature_error = Some(error);
                }
            },
            OP_PING_REQ => self.ping_request = None,
            OP_CONNECTION_PARAM_REQ if self.param_request.is_some() => {
                self.param_request = None;
                self.param_status = Some(error);
            },
            _ => {},
        }
    }

    /// Reports a connection parameter request of the host that ended without
    /// an update.
    pub(super) fn report_parameters(&mut self, shared: &Shared) {
        if let Some(status) = self.param_status
            && shared.try_push_event(Packet::connection_update_complete(status, self.current_params()))
        {
            self.param_status = None;
            shared.finish_param_request();
        }
    }

    /// Starts the procedures of this side while no other runs: once the link
    /// is encrypted the feature exchange, then asking for LE 2M, and at any
    /// time the host's connection parameter requests, which would otherwise
    /// wait forever on a link that is never encrypted. Gives up on a central
    /// that does not answer in time.
    #[inline(never)]
    pub(super) fn start_procedures(&mut self, now: u32, shared: &Shared) {
        shared.set_remote_features(self.central_features.map_or(0, |[first, ..]| first));
        self.announce_power();
        self.check_payload(now, shared);
        if let Some(deadline) = self.param_request.or(self.ping_request)
            && reached(now, deadline)
        {
            self.abort = Some(ERROR_RESPONSE_TIMEOUT);
            return;
        }
        if [self.features_request, self.phy_request]
            .iter()
            .any(|request| matches!(request, Request::Requested(deadline) if reached(now, *deadline)))
        {
            self.abort = Some(ERROR_RESPONSE_TIMEOUT);
            return;
        }
        let idle = self.encryption.phase == Phase::Idle
            && self.param_update.is_none()
            && self.phy_update.is_none()
            && self.channel_update.is_none()
            && self.queue.iter().all(Option::is_none)
            && self.notifications.iter().all(Option::is_none);
        let ours_running =
            [self.features_request, self.phy_request].iter().any(|request| matches!(request, Request::Requested(_)))
                || self.param_request.is_some();
        if !idle || ours_running {
            return;
        }
        let deadline = now.wrapping_add(PROCEDURE_TIMEOUT_US);
        let encrypted = self.encryption.tx_on;
        if (encrypted || self.host_queries & 1 != 0)
            && self.features_request == Request::NotStarted
            && self.central_features.is_none()
        {
            let mut request = [OP_PERIPHERAL_FEATURE_REQ, 0, 0, 0, 0, 0, 0, 0, 0];
            for (target, source) in request.iter_mut().skip(1).zip(FEATURES) {
                *target = source;
            }
            self.enqueue(Llid::Control, &request);
            self.features_request = Request::Requested(deadline);
        } else if (self.host_phy.is_some() || (encrypted && self.phy == Phy::M1))
            && self.phy_request == Request::NotStarted
        {
            let [tx, rx] = self.preferred_phys;
            self.enqueue(Llid::Control, &[OP_PHY_REQ, tx, rx]);
            self.phy_request = Request::Requested(deadline);
        } else if let Some([min, max, latency, timeout]) = shared.take_param_request() {
            let current = self.current_params();
            if (min..=max).contains(&current.interval) && latency == current.latency && timeout == current.timeout {
                // Already in place: report success without a procedure.
                self.param_status = Some(STATUS_SUCCESS);
                return;
            }
            let mut request = [0_u8; 24];
            let fields = [
                [OP_CONNECTION_PARAM_REQ].as_slice(),
                &min.to_le_bytes(),
                &max.to_le_bytes(),
                &latency.to_le_bytes(),
                &timeout.to_le_bytes(),
                // No preferred periodicity; offsets relative to this event.
                &[0],
                &self.counter.to_le_bytes(),
                &NO_OFFSET,
                &NO_OFFSET,
                &NO_OFFSET,
                &NO_OFFSET,
                &NO_OFFSET,
                &NO_OFFSET,
            ];
            for (target, source) in request.iter_mut().zip(fields.into_iter().flatten()) {
                *target = *source;
            }
            self.enqueue(Llid::Control, &request);
            self.param_request = Some(deadline);
            info!("asking for connection parameters");
        } else {
            // Nothing of ours to start.
        }
    }
}

/// Power control flags of `level`: bit 0 at the lowest power, bit 1 at the
/// highest.
fn limit_flags(level: usize) -> u8 {
    u8::from(level == 0) | (u8::from(level.saturating_add(1) >= LEVELS_DBM.len()) << 1_u8)
}

/// Whether a connection parameter request or response has parameters within
/// the specification: an interval range, latency and supervision timeout.
fn valid_request(params: &[u8]) -> bool {
    let Some([min0, min1, max0, max1, latency0, latency1, timeout0, timeout1]) = field::<8>(params, 0) else {
        return false;
    };
    let min = u16::from_le_bytes([min0, min1]);
    let max = u16::from_le_bytes([max0, max1]);
    min <= max
        && valid_connection_parameters(
            min,
            u16::from_le_bytes([latency0, latency1]),
            u16::from_le_bytes([timeout0, timeout1]),
            1,
            0,
        )
        && valid_connection_parameters(
            max,
            u16::from_le_bytes([latency0, latency1]),
            u16::from_le_bytes([timeout0, timeout1]),
            1,
            0,
        )
}
