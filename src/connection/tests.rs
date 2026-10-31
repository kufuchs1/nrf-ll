//! Regression tests for the actual link state machine, without radio MMIO.

use super::*;

fn connection() -> Connection {
    Connection::new(
        &ConnectInd {
            access_address:   0x9A32_8370,
            channel_map:      [0xFF, 0xFF, 0xFF, 0xFF, 0x1F],
            crc_init:         1,
            csa2:             false,
            hop:              5,
            initiator:        [1; 6],
            initiator_random: false,
            interval:         12,
            latency:          0,
            sca:              0,
            sca_ppm:          500,
            timeout:          600,
            win_offset:       0,
            win_size:         1,
        },
        100,
    )
}

#[test]
fn version_indication_is_queued_only_once_per_connection() {
    let mut link = connection();
    let version = [OP_VERSION_IND, 0x0B, 0, 0, 0, 0];
    link.handle_control(&version, false);
    assert_eq!(link.queue.iter().flatten().count(), 1);
    assert_eq!(link.queue[0].unwrap().data[0], OP_VERSION_IND);
    link.queue = [None; QUEUE_LEN];
    for _ in 0..10 {
        link.handle_control(&version, false);
    }
    assert!(link.queue.iter().all(Option::is_none));
    assert_eq!(link.abort, None);
}

#[test]
fn unanswered_control_procedures_end_the_link_despite_keepalives() {
    let shared = Shared::new();
    for procedure in 0..3 {
        let mut link = connection();
        link.establishment_deadline = None;
        match procedure {
            0 => link.features_request = Request::Requested(1000),
            1 => link.phy_request = Request::Requested(1000),
            _ => link.param_request = Some(1000),
        }
        link.last_valid = 999;
        link.start_procedures(999, &shared);
        assert_eq!(link.abort, None);
        link.start_procedures(1000, &shared);
        assert!(matches!(link.ended(1000), Some(Ended::Error(ERROR_RESPONSE_TIMEOUT))));
    }
    let mut link = connection();
    link.features_request = Request::Requested(5);
    link.start_procedures(u32::MAX, &shared);
    assert_eq!(link.abort, None);
    link.start_procedures(5, &shared);
    assert_eq!(link.abort, Some(ERROR_RESPONSE_TIMEOUT));
}

#[test]
fn keepalive_packets_cannot_extend_a_local_disconnect_deadline() {
    let mut link = connection();
    link.establishment_deadline = None;
    link.terminate = Some((0x13, false));
    link.terminate_deadline = Some(1000);
    link.last_valid = 999;
    assert!(link.ended(999).is_none());
    assert!(matches!(link.ended(1000), Some(Ended::Local(0x13))));
    link.terminate_deadline = Some(5);
    assert!(link.ended(u32::MAX).is_none());
    assert!(matches!(link.ended(5), Some(Ended::Local(0x13))));
}

#[test]
fn first_valid_packet_replaces_the_short_establishment_deadline() {
    let mut link = connection();
    let deadline = link.establishment_deadline.unwrap();
    assert!(matches!(link.ended(deadline), Some(Ended::Error(ERROR_FAILED_TO_ESTABLISH))));
    assert_eq!(link.receive(Llid::Continuation.bits(), 0, true, 1000, &Shared::new()), Some(true));
    assert!(link.establishment_deadline.is_none());
    assert!(link.ended(deadline).is_none());
}

#[test]
fn encryption_deadline_is_not_refreshed_by_received_traffic() {
    let mut link = connection();
    link.establishment_deadline = None;
    link.procedure_deadline = Some(1000);
    link.last_valid = 999;
    assert!(link.ended(999).is_none());
    assert!(matches!(link.ended(1000), Some(Ended::Error(ERROR_RESPONSE_TIMEOUT))));
    link.abort = Some(ERROR_MIC_FAILURE);
    assert!(matches!(link.ended(1000), Some(Ended::Error(ERROR_MIC_FAILURE))));
}

#[test]
fn unsolicited_start_response_never_enables_encryption() {
    for encrypted in [false, true] {
        let mut link = connection();
        link.handle_control(&[OP_START_ENC_RSP], encrypted);
        assert!(!link.encryption.tx_on);
        assert_eq!(link.abort, Some(ERROR_PDU_NOT_ALLOWED));
    }
}

#[test]
fn security_notification_survives_host_queue_pressure() {
    let full = Shared::new();
    for _ in 0..4 {
        assert!(full.try_push_event(Packet::completed_packets(1)));
    }
    let mut link = connection();
    link.encryption.phase = Phase::AwaitingStartResponse;
    link.encryption.rx_on = true;
    link.handle_control(&[OP_START_ENC_RSP], true);
    link.process(&[0; BUFFER_LEN], true, &full);
    assert_eq!(link.encryption_change, Some((0, true)));
    let available = Shared::new();
    link.process(&[0; BUFFER_LEN], true, &available);
    assert_eq!(link.encryption_change, None);
    for _ in 0..3 {
        assert!(available.try_push_event(Packet::completed_packets(1)));
    }
    assert!(!available.try_push_event(Packet::completed_packets(1)));
}

#[test]
fn start_response_requires_an_encrypted_received_packet() {
    let mut link = connection();
    link.encryption.phase = Phase::AwaitingStartResponse;
    link.encryption.rx_on = true;
    link.handle_control(&[OP_START_ENC_RSP], false);
    assert!(!link.encryption.tx_on);
    assert_eq!(link.abort, Some(ERROR_PDU_NOT_ALLOWED));
}

#[test]
fn authenticated_start_response_completes_only_the_expected_procedure() {
    let mut link = connection();
    link.encryption.phase = Phase::AwaitingStartResponse;
    link.encryption.rx_on = true;
    link.procedure_deadline = Some(1000);
    link.handle_control(&[OP_START_ENC_RSP], true);
    assert!(link.encryption.tx_on);
    assert!(link.encryption.phase == Phase::Idle);
    assert_eq!(link.procedure_deadline, None);
    assert_eq!(link.abort, None);
}

#[test]
fn repeated_encryption_requests_cannot_reset_session_state() {
    for phase in [Phase::Starting, Phase::AwaitingStartResponse, Phase::Idle] {
        let mut link = connection();
        link.encryption.phase = phase;
        link.encryption.rx_on = true;
        link.encryption.rx_counter = 42;
        link.handle_control(&[OP_ENC_REQ; 23], true);
        assert_eq!(link.abort, Some(ERROR_PDU_NOT_ALLOWED));
        assert_eq!(link.encryption.rx_counter, 42);
    }
}

#[test]
fn bad_mic_cannot_acknowledge_acl_or_move_sequence_numbers() {
    let mut link = connection();
    link.encryption.rx_on = true;
    link.tx_kind = TxKind::Acl;
    let shared = Shared::new();
    assert_eq!(link.receive(Llid::Start.bits() | NESN, 5, false, 999, &shared), None);
    assert_eq!(link.abort, Some(ERROR_MIC_FAILURE));
    assert!(!link.sn && !link.nesn && !link.received);
    assert_eq!(link.completed, 0);
    assert_eq!(link.last_valid, 100);
}

#[test]
fn unverified_new_payloads_never_change_receive_sequence_state() {
    let shared = Shared::new();
    for header in 0..=u8::MAX {
        for len in 1..=u8::MAX {
            let mut link = connection();
            link.encryption.rx_on = true;
            link.tx_kind = TxKind::Acl;
            let result = link.receive(header, len, false, 999, &shared);
            assert_ne!(result, Some(true), "header={header:#x}, len={len}");
            assert!(!link.nesn && !link.received);
            let acknowledged = result == Some(false) && header & NESN != 0;
            assert_eq!(link.sn, acknowledged);
            assert_eq!(link.completed, u16::from(acknowledged));
            // Only a retransmission keeps the link alive.
            assert_eq!(link.last_valid, if result == Some(false) { 999 } else { 100 });
            assert_eq!(link.encryption.rx_counter, 0);
        }
    }
}

#[test]
fn encrypted_retransmission_acknowledges_tx_without_consuming_rx_nonce() {
    let mut link = connection();
    link.encryption.rx_on = true;
    link.nesn = true;
    link.tx_kind = TxKind::Acl;
    assert_eq!(link.receive(Llid::Start.bits() | NESN, 5, false, 999, &Shared::new()), Some(false));
    assert_eq!(link.abort, None);
    assert!(link.sn && link.nesn && !link.received);
    assert_eq!(link.completed, 1);
    // It shows the central is there, which keeps the link alive.
    assert_eq!(link.last_valid, 999);
    assert!(link.payload_timer.is_none());
    assert_eq!(link.encryption.rx_counter, 0);
}

#[test]
fn new_authenticated_packet_acknowledges_acl() {
    let mut link = connection();
    link.encryption.rx_on = true;
    link.tx_kind = TxKind::Acl;
    assert_eq!(link.receive(Llid::Start.bits() | NESN, 5, true, 999, &Shared::new()), Some(true));
    assert!(link.sn && link.nesn && link.received);
    assert_eq!(link.completed, 1);
    assert_eq!(link.last_valid, 999);
}

#[test]
fn malformed_data_packets_fail_closed() {
    // Payloads up to 251 octets fit the receive buffer, whatever the
    // negotiated length; with a MIC no length field can exceed it.
    for (header, len, encrypted) in [(0, 1, false), (2, 0, false), (3, 0, true), (2, 252, false)] {
        let mut link = connection();
        link.encryption.rx_on = encrypted;
        assert_eq!(link.receive(header, len, true, 999, &Shared::new()), None);
        assert_eq!(link.abort, Some(ERROR_INVALID_PARAMETERS));
        assert!(!link.received && !link.sn && !link.nesn);
    }
}

#[test]
fn encrypted_payload_cannot_omit_mic() {
    for len in 1..=4 {
        let mut link = connection();
        link.encryption.rx_on = true;
        assert_eq!(link.receive(2, len, true, 999, &Shared::new()), None);
        assert_eq!(link.abort, Some(ERROR_MIC_FAILURE));
    }
}

#[test]
fn empty_packets_use_raw_header_instead_of_stale_ccm_output() {
    let mut link = connection();
    link.encryption.rx_on = true;
    link.rx_plain.fill(0xFF);
    let mut rx = [0; BUFFER_LEN];
    rx[0] = Llid::Continuation.bits();
    let shared = Shared::new();
    assert_eq!(link.receive(rx[0], 0, true, 999, &shared), Some(true));
    link.process(&rx, true, &shared);
    assert_eq!(link.encryption.rx_counter, 0);
    assert_eq!(link.abort, None);
    assert_eq!(link.stats.received, 1);
}

#[test]
fn tx_counter_exhaustion_cannot_wrap() {
    let mut link = connection();
    link.encryption.tx_on = true;
    link.encryption.tx_counter = crypto::COUNTER_LIMIT;
    link.enqueue(Llid::Control, &[OP_PING_RSP]);
    link.load_next(&Shared::new());
    assert_eq!(link.abort, Some(ERROR_MIC_FAILURE));
    assert_eq!(link.encryption.tx_counter, crypto::COUNTER_LIMIT);
}

#[test]
fn controls_require_exact_lengths_and_valid_parameters() {
    // A wrong length is answered as an unknown PDU.
    for payload in [&[OP_START_ENC_RSP, 0][..], &[OP_CHANNEL_MAP_IND, 1][..], &[OP_ENC_REQ][..]] {
        let mut link = connection();
        link.handle_control(payload, false);
        assert_eq!(link.abort, None);
        assert_eq!(link.queue[0].map(|queued| queued.data[..2] == [OP_UNKNOWN_RSP, payload[0]]), Some(true));
        assert!(link.channel_update.is_none() && link.encryption.phase == Phase::Idle);
    }
    // Unless an encryption procedure runs, which an answer would block.
    let mut link = connection();
    link.encryption.phase = Phase::Starting;
    link.handle_control(&[OP_START_ENC_RSP, 0], false);
    assert_eq!(link.abort, Some(ERROR_INVALID_PARAMETERS));
    assert!(link.queue.iter().all(Option::is_none));
    let mut link = connection();
    link.handle_control(&[OP_CHANNEL_MAP_IND, 0, 0, 0, 0, 0, 6, 0], false);
    assert_eq!(link.abort, Some(ERROR_INVALID_PARAMETERS));
    assert!(link.channel_update.is_none());
}

#[test]
fn channel_map_instants_are_checked_across_counter_wrap() {
    assert!(future_instant(0xFFFE, 4));
    assert!(!future_instant(4, 0xFFFE));
    assert!(!future_instant(4, 4));
    assert!(!future_instant(0, 0x8000));
    assert!(!future_instant(0, 0x7FFF));
    assert!(future_instant(0, 0x7FFE));
    let mut link = connection();
    link.counter = 5;
    link.handle_control(&[OP_CHANNEL_MAP_IND, 3, 0, 0, 0, 0, 4, 0], false);
    assert_eq!(link.abort, Some(ERROR_INSTANT_PASSED));
}

#[test]
fn invalid_connection_updates_never_change_timing() {
    for params in [[0; 11], [1, 0, 0, 5, 0, 0, 0, 100, 0, 6, 0], [1, 0, 0, 12, 0, 0xFF, 0xFF, 100, 0, 6, 0]] {
        assert!(parse_update(&params).is_none());
    }
    assert!(parse_update(&[1, 0, 0, 12, 0, 30, 0, 0x58, 2, 6, 0]).is_some());
}

#[test]
fn control_queue_overflow_ends_instead_of_stranding_a_procedure() {
    let mut link = connection();
    for _ in 0..=QUEUE_LEN {
        link.enqueue(Llid::Control, &[OP_PING_RSP]);
    }
    assert_eq!(link.abort, Some(ERROR_RESPONSE_TIMEOUT));
}

#[test]
fn peripheral_latency_is_used_only_without_pending_work() {
    let mut link = connection();
    link.expect = Expect::Anchor;
    let shared = Shared::new();
    assert!(link.can_skip(&shared));
    link.enqueue(Llid::Control, &[OP_PING_RSP]);
    assert!(!link.can_skip(&shared));
    link.queue.fill(None);
    link.encryption.phase = Phase::Starting;
    assert!(!link.can_skip(&shared));
    link.encryption.phase = Phase::Idle;
    assert!(link.can_skip(&shared));
    link.phy_update = Some((Phy::M2, 10));
    assert!(!link.can_skip(&shared));
}

#[test]
fn window_widening_stops_at_half_the_interval_less_the_interframe_space() {
    let link = connection();
    assert_eq!(link.interval, 15_000);
    assert_eq!(link.widening(1_000_000), 1016);
    assert_eq!(link.widening(60_000_000), 7350);
}

#[test]
fn central_controls_other_than_finishing_are_refused_while_encryption_starts() {
    for phase in [Phase::Starting, Phase::AwaitingStartResponse] {
        for payload in [&[OP_PING_REQ][..], &[OP_VERSION_IND, 9, 0, 0, 0, 0][..], &[0x0A][..]] {
            let mut link = connection();
            link.encryption.phase = phase;
            link.encryption.rx_on = phase == Phase::AwaitingStartResponse;
            link.handle_control(payload, link.encryption.rx_on);
            assert_eq!(link.abort, Some(ERROR_PDU_NOT_ALLOWED));
            assert!(link.queue.iter().all(Option::is_none));
        }
        let mut link = connection();
        link.encryption.phase = phase;
        link.handle_control(&[OP_TERMINATE_IND, 0x13], false);
        assert_eq!(link.abort, None);
        assert_eq!(link.terminated, Some(0x13));
    }
}

#[test]
fn a_pdu_loaded_in_plain_is_never_sealed_with_an_unassigned_counter() {
    let mut link = connection();
    link.enqueue(Llid::Control, &[OP_PING_RSP]);
    link.load_next(&Shared::new());
    assert!(!link.encryption.tx_sealed);
    // Encryption turning on must not change how the loaded PDU is resent.
    link.encryption.tx_on = true;
    assert!(!link.encryption.tx_sealed);
    assert_eq!(link.encryption.tx_counter, 0);
    link.enqueue(Llid::Control, &[OP_START_ENC_RSP]);
    link.load_next(&Shared::new());
    assert!(link.encryption.tx_sealed);
    assert_eq!(link.encryption.tx_counter, 1);
}

/// A connection with encryption on both ways.
fn encrypted() -> Connection {
    let mut link = connection();
    link.encryption.rx_on = true;
    link.encryption.tx_on = true;
    link
}

#[test]
fn a_key_refresh_pauses_encryption_both_ways() {
    let mut link = encrypted();
    link.handle_control(&[OP_PAUSE_ENC_REQ], true);
    assert_eq!(link.abort, None);
    assert!(link.encryption.phase == Phase::Pausing);
    assert_eq!(link.queue[0].map(|queued| queued.data[0]), Some(OP_PAUSE_ENC_RSP));
    // Our pause response went out encrypted; the central answers in plain.
    link.encryption.rx_on = false;
    link.encryption.phase = Phase::AwaitingPauseResponse;
    link.handle_control(&[OP_PAUSE_ENC_RSP], false);
    assert_eq!(link.abort, None);
    assert!(!link.encryption.tx_on);
    assert!(link.encryption.phase == Phase::Paused);
    // A refresh now waits for a separate, single-use prefetched block.
}

#[test]
fn a_pause_needs_an_encrypted_request_and_a_plain_answer() {
    let mut link = encrypted();
    link.handle_control(&[OP_PAUSE_ENC_REQ], false);
    assert_eq!(link.abort, Some(ERROR_PDU_NOT_ALLOWED));
    let mut link = connection();
    link.handle_control(&[OP_PAUSE_ENC_REQ], true);
    assert_eq!(link.abort, Some(ERROR_PDU_NOT_ALLOWED));
    let mut link = encrypted();
    link.encryption.phase = Phase::AwaitingPauseResponse;
    link.handle_control(&[OP_PAUSE_ENC_RSP], true);
    assert_eq!(link.abort, Some(ERROR_PDU_NOT_ALLOWED));
    assert!(link.encryption.tx_on);
}

#[test]
fn while_paused_only_a_new_encryption_request_or_termination_is_accepted() {
    let mut link = encrypted();
    link.encryption.phase = Phase::Paused;
    link.handle_control(&[OP_FEATURE_REQ, 0, 0, 0, 0, 0, 0, 0, 0], false);
    assert_eq!(link.abort, Some(ERROR_PDU_NOT_ALLOWED));
}

#[test]
fn a_symmetric_phy_update_takes_effect_at_its_instant() {
    let mut link = encrypted();
    link.handle_control(&[OP_PHY_UPDATE_IND, 2, 2, 10, 0], true);
    assert_eq!(link.abort, None);
    assert!(link.phy_update == Some((Phy::M2, 10)));
    link.counter = 10;
    link.apply_instants(&Shared::new());
    assert!(link.phy == Phy::M2);
    assert!(link.phy_update.is_none());
}

#[test]
fn phy_updates_without_a_change_asymmetric_or_coded_are_handled() {
    let mut link = encrypted();
    link.handle_control(&[OP_PHY_UPDATE_IND, 0, 0, 10, 0], true);
    assert_eq!(link.abort, None);
    assert!(link.phy_update.is_none());
    for (to_peripheral, to_central) in [(4, 4), (3, 3)] {
        let mut link = encrypted();
        link.handle_control(&[OP_PHY_UPDATE_IND, to_peripheral, to_central, 10, 0], true);
        assert_eq!(link.abort, Some(ERROR_UNSUPPORTED_VALUE));
    }
    let mut link = encrypted();
    link.handle_control(&[OP_PHY_UPDATE_IND, 2, 2, 0, 0], true);
    assert_eq!(link.abort, Some(ERROR_INSTANT_PASSED));
}

#[test]
fn the_peripheral_asks_for_2m_once_encrypted_and_answers_a_central_request() {
    let shared = Shared::new();
    let mut link = connection();
    link.central_features = Some([0x1F, 0, 0, 0, 0, 0, 0, 0]);
    link.start_procedures(0, &shared);
    assert!(link.queue[0].is_none());
    let mut link = encrypted();
    link.central_features = Some([0x1F, 0, 0, 0, 0, 0, 0, 0]);
    link.start_procedures(0, &shared);
    assert_eq!(link.queue[0].map(|queued| queued.data[..3] == [OP_PHY_REQ, 2, 2]), Some(true));
    link.handle_control(&[OP_UNKNOWN_RSP, OP_PHY_REQ], true);
    assert!(link.phy_request == Request::Done);
    let mut link = encrypted();
    link.handle_control(&[OP_PHY_REQ, 3, 3], true);
    assert_eq!(link.queue[0].map(|queued| queued.data[..3] == [OP_PHY_RSP, 2, 2]), Some(true));
    assert!(matches!(link.phy_request, Request::Requested(_)));
}

/// A connection parameter request PDU: interval 12 to 24, latency 4,
/// timeout 600, no offsets.
fn parameter_request(code: u8) -> [u8; 24] {
    let mut pdu = [0xFF_u8; 24];
    pdu[..12].copy_from_slice(&[code, 12, 0, 24, 0, 4, 0, 0x58, 0x02, 0, 0, 0]);
    pdu
}

#[test]
fn a_central_parameter_request_is_accepted_or_rejected_when_invalid() {
    let mut link = encrypted();
    link.handle_control(&parameter_request(OP_CONNECTION_PARAM_REQ), true);
    assert_eq!(link.abort, None);
    // A host that did not enable the request event leaves it to the link
    // layer.
    link.drive_remote_request(0, &Shared::new());
    let response = link.queue[0].unwrap();
    assert_eq!(usize::from(response.len), 24);
    assert_eq!(response.data[0], OP_CONNECTION_PARAM_RSP);
    assert_eq!(response.data[1..24], parameter_request(OP_CONNECTION_PARAM_REQ)[1..]);
    let mut invalid = parameter_request(OP_CONNECTION_PARAM_REQ);
    invalid[1] = 30;
    let mut link = encrypted();
    link.handle_control(&invalid, true);
    assert_eq!(
        link.queue[0]
            .map(|queued| queued.data[..3] == [OP_REJECT_EXT_IND, OP_CONNECTION_PARAM_REQ, ERROR_INVALID_PARAMETERS]),
        Some(true)
    );
}

#[test]
fn the_host_asks_for_parameters_only_after_features_and_phy_and_learns_a_refusal() {
    let shared = Shared::new();
    let mut link = encrypted();
    link.start_procedures(0, &shared);
    assert_eq!(link.queue[0].map(|queued| queued.data[0]), Some(OP_PERIPHERAL_FEATURE_REQ));
    link.queue = [None; QUEUE_LEN];
    link.handle_control(&[OP_FEATURE_RSP, 0x1F, 1, 0, 0, 0, 0, 0, 0], true);
    assert_eq!(link.central_features, Some([0x1F, 1, 0, 0, 0, 0, 0, 0]));
    link.start_procedures(0, &shared);
    assert_eq!(link.queue[0].map(|queued| queued.data[0]), Some(OP_PHY_REQ));
    link.queue = [None; QUEUE_LEN];
    link.handle_control(&[OP_REJECT_EXT_IND, OP_PHY_REQ, 0x1A], true);
    assert!(link.phy_request == Request::Done);
    link.param_request = Some(1000);
    link.handle_control(&[OP_REJECT_EXT_IND, OP_CONNECTION_PARAM_REQ, 0x23], true);
    assert_eq!(link.param_status, Some(0x23));
    assert!(link.param_request.is_none());
}

#[test]
fn parameters_already_in_place_are_reported_without_a_procedure() {
    let shared = Shared::new();
    let mut link = encrypted();
    link.central_features = Some([0x1F, 1, 0, 0, 0, 0, 0, 0]);
    link.phy_request = Request::Done;
    let current = link.current_params();
    shared.request_params([current.interval, current.interval, current.latency, current.timeout]);
    link.start_procedures(0, &shared);
    assert!(link.queue.iter().all(Option::is_none));
    assert!(link.param_request.is_none());
    assert_eq!(link.param_status, Some(STATUS_SUCCESS));
    shared.request_params([current.interval, current.interval, current.latency.wrapping_add(1), current.timeout]);
    link.param_status = None;
    link.start_procedures(0, &shared);
    assert_eq!(link.queue[0].map(|queued| queued.data[0]), Some(OP_CONNECTION_PARAM_REQ));
}

#[test]
fn the_feature_answer_keeps_only_the_shared_first_byte() {
    let mut link = encrypted();
    link.handle_control(&[OP_FEATURE_REQ, 0x01, 0xFF, 0, 0, 0, 0, 0, 0], true);
    let response = link.queue[0].unwrap();
    assert_eq!(response.data[..3], [OP_FEATURE_RSP, 0x01, FEATURES[1]]);
}

#[test]
fn a_power_control_request_moves_the_power_and_reports_it() {
    let mut link = encrypted();
    link.handle_control(&[OP_POWER_CONTROL_REQ, 1, (-8_i8).cast_unsigned(), 0], true);
    let response = link.queue[0].unwrap();
    assert_eq!(response.data[0], OP_POWER_CONTROL_RSP);
    assert_eq!(response.data[2].cast_signed(), -8);
    assert_eq!(response.data[3].cast_signed(), -8);
    // Nothing measured yet: the acceptable reduction is unknown.
    assert_eq!(response.data[4], 0xFF);
    let mut link = encrypted();
    link.handle_control(&[OP_POWER_CONTROL_REQ, 1, 100, 0], true);
    let response = link.queue[0].unwrap();
    assert_eq!(response.data[1], 0x02);
    assert_eq!(response.data[3].cast_signed(), 4);
}

#[test]
fn power_changes_are_announced_only_to_a_central_that_supports_them() {
    let shared = Shared::new();
    let mut link = encrypted();
    link.phy_request = Request::Done;
    link.features_request = Request::Done;
    link.central_features = Some([0x1F, 0, 0, 0, 0, 0, 0, 0]);
    link.power[0].on_loss();
    link.start_procedures(0, &shared);
    assert!(link.queue[0].is_none());
    link.central_features = Some([0x1F, 0, 0, 0, 0x06, 0, 0, 0]);
    link.power_reporting = 1;
    link.start_procedures(0, &shared);
    let indication = link.queue[0].unwrap();
    assert_eq!(indication.data[..5], [OP_POWER_CHANGE_IND, 1, 0, 3, 3]);
}

#[test]
fn the_peripheral_pings_before_the_authenticated_payload_timeout() {
    let shared = Shared::new();
    let mut link = encrypted();
    link.features_request = Request::Done;
    link.phy_request = Request::Done;
    link.payload_timer = Some((0, false));
    link.start_procedures(22_000_000, &shared);
    assert!(link.queue[0].is_none());
    link.start_procedures(23_000_000, &shared);
    assert_eq!(link.queue[0].map(|queued| queued.data[0]), Some(OP_PING_REQ));
    assert_eq!(link.payload_timer, Some((0, true)));
    // The encrypted answer restarts the timer.
    assert_eq!(link.receive(Llid::Control.bits() | NESN, 5, true, 23_100_000, &shared), Some(true));
    assert_eq!(link.payload_timer, Some((23_100_000, false)));
    link.queue = [None; QUEUE_LEN];
    link.start_procedures(53_200_000, &shared);
    assert_eq!(link.payload_timer, Some((53_200_000, false)));
}

#[test]
fn an_unanswered_ping_ends_the_link_after_the_procedure_timeout() {
    let shared = Shared::new();
    let mut link = encrypted();
    link.features_request = Request::Done;
    link.phy_request = Request::Done;
    link.payload_timer = Some((0, false));
    link.start_procedures(23_000_000, &shared);
    assert_eq!(link.queue[0].map(|queued| queued.data[0]), Some(OP_PING_REQ));
    // Other authenticated traffic does not answer the ping, and no second
    // ping starts while it runs.
    assert_eq!(link.receive(Llid::Control.bits() | NESN, 5, true, 23_100_000, &shared), Some(true));
    link.queue = [None; QUEUE_LEN];
    link.start_procedures(46_000_000, &shared);
    assert!(link.queue[0].is_none());
    assert!(link.abort.is_none());
    link.start_procedures(63_000_000, &shared);
    assert_eq!(link.abort, Some(ERROR_RESPONSE_TIMEOUT));
}

#[test]
fn a_ping_response_ends_the_ping_procedure() {
    let shared = Shared::new();
    let mut link = encrypted();
    link.ping_request = Some(1000);
    link.handle_control(&[OP_PING_RSP], true);
    assert!(link.ping_request.is_none());
    link.ping_request = Some(1000);
    link.handle_rejection(OP_UNKNOWN_RSP, &[OP_PING_REQ]);
    assert!(link.ping_request.is_none());
    link.start_procedures(2000, &shared);
    assert!(link.abort.is_none());
}

#[test]
fn an_expired_payload_timeout_waits_for_room_in_the_event_queue() {
    let shared = Shared::with_all_events();
    let mut link = encrypted();
    link.payload_timer = Some((0, true));
    while shared.try_push_event(Packet::completed_packets(1)) {}
    link.start_procedures(31_000_000, &shared);
    assert!(link.notifications.iter().flatten().any(Packet::is_payload_timeout));
    // It is not queued twice while it waits.
    link.payload_timer = Some((0, true));
    link.start_procedures(62_000_000, &shared);
    assert_eq!(link.notifications.iter().flatten().filter(|event| event.is_payload_timeout()).count(), 1);
}

#[test]
fn data_while_encryption_starts_or_pauses_ends_the_link_unacknowledged() {
    let phases = [
        Phase::AwaitingEntropy { rand: [0; 8], ediv: [0; 2] },
        Phase::AwaitingKey { requested: true, rand: [0; 8], ediv: [0; 2] },
        Phase::Starting,
        Phase::AwaitingStartResponse,
        Phase::Pausing,
        Phase::AwaitingPauseResponse,
        Phase::Paused,
    ];
    for phase in phases {
        for llid in [Llid::Start, Llid::Continuation] {
            let mut link = connection();
            link.encryption.phase = phase;
            assert_eq!(link.receive(llid.bits(), 5, true, 999, &Shared::new()), None);
            assert_eq!(link.abort, Some(ERROR_MIC_FAILURE));
            assert!(!link.nesn && !link.received);
        }
        // Empty PDUs and control PDUs keep the procedure going.
        let mut link = connection();
        link.encryption.phase = phase;
        assert_eq!(link.receive(Llid::Continuation.bits(), 0, true, 999, &Shared::new()), Some(true));
        let mut link = connection();
        link.encryption.phase = phase;
        assert_eq!(link.receive(Llid::Control.bits(), 1, true, 999, &Shared::new()), Some(true));
        assert_eq!(link.abort, None);
    }
}

#[test]
fn a_parameter_request_during_another_instant_is_a_transaction_collision() {
    let mut link = encrypted();
    link.phy_update = Some((Phy::M2, 10));
    link.next_tx_phy = Phy::M2;
    link.handle_control(&parameter_request(OP_CONNECTION_PARAM_REQ), true);
    assert_eq!(
        link.queue[0].map(|queued| queued.data[..3] == [OP_REJECT_EXT_IND, OP_CONNECTION_PARAM_REQ, 0x2A]),
        Some(true)
    );
}

/// A connection update PDU to `interval` with the current latency and
/// timeout at instant 10.
fn update_to(interval: u8) -> [u8; 12] { [OP_CONNECTION_UPDATE_IND, 1, 0, 0, interval, 0, 0, 0, 0x58, 2, 10, 0] }

/// Applies the update due at instant 10 and returns how many events the
/// host got.
fn events_at_instant(link: &mut Connection) -> usize {
    let shared = Shared::with_all_events();
    link.counter = 10;
    link.apply_instants(&shared);
    let mut count = 0;
    while shared.try_push_event(Packet::completed_packets(1)) {
        count += 1;
    }
    4 - count
}

#[test]
fn the_host_learns_of_updates_that_change_something_or_that_it_asked_for() {
    let mut link = encrypted();
    link.handle_control(&update_to(24), true);
    assert_eq!(link.abort, None);
    assert_eq!(events_at_instant(&mut link), 1);
    assert_eq!(link.interval, 24 * UNIT_1250_US);
    // The same parameters again: only the anchor moves.
    let mut link = encrypted();
    link.handle_control(&update_to(12), true);
    assert_eq!(events_at_instant(&mut link), 0);
    // Unless they answer the host's request.
    let mut link = encrypted();
    link.param_request = Some(1000);
    link.handle_control(&update_to(12), true);
    assert!(link.param_request.is_none());
    assert_eq!(events_at_instant(&mut link), 1);
}

#[test]
fn a_phy_update_to_the_current_phy_changes_nothing() {
    let mut link = encrypted();
    link.handle_control(&[OP_PHY_UPDATE_IND, 1, 1, 10, 0], true);
    assert_eq!(link.abort, None);
    assert!(link.phy_update.is_none());
}

#[test]
fn the_host_parameter_request_goes_out_on_a_link_that_is_never_encrypted() {
    let shared = Shared::new();
    let mut link = connection();
    link.central_features = Some([0x1F, 0, 0, 0, 0, 0, 0, 0]);
    shared.request_params([24, 40, 0, 600]);
    link.start_procedures(0, &shared);
    assert_eq!(link.queue[0].map(|queued| queued.data[0]), Some(OP_CONNECTION_PARAM_REQ));
    assert!(link.param_request.is_some());
    // Features and the PHY still wait for encryption.
    assert!(link.features_request == Request::NotStarted && link.phy_request == Request::NotStarted);
}

#[test]
fn a_finished_link_leaves_no_key_material_behind() {
    let mut link = encrypted();
    link.encryption.rx_config = [0xA5; CONFIG_LEN];
    link.encryption.tx_config = [0x5A; CONFIG_LEN];
    link.encryption.skd = [1; 16];
    link.encryption.iv = [2; 8];
    link.encryption.scratch = [3; SCRATCH_LEN];
    link.encryption.wipe();
    assert_eq!(link.encryption.rx_config, [0; CONFIG_LEN]);
    assert_eq!(link.encryption.tx_config, [0; CONFIG_LEN]);
    assert_eq!(link.encryption.skd, [0; 16]);
    assert_eq!(link.encryption.iv, [0; 8]);
    assert!(link.encryption.scratch.iter().all(|&byte| byte == 0));
}

#[test]
fn plain_duplicate_can_acknowledge_tx_without_delivering_rx_twice() {
    let mut link = connection();
    link.nesn = true;
    link.tx_kind = TxKind::Acl;
    assert_eq!(link.receive(Llid::Start.bits() | NESN, 1, true, 999, &Shared::new()), Some(false));
    assert!(link.sn && link.nesn && !link.received);
    assert_eq!(link.completed, 1);
}

#[test]
fn asymmetric_phy_update_keeps_both_directions_and_unchanged_fields() {
    for (receive, transmit) in [(1, 2), (2, 1)] {
        let mut link = connection();
        link.handle_control(&[OP_PHY_UPDATE_IND, receive, transmit, 10, 0], false);
        assert_eq!(link.abort, None);
        link.counter = 10;
        link.apply_instants(&Shared::new());
        assert_eq!(link.phy.hci(), receive);
        assert_eq!(link.tx_phy.hci(), transmit);
        link.handle_control(&[OP_PHY_UPDATE_IND, 0, 0, 20, 0], false);
        assert_eq!(link.phy.hci(), receive);
        assert_eq!(link.tx_phy.hci(), transmit);
    }
}

#[test]
fn host_notifications_survive_queue_pressure() {
    let full = Shared::with_all_events();
    for _ in 0..4 {
        assert!(full.try_push_event(Packet::completed_packets(1)));
    }
    let mut link = connection();
    link.notify(
        Packet::connection_complete(0, (crate::pdu::Peer::new([1; 6], false), None), link.current_params(), 0),
        &full,
    );
    link.handle_control(&[OP_PHY_UPDATE_IND, 2, 2, 10, 0], false);
    assert_eq!(link.abort, None);
    link.counter = 10;
    link.apply_instants(&full);
    assert_eq!(link.notifications.iter().flatten().count(), 2);
    let available = Shared::with_all_events();
    link.flush_notifications(&available);
    assert!(link.notifications.iter().all(Option::is_none));
    for _ in 0..2 {
        assert!(available.try_push_event(Packet::completed_packets(1)));
    }
    assert!(!available.try_push_event(Packet::completed_packets(1)));
}

#[test]
fn power_requests_validate_phy_round_up_and_keep_independent_levels() {
    for phy in [0, 3, 4, 8, 255] {
        let mut link = connection();
        link.handle_control(&[OP_POWER_CONTROL_REQ, phy, 0, 0], false);
        assert_eq!(link.queue[0].unwrap().data[..3], [
            OP_REJECT_EXT_IND,
            OP_POWER_CONTROL_REQ,
            ERROR_UNSUPPORTED_VALUE
        ]);
    }
    let mut link = connection();
    link.handle_control(&[OP_POWER_CONTROL_REQ, 1, 0, 126], false);
    assert_eq!(link.queue[0].unwrap().data[2], ERROR_INVALID_PARAMETERS);
    link.queue = [None; QUEUE_LEN];
    link.handle_control(&[OP_POWER_CONTROL_REQ, 2, (-6_i8).cast_unsigned(), 0], false);
    assert_eq!(tx_power(link.power[0].level()), 0);
    assert_eq!(tx_power(link.power[1].level()), -4);
    link.queue = [None; QUEUE_LEN];
    link.handle_control(&[OP_POWER_CONTROL_REQ, 2, 0x7F, 0], false);
    assert_eq!(tx_power(link.power[1].level()), 4);
}

#[test]
fn host_remote_queries_work_without_encryption_and_version_is_sent_once() {
    let shared = Shared::with_all_events();
    let mut link = connection();
    shared.request_queries(3);
    link.service_queries(0, &shared);
    assert_eq!(link.queue[0].unwrap().data[0], OP_VERSION_IND);
    link.queue = [None; QUEUE_LEN];
    link.start_procedures(0, &shared);
    assert_eq!(link.queue[0].unwrap().data[0], OP_PERIPHERAL_FEATURE_REQ);
    link.queue = [None; QUEUE_LEN];
    link.handle_control(&[OP_VERSION_IND, 11, 1, 2, 3, 4], false);
    assert!(link.queue.iter().all(Option::is_none));
    link.handle_control(&[OP_FEATURE_RSP, 31, 1, 0, 0, 0, 0, 0, 0], false);
    link.service_queries(10, &shared);
    assert_eq!(link.host_queries, 0);
    for _ in 0..2 {
        assert!(shared.try_push_event(Packet::completed_packets(1)));
    }
    assert!(!shared.try_push_event(Packet::completed_packets(1)));
}

#[test]
fn host_phy_request_completes_even_when_the_central_keeps_the_current_phy() {
    let shared = Shared::with_all_events();
    let mut link = connection();
    link.host_phy = Some([1, 2]);
    link.preferred_phys = [1, 2];
    link.start_procedures(0, &shared);
    assert_eq!(link.queue[0].unwrap().data[..3], [OP_PHY_REQ, 1, 2]);
    link.queue = [None; QUEUE_LEN];
    link.handle_control(&[OP_PHY_UPDATE_IND, 0, 0, 0, 0], false);
    assert_eq!(link.phy_status, Some(0));
    link.service_queries(1, &shared);
    assert!(link.host_phy.is_none());
    assert!(link.phy_status.is_none());
    for _ in 0..3 {
        assert!(shared.try_push_event(Packet::completed_packets(1)));
    }
    assert!(!shared.try_push_event(Packet::completed_packets(1)));
}

#[test]
fn encryption_waits_without_rng_work_and_builds_the_prefetched_response() {
    use core::{
        future::Future,
        pin::pin,
        task::{Context, Waker},
    };
    let shared = Shared::with_all_events();
    shared.set_connected(true);
    let prefetch = Prefetch::new();
    let mut link = connection();
    let mut request = [0x11; 23];
    request[0] = OP_ENC_REQ;
    link.handle_control(&request, false);
    assert!(matches!(link.encryption.phase, Phase::AwaitingEntropy { .. }));
    for _ in 0..5 {
        link.drive_encryption(&shared, &prefetch);
        assert!(link.queue.iter().all(Option::is_none));
        assert_eq!(link.abort, None);
    }
    // Radio keepalives remain valid while the separate producer is pending.
    assert_eq!(link.receive(Llid::Continuation.bits(), 0, true, 200, &shared), Some(true));
    let mut worker = pin!(prefetch.run_with(async |bytes: &mut [u8]| bytes.fill(0x22)));
    assert!(worker.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
    link.drive_encryption(&shared, &prefetch);
    assert!(
        matches!(link.encryption.phase, Phase::AwaitingKey { rand, ediv, .. } if rand == [0x11; 8] && ediv == [0x11; 2])
    );
    let response = link.queue[0].unwrap();
    assert_eq!(response.data[0], OP_ENC_RSP);
    assert_eq!(&response.data[1..13], &[0x22; 12]);
    assert_eq!(&link.encryption.skd[..8], &[0x11; 8]);
    assert_eq!(&link.encryption.skd[8..], &[0x22; 8]);
    assert_eq!(&link.encryption.iv[..4], &[0x11; 4]);
    assert_eq!(&link.encryption.iv[4..], &[0x22; 4]);
    assert!(prefetch.take().is_none());
}

#[test]
fn encryption_refresh_consumes_a_different_prefetched_block() {
    use core::{
        cell::Cell,
        future::Future,
        pin::pin,
        task::{Context, Waker},
    };
    let shared = Shared::new();
    let prefetch = Prefetch::new();
    let produced = Cell::new(0_u8);
    let mut worker = pin!(prefetch.run_with(async |bytes: &mut [u8]| {
        produced.set(produced.get() + 1);
        bytes.fill(produced.get());
    }));
    let mut context = Context::from_waker(Waker::noop());
    let mut link = connection();
    let mut request = [0x11; 23];
    request[0] = OP_ENC_REQ;
    assert!(worker.as_mut().poll(&mut context).is_pending());
    link.handle_control(&request, false);
    link.drive_encryption(&shared, &prefetch);
    assert_eq!(&link.queue[0].unwrap().data[1..13], &[1; 12]);
    assert!(worker.as_mut().poll(&mut context).is_pending());
    // Model the encrypted link after its pause handshake completed.
    link.encryption.phase = Phase::Paused;
    link.encryption.rx_on = false;
    link.encryption.tx_on = false;
    link.queue = [None; QUEUE_LEN];
    link.handle_control(&request, false);
    assert!(link.encryption.procedure == Procedure::Refresh);
    link.drive_encryption(&shared, &prefetch);
    assert_eq!(&link.queue[0].unwrap().data[1..13], &[2; 12]);
    assert_eq!(&link.encryption.iv[4..], &[2; 4]);
    assert!(prefetch.take().is_none());
}

#[test]
fn entropy_wait_preserves_response_deadline_and_accepts_termination() {
    let mut request = [0x11; 23];
    request[0] = OP_ENC_REQ;
    let mut link = connection();
    link.handle_control(&request, false);
    let deadline = link.procedure_deadline.unwrap();
    link.last_valid = deadline - 1;
    assert!(matches!(link.ended(deadline), Some(Ended::Error(ERROR_RESPONSE_TIMEOUT))));
    let mut link = connection();
    link.handle_control(&request, false);
    link.handle_control(&[OP_TERMINATE_IND, 0x13], false);
    assert!(matches!(link.ended(101), Some(Ended::Terminated(0x13))));
    assert!(link.queue.iter().all(Option::is_none));
}

#[test]
fn packets_of_one_event_wait_and_are_processed_in_order_after_it() {
    let shared = Shared::new();
    let mut link = connection();
    let mut rx = [0; BUFFER_LEN];
    let packets: [(u8, &[u8]); 3] =
        [(Llid::Start.bits(), &[0xA1]), (Llid::Start.bits() | SN, &[0xA2]), (Llid::Control.bits(), &[OP_PING_REQ])];
    for (header, payload) in packets {
        rx[0] = header;
        rx[1] = u8::try_from(payload.len()).unwrap();
        rx[DATA_HEADER_LEN..DATA_HEADER_LEN + payload.len()].copy_from_slice(payload);
        assert_eq!(link.receive(header, rx[1], true, 999, &shared), Some(true));
        assert!(link.received);
        link.stash(&rx, false);
    }
    // The host has room for two packets, both taken by the waiting ones:
    // the next data packet is not acknowledged and comes again.
    let nesn = link.nesn;
    assert_eq!(link.receive(Llid::Start.bits() | SN, 1, true, 999, &shared), Some(true));
    assert!(!link.received);
    assert_eq!(link.nesn, nesn);
    // Empty packets need no room.
    link.nesn = !link.nesn;
    assert_eq!(link.receive(Llid::Continuation.bits(), 0, true, 999, &shared), Some(true));
    assert!(link.received);
    rx[0] = Llid::Continuation.bits();
    rx[1] = 0;
    link.stash(&rx, false);
    assert_eq!(shared.acl_room(), 2);
    link.process(&rx, false, &shared);
    assert_eq!(shared.take_acl_in().map(|bytes| bytes[4]), Some(0xA1));
    assert_eq!(shared.take_acl_in().map(|bytes| bytes[4]), Some(0xA2));
    assert_eq!(link.queue[0].map(|queued| queued.data[0]), Some(OP_PING_RSP));
    assert_eq!(link.stats.received, 4);
    assert!(link.pending.iter().all(Option::is_none));
}

#[test]
fn a_stashed_encrypted_packet_uses_its_counter_before_the_next_is_decrypted() {
    let shared = Shared::new();
    let mut link = connection();
    link.encryption.rx_on = true;
    let mut rx = [0; BUFFER_LEN];
    rx[0] = Llid::Start.bits();
    rx[1] = 5;
    link.rx_plain[..4].copy_from_slice(&[Llid::Start.bits(), 1, 0, 0x42]);
    assert_eq!(link.receive(rx[0], 5, true, 999, &shared), Some(true));
    link.stash(&rx, true);
    assert_eq!(link.encryption.rx_counter, 1);
    assert_eq!(link.pending[0].map(|packet| packet.bytes[3]), Some(0x42));
}

#[test]
fn an_event_continues_only_while_another_exchange_fits_before_the_next() {
    let mut link = connection();
    // 27 octets without a MIC; the S1 byte in RAM is counted as well,
    // which errs on the long side.
    assert_eq!(link.exchange_us(), 3 * (40 + 33 * 8) + 450);
    link.phy = Phy::M2;
    link.tx_phy = Phy::M2;
    assert_eq!(link.exchange_us(), 3 * (24 + 33 * 4) + 450);
    // 251 octets with a MIC each way.
    link.length = DataLength::new(LENGTH_MAX);
    link.length.announced_tx = LENGTH_MAX;
    link.length.take_peer(&[251, 0, 0x48, 0x08, 251, 0, 0x48, 0x08]);
    link.encryption.tx_on = true;
    link.encryption.rx_on = true;
    assert_eq!(link.exchange_us(), 3 * (24 + 261 * 4) + 450);
    link.phy = Phy::M1;
    // Interval, widening, address, ramp-up, margin and processing time.
    assert_eq!(link.close_by(0), 15_000 - 31 - 40 - 40 - 30 - 500);
}

#[test]
fn a_host_that_enabled_the_event_decides_on_a_central_parameter_request() {
    let shared = Shared::with_all_events();
    shared.set_connected(true);
    let mut link = encrypted();
    link.handle_control(&parameter_request(OP_CONNECTION_PARAM_REQ), true);
    link.drive_remote_request(0, &shared);
    assert!(link.queue[0].is_none());
    assert!(link.notifications.iter().all(Option::is_none));
    let hci = crate::hci::Hci::new(&shared);
    // The host offers 30 to 40 units, latency 2 and timeout 800.
    let reply = [0, 0, 30, 0, 40, 0, 2, 0, 0x20, 0x03, 0, 0, 0, 0];
    assert_eq!(hci.reply_parameters(0x2020, &reply), 0);
    assert_eq!(hci.reply_parameters(0x2021, &[0, 0, 0x3B]), 0x0C);
    link.drive_remote_request(1000, &shared);
    let response = link.queue[0].unwrap();
    assert_eq!(response.data[..9], [OP_CONNECTION_PARAM_RSP, 30, 0, 40, 0, 2, 0, 0x20, 0x03]);
    assert_eq!(response.data[9..24], parameter_request(OP_CONNECTION_PARAM_REQ)[9..]);
    assert!(link.remote_request.is_none());
}

#[test]
fn a_host_that_does_not_answer_has_the_request_rejected() {
    let shared = Shared::with_all_events();
    let mut link = encrypted();
    link.handle_control(&parameter_request(OP_CONNECTION_PARAM_REQ), true);
    link.drive_remote_request(0, &shared);
    link.drive_remote_request(HOST_REPLY_US - 1, &shared);
    assert!(link.queue[0].is_none());
    link.drive_remote_request(HOST_REPLY_US, &shared);
    assert_eq!(
        link.queue[0].map(|queued| queued.data[..3] == [OP_REJECT_EXT_IND, OP_CONNECTION_PARAM_REQ, 0x3B]),
        Some(true)
    );
}

#[test]
fn the_data_length_follows_both_sides_and_the_time_on_the_air() {
    let shared = Shared::with_all_events();
    let mut link = connection();
    assert_eq!(link.tx_payload_max(), 27);
    // The central receives and sends 251 octets in 2120 us.
    link.handle_control(&[OP_LENGTH_REQ, 251, 0, 0x48, 0x08, 251, 0, 0x48, 0x08], false);
    let response = link.queue[0].unwrap();
    // We receive 251 octets but send only what the host allowed so far.
    assert_eq!(response.data[..9], [OP_LENGTH_RSP, 251, 0, 0x48, 0x08, 27, 0, 0x48, 0x01]);
    assert_eq!(link.length.effective(), [27, 328, 251, 2120]);
    link.drive_length(&shared);
    assert_eq!(link.length.reported, [27, 328, 251, 2120]);
    assert!(link.notifications.iter().all(Option::is_none));
    // Our response is acknowledged: the central knows we send 27 octets.
    link.length.offer_taken();
    // The host lets the link send 251 octets. Nothing longer goes out until
    // the central has been told, and has answered.
    shared.set_connected(true);
    assert_eq!(crate::hci::Hci::new(&shared).set_data_length(&[0, 0, 251, 0, 0x48, 0x08]), 0);
    link.drive_length(&shared);
    assert_eq!(link.length.local_tx, LENGTH_MAX);
    assert_eq!(link.tx_payload_max(), 27);
    let request = link.length.pdu(OP_LENGTH_REQ);
    assert_eq!(request, [OP_LENGTH_REQ, 251, 0, 0x48, 0x08, 251, 0, 0x48, 0x08]);
    assert_eq!(link.tx_payload_max(), 27);
    link.handle_control(&[OP_LENGTH_RSP, 251, 0, 0x48, 0x08, 251, 0, 0x48, 0x08], false);
    assert_eq!(link.tx_payload_max(), 251);
    // A host that lowers the length takes effect at once.
    link.length.local_tx = [100, 2120];
    assert_eq!(link.tx_payload_max(), 100);
    link.length.local_tx = LENGTH_MAX;
    // Encrypted on LE 1M, 2120 us still hold 251 octets with the MIC; a
    // central that receives in 1000 us gets at most 107.
    link.encryption.tx_on = true;
    assert_eq!(link.tx_payload_max(), 251);
    link.length.take_peer(&[251, 0, 0xE8, 0x03, 251, 0, 0x48, 0x08]);
    assert_eq!(link.tx_payload_max(), 1000 / 8 - 10 - 4);
    // On LE 2M the same time holds twice the octets, less the overhead.
    link.tx_phy = Phy::M2;
    assert_eq!(link.tx_payload_max(), 1000 / 4 - 11 - 4);
}

#[test]
fn host_data_is_sent_in_fragments_the_central_receives() {
    let shared = Shared::new();
    shared.set_connected(true);
    let mut link = connection();
    let mut data = [0; ACL_MAX];
    for (index, byte) in data.iter_mut().enumerate() {
        *byte = u8::try_from(index).unwrap();
    }
    assert!(shared.queue_acl_for_test(&data[..60]));
    link.load_next(&shared);
    assert!(link.tx_kind == TxKind::AclPart);
    assert_eq!(link.tx[..3], [Llid::Start.bits(), 27, 0]);
    assert_eq!(link.tx[3..30], data[..27]);
    link.load_next(&shared);
    assert!(link.tx_kind == TxKind::AclPart);
    assert_eq!(link.tx[..3], [Llid::Continuation.bits(), 27, 0]);
    assert_eq!(link.tx[3..30], data[27..54]);
    link.load_next(&shared);
    assert!(link.tx_kind == TxKind::Acl);
    assert_eq!(link.tx[..3], [Llid::Continuation.bits(), 6, 0]);
    assert_eq!(link.tx[3..9], data[54..60]);
    // Only the last fragment completes the host's packet.
    link.tx_kind = TxKind::AclPart;
    assert_eq!(link.acknowledge(NESN, &shared), Some(()));
    assert_eq!(link.completed, 0);
}

#[test]
fn the_link_asks_for_a_longer_data_length_only_when_the_host_allows_it() {
    let shared = Shared::new();
    let mut link = encrypted();
    link.features_request = Request::Done;
    link.phy_request = Request::Done;
    link.central_features = Some([0x3F, 0, 0, 0, 0, 0, 0, 0]);
    link.start_procedures(0, &shared);
    assert!(link.queue[0].is_none());
    link.length.local_tx = LENGTH_MAX;
    link.start_procedures(0, &shared);
    assert_eq!(
        link.queue[0].map(|queued| queued.data[..9] == [OP_LENGTH_REQ, 251, 0, 0x48, 0x08, 251, 0, 0x48, 0x08]),
        Some(true)
    );
    assert!(matches!(link.length_request, Request::Requested(_)));
    link.handle_control(&[OP_LENGTH_RSP, 251, 0, 0x48, 0x08, 251, 0, 0x48, 0x08], true);
    assert!(link.length_request == Request::Done);
    assert_eq!(link.length.effective(), [251, 2120, 251, 2120]);
}

#[test]
fn a_length_response_takes_effect_once_acknowledged_and_an_unknown_one_ends_the_attempts() {
    let shared = Shared::new();
    let mut link = connection();
    link.length = DataLength::new(LENGTH_MAX);
    link.handle_control(&[OP_LENGTH_REQ, 251, 0, 0x48, 0x08, 251, 0, 0x48, 0x08], false);
    link.queue = [None; QUEUE_LEN];
    assert_eq!(link.tx_payload_max(), 27);
    link.tx[DATA_HEADER_LEN] = OP_LENGTH_RSP;
    link.tx_kind = TxKind::Control;
    assert_eq!(link.acknowledge(NESN, &shared), Some(()));
    assert_eq!(link.tx_payload_max(), 251);
    // A central that does not know the procedure is not asked again.
    let mut link = encrypted();
    link.features_request = Request::Done;
    link.phy_request = Request::Done;
    link.length.local_tx = LENGTH_MAX;
    link.start_procedures(0, &shared);
    assert_eq!(link.queue[0].map(|queued| queued.data[0]), Some(OP_LENGTH_REQ));
    link.queue = [None; QUEUE_LEN];
    link.handle_rejection(OP_UNKNOWN_RSP, &[OP_LENGTH_REQ]);
    link.start_procedures(0, &shared);
    assert!(link.queue[0].is_none());
    assert_eq!(link.tx_payload_max(), 27);
}

#[test]
fn a_partly_sent_host_packet_keeps_the_event_open_and_latency_off() {
    let shared = Shared::new();
    shared.set_connected(true);
    let mut link = connection();
    link.expect = Expect::Anchor;
    assert!(shared.queue_acl_for_test(&[7; 60]));
    link.load_next(&shared);
    assert!(link.tx_kind == TxKind::AclPart);
    assert!(!shared.has_acl_out());
    link.tx_kind = TxKind::Empty;
    assert!(!link.can_skip(&shared));
}

#[test]
fn an_answered_central_parameter_request_holds_own_procedures_until_its_update() {
    let shared = Shared::new();
    let mut link = encrypted();
    link.features_request = Request::Done;
    link.handle_control(&parameter_request(OP_CONNECTION_PARAM_REQ), true);
    link.drive_remote_request(0, &shared);
    assert_eq!(link.queue[0].map(|queued| queued.data[0]), Some(OP_CONNECTION_PARAM_RSP));
    link.queue = [None; QUEUE_LEN];
    // The PHY request waits for the central's update.
    link.start_procedures(1000, &shared);
    assert!(link.queue[0].is_none());
    // A central that never sends it ends the link like any procedure.
    link.start_procedures(PROCEDURE_TIMEOUT_US, &shared);
    assert_eq!(link.abort, Some(ERROR_RESPONSE_TIMEOUT));
}

#[test]
fn a_central_rejecting_our_parameter_response_ends_its_procedure() {
    let shared = Shared::new();
    let mut link = encrypted();
    link.features_request = Request::Done;
    link.handle_control(&parameter_request(OP_CONNECTION_PARAM_REQ), true);
    link.drive_remote_request(0, &shared);
    assert!(link.remote_update.is_some());
    link.handle_control(&[OP_REJECT_EXT_IND, OP_CONNECTION_PARAM_RSP, ERROR_INVALID_PARAMETERS], true);
    assert!(link.remote_update.is_none());
    link.queue = [None; QUEUE_LEN];
    link.start_procedures(PROCEDURE_TIMEOUT_US, &shared);
    assert_eq!(link.abort, None);
    assert_eq!(link.queue[0].map(|queued| queued.data[0]), Some(OP_PHY_REQ));
}

#[test]
fn a_host_update_sent_with_the_answer_completes_once_the_central_update_is_in_place() {
    let shared = Shared::with_all_events();
    shared.set_connected(true);
    let hci = crate::hci::Hci::new(&shared);
    let mut link = encrypted();
    link.features_request = Request::Done;
    link.phy_request = Request::Done;
    link.handle_control(&parameter_request(OP_CONNECTION_PARAM_REQ), true);
    link.drive_remote_request(0, &shared);
    // TrouBLE's accept: LE Connection Update for the central's range, then
    // the reply. The central's periodicity is not repeated.
    assert_eq!(hci.command_async(0x2013, &[0, 0, 12, 0, 24, 0, 4, 0, 0x58, 0x02, 0, 0, 0, 0]), 0);
    assert_eq!(hci.reply_parameters(0x2020, &[0, 0, 12, 0, 24, 0, 4, 0, 0x58, 0x02, 0, 0, 0, 0]), 0);
    link.drive_remote_request(10, &shared);
    let response = link.queue[0].unwrap();
    assert_eq!(response.data[..10], [OP_CONNECTION_PARAM_RSP, 12, 0, 24, 0, 4, 0, 0x58, 0x02, 0]);
    link.queue = [None; QUEUE_LEN];
    // Nothing of ours starts while the central's update is pending.
    link.start_procedures(20, &shared);
    assert!(link.queue[0].is_none());
    // The central's update arrives: interval 15 ms, latency 4, timeout 6 s.
    link.remote_update = None;
    link.interval = 12 * UNIT_1250_US;
    link.latency = 4;
    link.timeout = 600 * UNIT_10MS_US;
    link.start_procedures(30, &shared);
    assert!(link.queue[0].is_none());
    assert_eq!(link.param_status, Some(STATUS_SUCCESS));
}
