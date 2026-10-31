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
    for (header, len, encrypted) in [(0, 1, false), (2, 0, false), (3, 0, true), (2, 28, false), (2, 32, true)] {
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
