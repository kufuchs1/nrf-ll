//! The link layer task: advertises as the host configured it and runs the
//! resulting connection.

use crate::{
    advertiser::legacy::{self, Kind, Settings},
    clock::Clock,
    connection::{Connection, Ended},
    hci::{ConnectionParams, Packet, Shared, random},
    log::info,
    pdu::BUFFER_LEN,
    radio::Radio,
};
use embassy_futures::select::select;
use embassy_time::{Duration, Instant};

/// Upper bound of the random delay added to each advertising interval.
const ADV_DELAY_MAX_US: u32 = 10_000;
/// Duration of high duty cycle directed advertising.
const HIGH_DUTY_DURATION: Duration = Duration::from_millis(1280);
/// Interval of high duty cycle directed advertising events.
const HIGH_DUTY_INTERVAL_US: u32 = 3750;
/// Disconnection reason: connection timeout.
const REASON_TIMEOUT: u8 = 0x08;
/// Disconnection reason: connection terminated by local host.
const REASON_LOCAL_HOST: u8 = 0x16;
/// Status: success.
const STATUS_SUCCESS: u8 = 0x00;

/// Ends high duty cycle directed advertising after its time. `since` is
/// when the advertising was enabled. Returns true if it ended.
async fn check_limits(settings: &Settings, since: &mut Option<Instant>, shared: &Shared) -> bool {
    let started = *since.get_or_insert_with(Instant::now);
    if settings.kind != Kind::DirectedHighDuty || started.elapsed() < HIGH_DUTY_DURATION {
        return false;
    }
    *since = None;
    shared.stop_advertising();
    shared.push_event(Packet::advertising_timeout()).await;
    true
}

/// Time until the next advertising event.
fn interval(settings: &Settings) -> u32 {
    if settings.kind == Kind::DirectedHighDuty {
        return HIGH_DUTY_INTERVAL_US;
    }
    let mut jitter = [0_u8; 2];
    random(&mut jitter);
    settings.interval.saturating_add(u32::from(u16::from_le_bytes(jitter)).checked_rem(ADV_DELAY_MAX_US).unwrap_or(0))
}

/// Runs the link layer forever.
#[inline]
pub async fn run(radio: &mut Radio<'_>, clock: &mut Clock<'_>, shared: &Shared) -> ! {
    let mut rx = [0_u8; BUFFER_LEN];
    let mut since = None;
    loop {
        crate::health::checkpoint(15);
        crate::maintenance::service(clock, radio).await;
        crate::health::checkpoint(15);
        let Some(settings) = shared.advertising() else {
            since = None;
            clock.pause();
            crate::health::suspend();
            select(shared.changed(), crate::maintenance::requested()).await;
            continue;
        };
        if check_limits(&settings, &mut since, shared).await {
            continue;
        }
        clock.resume_now().await;
        let (primary, scan_response) = settings.pdus();
        let Some((request, end)) = legacy::event(radio, clock, &settings, (&primary, &scan_response), &mut rx) else {
            let next = clock.now().wrapping_add(interval(&settings));
            if !clock.sleep_until(next, shared.changed()).await {
                since = None;
            }
            continue;
        };
        shared.set_connected(true);
        radio.set_access_address(request.access_address);
        radio.set_crc_init(request.crc_init);
        let mut connection = Connection::new(&request, end);
        let central = request.central();
        let mut shown = central.address;
        shown.reverse();
        info!("central {=[u8; 6]:02X} random {}", shown, central.random);
        let params = ConnectionParams::new(request.interval, request.latency, request.timeout);
        let local = (settings.own != settings.address).then_some(settings.own.address);
        _ = shared.try_push_event(Packet::connection_complete(
            STATUS_SUCCESS,
            (request.central(), local),
            params,
            request.sca,
        ));
        since = None;
        let (ended, stats) = connection.run(radio, clock, &mut rx, shared).await;
        info!(
            "connection ended: {} events, {} missed, {} crc errors, {} packets",
            stats.events, stats.missed, stats.crc_errors, stats.received
        );
        let reason = match ended {
            Ended::Error(code) | Ended::Terminated(code) => code,
            Ended::Local(_) => REASON_LOCAL_HOST,
            Ended::Lost => REASON_TIMEOUT,
        };
        shared.set_connected(false);
        shared.push_event(Packet::disconnection_complete(reason)).await;
    }
}
