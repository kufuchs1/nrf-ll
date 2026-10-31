//! The link layer task: advertises as the host configured it and runs the
//! resulting connection.

use crate::{
    advertiser::legacy::{self, Kind, Settings},
    clock::{Clock, SETUP_US},
    connection::{Connection, Ended},
    hci::{ConnectionParams, Packet, Shared},
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
    if matches!(
        select(shared.push_event(Packet::advertising_timeout()), shared.reset_requested()).await,
        embassy_futures::select::Either::Second(())
    ) {
        shared.signal_reset();
    }
    true
}

/// Time until the next advertising event. The random delay comes from the
/// RNG interrupt while other tasks run.
async fn interval(settings: &Settings) -> u32 {
    if settings.kind == Kind::DirectedHighDuty {
        return HIGH_DUTY_INTERVAL_US;
    }
    let mut jitter = [0_u8; 2];
    crate::rng::fill_async(&mut jitter).await;
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
        if shared.take_reset() {
            radio.disable();
            clock.pause();
            shared.complete_reset();
        }
        shared.refresh_private_address();
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
        let started = clock.now();
        let Some((request, end)) = legacy::event(radio, clock, &settings, (&primary, &scan_response), &mut rx) else {
            let next = started.wrapping_add(interval(&settings).await);
            // The sleep returns `SETUP_US` early, for a radio start the timer
            // triggers; advertising starts when it returns, so it sleeps that
            // much longer to keep the advertising interval.
            if !clock.sleep_until(next.wrapping_add(SETUP_US), shared.changed()).await {
                since = None;
            }
            continue;
        };
        shared.set_connected(true);
        radio.set_access_address(request.access_address);
        radio.set_crc_init(request.crc_init);
        let mut connection = Connection::new(&request, end);
        connection.set_preferred_phys(shared.preferred_phys());
        connection.set_suggested_length(shared.suggested_length());
        let central = request.central();
        let mut shown = central.address;
        shown.reverse();
        info!("central {=[u8; 6]:02X} random {}", shown, central.random);
        let params = ConnectionParams::new(request.interval, request.latency, request.timeout);
        let local = (settings.own != settings.address).then_some(settings.own.address);
        connection.notify(
            Packet::connection_complete_resolved(
                STATUS_SUCCESS,
                (request.central(), local),
                params,
                request.sca,
                settings.resolve(request.central()),
            ),
            shared,
        );
        since = None;
        let (ended, stats) = connection.run(radio, clock, &mut rx, shared).await;
        info!(
            "connection ended: {} events, {} missed, {} crc errors, {} packets",
            stats.events, stats.missed, stats.crc_errors, stats.received
        );
        if matches!(ended, Ended::Reset) {
            radio.disable();
            clock.pause();
            shared.complete_reset();
            continue;
        }
        // The host gets the retained events and every packet the link
        // acknowledged before it learns that the link ended.
        if !connection.flush_after_disconnect(shared).await
            || matches!(
                select(shared.acl_in_drained(), shared.reset_requested()).await,
                embassy_futures::select::Either::Second(())
            )
        {
            radio.disable();
            clock.pause();
            shared.complete_reset();
            continue;
        }
        let reason = match ended {
            Ended::Error(code) | Ended::Terminated(code) => code,
            Ended::Local(_) => REASON_LOCAL_HOST,
            Ended::Lost => REASON_TIMEOUT,
            Ended::Reset => continue,
        };
        shared.set_connected(false);
        if matches!(
            select(shared.push_event(Packet::disconnection_complete(reason)), shared.reset_requested()).await,
            embassy_futures::select::Either::Second(())
        ) {
            radio.disable();
            clock.pause();
            shared.complete_reset();
        }
    }
}
