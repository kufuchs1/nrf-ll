//! Microsecond time base on TIMER0, with the fixed PPI channels that start
//! the radio and capture its packet timing.
//!
//! Between radio events TIMER0 and the high frequency crystal stop. RTC0
//! keeps the time on the low frequency clock and restarts TIMER0 at an exact
//! tick before the next event.

use crate::{log::info, sleep};
use core::{
    cell::Cell,
    future::{Future, poll_fn},
    task::Poll,
};
use embassy_futures::select::{Either, select};
use embassy_nrf::{
    Peri,
    pac::{
        CLOCK,
        PPI,
        RTC0 as RTC,
        TEMP,
        TIMER0 as REGS,
        clock::vals::HfclkstatSrc,
        timer::vals::{Bitmode, Mode},
    },
    peripherals::{RTC0, TIMER0},
};
use embassy_sync::{blocking_mutex::CriticalSectionMutex, waitqueue::AtomicWaker};
use embassy_time::{Duration, Timer, with_timeout};

/// Interval between temperature checks for the RC oscillator.
const CALIBRATION_INTERVAL: Duration = Duration::from_secs(4);
/// Intervals in a row without a calibration while the temperature holds.
const CALIBRATION_SKIPS_MAX: u8 = 1;
/// Temperature change that requires a calibration, in units of 0.25 °C.
const CALIBRATION_TEMP_CHANGE: u32 = 2;
/// Capture register of the access address time (PPI channel 26).
const CC_ADDRESS: usize = 1;
/// Capture register of the packet end time (PPI channel 27).
const CC_END: usize = 2;
/// Capture register of [`Clock::now`] and of the RTC tick before sleeping.
const CC_NOW: usize = 3;
/// Compare register starting the radio (PPI channels 20 and 21).
const CC_START: usize = 0;
/// Time after which a calibration whose crystal or end never came is given
/// up until the next interval.
const CALIBRATION_TIMEOUT: Duration = Duration::from_millis(100);
/// Programmable PPI channel: CLOCK HFCLKSTARTED to CLOCK CAL, while a
/// calibration waits for the crystal.
const PPI_CALIBRATE: usize = 3;
/// Wakes the calibration when the clock interrupt reports it done.
static CALIBRATION_DONE: AtomicWaker = AtomicWaker::new();
/// Wakes the radio task when the high frequency crystal has started.
static CRYSTAL_STARTED: AtomicWaker = AtomicWaker::new();
/// Wakes the calibration task after a die temperature measurement.
static TEMPERATURE_READY: AtomicWaker = AtomicWaker::new();
/// Time after which the crystal is started again when it does not run.
const CRYSTAL_RETRY_US: u32 = 2000;
/// Time the high frequency crystal gets to start before TIMER0 restarts.
const CRYSTAL_LEAD_US: u32 = 800;
/// Time before TIMER0 restarts at which the task wakes to wait for it.
const RESUME_EARLY_US: u32 = 100;
/// Fixed PPI channel: TIMER0 COMPARE0 to RADIO TXEN.
const PPI_TXEN: usize = 20;
/// Fixed PPI channel: TIMER0 COMPARE0 to RADIO RXEN.
const PPI_RXEN: usize = 21;
/// Fixed PPI channel: RADIO ADDRESS to TIMER0 CAPTURE1.
const PPI_ADDRESS: usize = 26;
/// Fixed PPI channel: RADIO END to TIMER0 CAPTURE2.
const PPI_END: usize = 27;
/// PPI channel: RTC0 COMPARE0 to TIMER0 START.
const PPI_RESUME: usize = 0;
/// PPI channel: RTC0 COMPARE1 to TIMER0 CAPTURE3.
const PPI_SYNC: usize = 1;
/// Prescaler for 1 MHz from the 16 MHz timer clock.
const PRESCALER_1MHZ: u8 = 4;
/// RTC0 compare register restarting TIMER0.
const RTC_RESUME: usize = 0;
/// RTC0 compare register marking the tick TIMER0 is read at.
const RTC_SYNC: usize = 1;
/// Mask of the 24-bit RTC counter.
const RTC_MASK: u32 = 0x00FF_FFFF;
/// Smallest distance from the current RTC tick a compare event needs.
const RTC_MIN_TICKS: u32 = 2;
/// Time from the TIMER0 restart until the time slept for.
const SETUP_US: u32 = 300;
/// Shortest wait for which TIMER0 and the crystal stop.
const SLEEP_MIN_US: u32 = 3000;

/// Number of users that need the high frequency crystal. The count and the
/// start or stop task change together in a critical section: a release that
/// counted down to zero but was preempted before stopping the crystal would
/// otherwise stop it under a user that requested it in between.
static CRYSTAL_USERS: CriticalSectionMutex<Cell<u8>> = CriticalSectionMutex::new(Cell::new(0));

/// Free-running 32-bit microsecond time. Times wrap after 71 minutes, so
/// they are compared with wrapping differences.
pub struct Clock<'peripherals> {
    /// The RTC, owned for the lifetime of the clock.
    _rtc:   Peri<'peripherals, RTC0>,
    /// The timer, owned for the lifetime of the clock.
    _timer: Peri<'peripherals, TIMER0>,
    /// Time at which TIMER0 counted zero.
    base:   u32,
    /// Restarts at which the crystal was not running yet.
    late:   u32,
    /// RTC tick and time at it while TIMER0 is stopped.
    paused: Option<(u32, u32)>,
}

/// Undoes a calibration's setup when it completes or its future is dropped.
struct Calibration;

impl Drop for Calibration {
    fn drop(&mut self) {
        PPI.chenclr().write(|w| w.set_ch(PPI_CALIBRATE, true));
        CLOCK.intenclr().write(|w| w.set_done(true));
        CLOCK.events_done().write_value(0);
        release_crystal();
    }
}

/// Cancels a temperature measurement when its future completes or is dropped.
struct TemperatureMeasurement;

impl Drop for TemperatureMeasurement {
    fn drop(&mut self) {
        TEMP.intenclr().write(|w| w.set_datardy(true));
        TEMP.tasks_stop().write_value(1);
        TEMP.events_datardy().write_value(0);
    }
}

/// Owns an in-progress clock restart until its future commits or cancels.
struct ResumeGuard<'clock, 'peripherals> {
    /// Borrow prevents any other clock operation until this restart finishes.
    clock:     &'clock mut Clock<'peripherals>,
    /// Successful restarts transfer their crystal reference to the clock.
    finished:  bool,
    /// Original RTC time base restored when the future is cancelled.
    origin:    (u32, u32),
    /// Whether this operation acquired a high frequency clock reference.
    requested: bool,
}

impl<'clock, 'peripherals> ResumeGuard<'clock, 'peripherals> {
    /// Commits the running clock and transfers its crystal reference.
    fn finish(mut self) { self.finished = true; }

    /// Starts a restart transaction without acquiring the crystal early.
    const fn new(clock: &'clock mut Clock<'peripherals>, origin: (u32, u32)) -> Self {
        Self { clock, finished: false, origin, requested: false }
    }

    /// Acquires the crystal only once the scheduled wake time is reached.
    fn request(&mut self) {
        request_crystal();
        self.requested = true;
    }
}

impl Drop for ResumeGuard<'_, '_> {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        PPI.chenclr().write(|w| w.set_ch(PPI_RESUME, true));
        self.clock.cancel_start();
        REGS.tasks_stop().write_value(1);
        REGS.tasks_clear().write_value(1);
        RTC.events_compare(RTC_RESUME).write_value(0);
        self.clock.paused = Some(self.origin);
        if self.requested {
            CLOCK.intenclr().write(|w| w.set_hfclkstarted(true));
            release_crystal();
        }
    }
}

impl<'peripherals> Clock<'peripherals> {
    /// Time of the last access address the radio sent or received.
    #[inline]
    #[must_use = "the time is only read"]
    pub fn address_time(&self) -> u32 { self.base.wrapping_add(REGS.cc(CC_ADDRESS).read()) }

    /// Stops starting the radio from the timer.
    #[inline]
    pub fn cancel_start(&mut self) {
        PPI.chenclr().write(|w| {
            w.set_ch(PPI_TXEN, true);
            w.set_ch(PPI_RXEN, true);
        });
    }

    /// Time of the last packet end.
    #[inline]
    #[must_use = "the time is only read"]
    pub fn end_time(&self) -> u32 { self.base.wrapping_add(REGS.cc(CC_END).read()) }

    /// Starts the crystal again if it stopped while TIMER0 runs, which
    /// leaves the radio and the time base on the inaccurate internal
    /// oscillator. Returns false if it had stopped.
    #[inline]
    pub async fn ensure_crystal(&mut self) -> bool {
        if self.paused.is_some() || crystal_running() {
            return true;
        }
        self.late = self.late.wrapping_add(1);
        info!("crystal stopped while in use");
        CLOCK.tasks_hfclkstart().write_value(1);
        self.wait_crystal().await;
        false
    }

    /// Waits until TIMER0 restarted at RTC tick `tick + ticks` and continues
    /// the time from `time` at `tick`.
    async fn finish_resume(&mut self, tick: u32, time: u32, ticks: u32) {
        let remaining = ticks.wrapping_sub(rtc_now().wrapping_sub(tick) & RTC_MASK);
        if is_ahead(remaining) {
            Timer::after_micros(u64::from(ticks_to_us(remaining).saturating_sub(RESUME_EARLY_US))).await;
        }
        let target = tick.wrapping_add(ticks) & RTC_MASK;
        let mut started_at = ticks;
        sleep::until(|| RTC.events_compare(RTC_RESUME).read() != 0 || passed(target));
        if RTC.events_compare(RTC_RESUME).read() == 0 {
            REGS.tasks_start().write_value(1);
            started_at = rtc_now().wrapping_sub(tick) & RTC_MASK;
            info!("clock restart missed its tick");
        }
        PPI.chenclr().write(|w| w.set_ch(PPI_RESUME, true));
        self.base = time.wrapping_add(ticks_to_us(started_at));
        self.paused = None;
        if !crystal_running() {
            self.late = self.late.wrapping_add(1);
            self.wait_crystal().await;
        }
    }

    /// Pauses and waits until `at` or until `interrupt` completes. Returns
    /// true if `at` was reached.
    #[inline]
    pub async fn idle_until<F>(&mut self, at: u32, interrupt: F) -> bool
    where
        F: Future,
    {
        self.pause();
        let ahead = at.wrapping_sub(self.now());
        if !is_ahead(ahead) {
            return true;
        }
        matches!(select(Timer::after_micros(u64::from(ahead)), interrupt).await, Either::First(()))
    }

    /// Number of restarts at which the crystal was not running yet.
    #[inline]
    #[must_use = "the count is only read"]
    pub const fn late(&self) -> u32 { self.late }

    /// Sets up the timer, the RTC and the capture channels. The clock starts
    /// paused.
    #[inline]
    #[must_use = "the clock stops being usable once dropped"]
    pub fn new(timer: Peri<'peripherals, TIMER0>, rtc: Peri<'peripherals, RTC0>) -> Self {
        REGS.tasks_stop().write_value(1);
        REGS.mode().write(|w| w.set_mode(Mode::Timer));
        REGS.bitmode().write(|w| w.set_bitmode(Bitmode::_32bit));
        REGS.prescaler().write(|w| w.set_prescaler(PRESCALER_1MHZ));
        REGS.tasks_clear().write_value(1);
        RTC.tasks_stop().write_value(1);
        RTC.prescaler().write(|w| w.set_prescaler(0));
        RTC.evtenset().write(|w| {
            w.set_compare(RTC_RESUME, true);
            w.set_compare(RTC_SYNC, true);
        });
        RTC.tasks_clear().write_value(1);
        RTC.tasks_start().write_value(1);
        let ch_resume = PPI.ch(PPI_RESUME);
        ch_resume.eep().write_value(address(RTC.events_compare(RTC_RESUME).as_ptr()));
        ch_resume.tep().write_value(address(REGS.tasks_start().as_ptr()));
        let ch_sync = PPI.ch(PPI_SYNC);
        ch_sync.eep().write_value(address(RTC.events_compare(RTC_SYNC).as_ptr()));
        ch_sync.tep().write_value(address(REGS.tasks_capture(CC_NOW).as_ptr()));
        PPI.chenset().write(|w| {
            w.set_ch(PPI_ADDRESS, true);
            w.set_ch(PPI_END, true);
        });
        Self { _rtc: rtc, _timer: timer, base: 0, late: 0, paused: Some((rtc_now(), 0)) }
    }

    /// The current time. While paused it follows the RTC, to about 30 us.
    #[inline]
    #[must_use = "the time is only read"]
    pub fn now(&self) -> u32 {
        if let Some((tick, time)) = self.paused {
            return time.wrapping_add(ticks_to_us(rtc_now().wrapping_sub(tick) & RTC_MASK));
        }
        REGS.tasks_capture(CC_NOW).write_value(1);
        self.base.wrapping_add(REGS.cc(CC_NOW).read())
    }

    /// Stops TIMER0 and releases the crystal. The time continues on the RTC.
    #[inline]
    pub fn pause(&mut self) {
        if self.paused.is_some() {
            return;
        }
        self.cancel_start();
        PPI.chenset().write(|w| w.set_ch(PPI_SYNC, true));
        let tick = loop {
            let tick = rtc_now().wrapping_add(RTC_MIN_TICKS) & RTC_MASK;
            RTC.cc(RTC_SYNC).write(|w| w.set_compare(tick));
            RTC.events_compare(RTC_SYNC).write_value(0);
            sleep::until(|| RTC.events_compare(RTC_SYNC).read() != 0 || passed(tick));
            if RTC.events_compare(RTC_SYNC).read() != 0 {
                break tick;
            }
        };
        PPI.chenclr().write(|w| w.set_ch(PPI_SYNC, true));
        let time = self.base.wrapping_add(REGS.cc(CC_NOW).read());
        REGS.tasks_stop().write_value(1);
        REGS.tasks_clear().write_value(1);
        release_crystal();
        self.paused = Some((tick, time));
    }

    /// Starts receiving at `at`. Returns false if `at` is not in the future.
    #[inline]
    pub fn receive_at(&mut self, at: u32) -> bool { self.start_at(at, PPI_RXEN) }

    /// Restarts TIMER0 as soon as the crystal can run.
    ///
    /// Dropping this future rolls back to the paused RTC time base.
    #[inline]
    pub async fn resume_now(&mut self) {
        let Some((tick, time)) = self.paused else { return };
        let mut restart = ResumeGuard::new(self, (tick, time));
        restart.request();
        let elapsed = rtc_now().wrapping_sub(tick) & RTC_MASK;
        let ticks = elapsed.saturating_add(us_to_ticks(CRYSTAL_LEAD_US)).saturating_add(RTC_MIN_TICKS);
        RTC.cc(RTC_RESUME).write(|w| w.set_compare(tick.wrapping_add(ticks) & RTC_MASK));
        RTC.events_compare(RTC_RESUME).write_value(0);
        PPI.chenset().write(|w| w.set_ch(PPI_RESUME, true));
        restart.clock.finish_resume(tick, time, ticks).await;
        restart.finish();
    }

    /// Waits until `at` or until `interrupt` completes, with TIMER0 and the
    /// crystal stopped for long waits. Returns true if `at` was reached. The
    /// clock runs afterwards if `at` was reached and stays paused otherwise.
    #[inline]
    pub async fn sleep_until<F>(&mut self, at: u32, interrupt: F) -> bool
    where
        F: Future,
    {
        let ahead = at.wrapping_sub(self.now());
        if !is_ahead(ahead) {
            self.resume_now().await;
            return true;
        }
        if self.paused.is_none() && ahead < SLEEP_MIN_US {
            return matches!(select(Timer::after_micros(u64::from(ahead)), interrupt).await, Either::First(()));
        }
        self.pause();
        let Some((tick, time)) = self.paused else { return true };
        let ticks = us_to_ticks(at.wrapping_sub(SETUP_US).wrapping_sub(time));
        let resume = tick.wrapping_add(ticks) & RTC_MASK;
        let elapsed = rtc_now().wrapping_sub(tick) & RTC_MASK;
        if ticks < elapsed.saturating_add(us_to_ticks(CRYSTAL_LEAD_US)).saturating_add(RTC_MIN_TICKS) {
            self.resume_now().await;
            return true;
        }
        let mut restart = ResumeGuard::new(self, (tick, time));
        RTC.cc(RTC_RESUME).write(|w| w.set_compare(resume));
        RTC.events_compare(RTC_RESUME).write_value(0);
        PPI.chenset().write(|w| w.set_ch(PPI_RESUME, true));
        let wake = ticks_to_us(ticks.wrapping_sub(elapsed)).saturating_sub(CRYSTAL_LEAD_US);
        if let Either::Second(_) = select(Timer::after_micros(u64::from(wake)), interrupt).await {
            return false;
        }
        restart.request();
        restart.clock.finish_resume(tick, time, ticks).await;
        restart.finish();
        true
    }

    /// Starts the radio through `channel` at `at`. Returns false if `at` is
    /// not in the future.
    fn start_at(&mut self, at: u32, channel: usize) -> bool {
        self.cancel_start();
        REGS.cc(CC_START).write_value(at.wrapping_sub(self.base));
        REGS.events_compare(CC_START).write_value(0);
        PPI.chenset().write(|w| w.set_ch(channel, true));
        is_ahead(at.wrapping_sub(self.now()))
    }

    /// Starts sending at `at`. Returns false if `at` is not in the future.
    #[inline]
    pub fn transmit_at(&mut self, at: u32) -> bool { self.start_at(at, PPI_TXEN) }

    /// Sleeps until the crystal runs, starting it again if it does not come
    /// up in time.
    async fn wait_crystal(&self) {
        while !crystal_running() {
            if with_timeout(Duration::from_micros(u64::from(CRYSTAL_RETRY_US)), crystal_started()).await.is_err() {
                CLOCK.tasks_hfclkstart().write_value(1);
                info!("crystal started again");
            }
        }
        CLOCK.intenclr().write(|w| w.set_hfclkstarted(true));
    }

    /// Busy-waits until `at` for callers that require microsecond precision.
    /// Use [`Self::sleep_until`] outside timing-critical sections.
    #[inline]
    pub fn wait_until(&self, at: u32) { while !reached(self.now(), at) {} }
}

/// The address of a register for a PPI endpoint.
fn address<T>(register: *mut T) -> u32 { u32::try_from(register.addr()).unwrap_or_default() }

/// Keeps the low frequency RC oscillator within 500 ppm forever.
///
/// Owns TEMP exclusively. The TEMP data-ready interrupt (calling
/// [`on_temperature_interrupt`]) and the `CLOCK_POWER` interrupt (calling
/// [`on_clock_interrupt`]) wake it, and both must be enabled: nothing polls
/// the events. Dropping the future releases the crystal and stops a running
/// measurement.
///
/// As Nordic specifies it, the temperature is checked every
/// [`CALIBRATION_INTERVAL`], and the oscillator calibrated when it changed by
/// 0.5 °C, or at the latest every second interval.
#[inline]
pub async fn calibrate_rc(_temperature: Peri<'_, embassy_nrf::peripherals::TEMP>) -> ! {
    let mut calibrated_at = None;
    let mut skipped = 0_u8;
    loop {
        let temperature = temperature().await;
        let changed = calibrated_at.is_none_or(|last: i32| last.abs_diff(temperature) >= CALIBRATION_TEMP_CHANGE);
        if changed || skipped >= CALIBRATION_SKIPS_MAX {
            if calibrate().await {
                calibrated_at = Some(temperature);
                skipped = 0;
            } else {
                info!("RC calibration timed out");
            }
        } else {
            skipped = skipped.saturating_add(1);
        }
        Timer::after(CALIBRATION_INTERVAL).await;
    }
}

/// Calibrates the RC oscillator once against the high frequency crystal.
///
/// PPI starts the calibration when the crystal runs, and the clock interrupt
/// wakes the task when it is done, so the CPU wakes twice. Gives up after
/// [`CALIBRATION_TIMEOUT`] if the crystal or the end never comes.
async fn calibrate() -> bool {
    CLOCK.events_done().write_value(0);
    let channel = PPI.ch(PPI_CALIBRATE);
    channel.eep().write_value(address(CLOCK.events_hfclkstarted().as_ptr()));
    channel.tep().write_value(address(CLOCK.tasks_cal().as_ptr()));
    PPI.chenset().write(|w| w.set_ch(PPI_CALIBRATE, true));
    request_crystal();
    let _calibration = Calibration;
    // A crystal that already ran reports no start. If it starts just now
    // as well, the second start of the calibration is harmless.
    if crystal_running() {
        CLOCK.tasks_cal().write_value(1);
    }
    with_timeout(CALIBRATION_TIMEOUT, calibration_done()).await.is_ok()
}

/// Waits until the calibration is done.
async fn calibration_done() {
    poll_fn(|cx| {
        CALIBRATION_DONE.register(cx.waker());
        if CLOCK.events_done().read() != 0 {
            return Poll::Ready(());
        }
        CLOCK.intenset().write(|w| w.set_done(true));
        Poll::Pending
    })
    .await;
}

/// Waits for the crystal through the existing `CLOCK_POWER` interrupt.
async fn crystal_started() {
    poll_fn(|cx| {
        CRYSTAL_STARTED.register(cx.waker());
        if crystal_running() {
            return Poll::Ready(());
        }
        CLOCK.intenset().write(|w| w.set_hfclkstarted(true));
        Poll::Pending
    })
    .await;
}

/// Handles the clock interrupt: wakes calibration and crystal startup.
/// Call it from the `CLOCK_POWER` interrupt handler, which must be enabled.
#[inline]
pub fn on_clock_interrupt() {
    CLOCK.intenclr().write(|w| {
        w.set_done(true);
        w.set_hfclkstarted(true);
    });
    CALIBRATION_DONE.wake();
    CRYSTAL_STARTED.wake();
}

/// Handles TEMP data-ready; call from an enabled, lower-priority TEMP ISR.
#[inline]
pub fn on_temperature_interrupt() {
    TEMP.intenclr().write(|w| w.set_datardy(true));
    TEMPERATURE_READY.wake();
}

/// The die temperature in units of 0.25 °C, woken by the TEMP interrupt.
async fn temperature() -> i32 {
    let _measurement = TemperatureMeasurement;
    TEMP.events_datardy().write_value(0);
    TEMP.tasks_start().write_value(1);
    poll_fn(|cx| {
        TEMPERATURE_READY.register(cx.waker());
        if TEMP.events_datardy().read() != 0 {
            return Poll::Ready(TEMP.temp().read().cast_signed());
        }
        TEMP.intenset().write(|w| w.set_datardy(true));
        Poll::Pending
    })
    .await
}

/// Whether the high frequency clock runs from the crystal.
fn crystal_running() -> bool {
    let status = CLOCK.hfclkstat().read();
    status.state() && status.src() == HfclkstatSrc::Xtal
}

/// Whether a wrapping difference is a positive time.
const fn is_ahead(difference: u32) -> bool { difference > 0 && difference < u32::MAX >> 1 }

/// Whether `now` is at or past `at`.
#[inline]
#[must_use = "the comparison is only computed"]
pub const fn reached(now: u32, at: u32) -> bool { now.wrapping_sub(at) < u32::MAX >> 1 }

/// Drops one user of the high frequency crystal and stops it after the last.
fn release_crystal() {
    CRYSTAL_USERS.lock(|users| {
        let left = users.get().saturating_sub(1);
        users.set(left);
        if left == 0 {
            CLOCK.tasks_hfclkstop().write_value(1);
        }
    });
}

/// Adds a user of the high frequency crystal and starts it for the first.
fn request_crystal() {
    CRYSTAL_USERS.lock(|users| {
        let count = users.get();
        users.set(count.saturating_add(1));
        if count == 0 {
            CLOCK.events_hfclkstarted().write_value(0);
            CLOCK.tasks_hfclkstart().write_value(1);
        }
    });
}

/// Whether the RTC counter is past `tick`.
fn passed(tick: u32) -> bool {
    let difference = rtc_now().wrapping_sub(tick) & RTC_MASK;
    difference != 0 && difference < RTC_MASK >> 1_u32
}

/// The RTC counter.
fn rtc_now() -> u32 { RTC.counter().read().counter() }

/// Microseconds of `ticks` RTC ticks, 15625/512 us each.
fn ticks_to_us(ticks: u32) -> u32 {
    u32::try_from(u64::from(ticks).saturating_mul(15_625) >> 9_u32).unwrap_or(u32::MAX)
}

/// Whole RTC ticks in `us` microseconds.
fn us_to_ticks(us: u32) -> u32 {
    u32::try_from(u64::from(us).wrapping_shl(9).checked_div(15_625).unwrap_or(0)).unwrap_or(u32::MAX)
}
