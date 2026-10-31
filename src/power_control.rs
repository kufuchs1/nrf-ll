//! Transmit power that follows the link: lower while the central is heard
//! strongly, higher when its packets get weak or go missing.
//!
//! The path is taken as symmetric and the central as sending at 0 dBm, so the
//! central hears this peripheral at about its own power plus the received
//! signal strength. Power steps down while that estimate stays above
//! [`TARGET_HIGH_DBM`] and up below [`TARGET_LOW_DBM`]. A central that sends
//! stronger than assumed still hears the device 15 dB above its
//! sensitivity. A packet of ours that the central did not acknowledge raises
//! the power at once, and keeps it from stepping down for
//! [`HOLD_AFTER_LOSS`] packets. Packets of the central that were not
//! received say nothing about this side's power and are ignored.
//!
//! A central that runs power control measures this side's signal itself and
//! asks for a change. Its request becomes the floor: the own control never
//! steps below it, as the estimate that the central would hear less is the
//! one it just contradicted. A later request of the central lowers the floor
//! again.

/// Transmit power levels in dBm, lowest first.
pub const LEVELS_DBM: [i8; 8] = [-20, -16, -12, -8, -4, 0, 3, 4];
/// Level at the start of a connection and for advertising: 0 dBm.
pub const DEFAULT_LEVEL: usize = 5;
/// Estimated signal at the central above which the power steps down.
const TARGET_HIGH_DBM: i32 = -60;
/// Estimated signal at the central below which the power steps up.
const TARGET_LOW_DBM: i32 = -72;
/// Received packets after a loss before the power may step down again.
const HOLD_AFTER_LOSS: u8 = 64;
/// Received packets between two decisions.
const SAMPLES_PER_DECISION: u8 = 16;
/// Fixed point factor of the average.
const SCALE: i32 = 16;
/// Weight of a new sample in the average, as a shift.
const SMOOTHING_SHIFT: u32 = 3;

/// Transmit power control of one connection.
#[derive(Clone, Copy)]
pub struct PowerControl {
    /// Average received signal strength in dBm times [`SCALE`].
    average: Option<i32>,
    /// Index into [`LEVELS_DBM`] the own control does not step below: the
    /// level the central last asked for.
    floor:   usize,
    /// Received packets until the power may step down again.
    hold:    u8,
    /// Index into [`LEVELS_DBM`].
    level:   usize,
    /// Samples since the last decision.
    samples: u8,
}

impl PowerControl {
    /// Received signal strength in dBm, averaged, once a packet arrived.
    #[inline]
    #[must_use = "the signal strength is only read"]
    pub fn average_dbm(&self) -> Option<i32> { self.average.map(|average| average.checked_div(SCALE).unwrap_or(0_i32)) }

    /// Steps the power down or up by one level from the average.
    fn decide(&mut self) {
        let Some(average) = self.average else { return };
        let own = i32::from(LEVELS_DBM.get(self.level).copied().unwrap_or_default());
        let at_central = own.saturating_add(average.checked_div(SCALE).unwrap_or(0_i32));
        if at_central > TARGET_HIGH_DBM && self.hold == 0 && self.level > self.floor {
            self.level = self.level.saturating_sub(1);
        } else if at_central < TARGET_LOW_DBM {
            self.level = self.level.saturating_add(1).min(LEVELS_DBM.len().saturating_sub(1));
        } else {
            // Within the window: keep the level.
        }
    }

    /// Index into [`LEVELS_DBM`] to send with.
    #[inline]
    #[must_use = "the level is only read"]
    pub const fn level(&self) -> usize { self.level }

    /// Moves to the level closest to `dbm`, as the central asked, and keeps
    /// the own control from stepping below it.
    #[inline]
    pub fn move_to(&mut self, dbm: i32) {
        let closest = LEVELS_DBM.iter().enumerate().min_by_key(|&(_, &level)| i32::from(level).abs_diff(dbm));
        self.level = closest.map_or(self.level, |(index, _)| index);
        self.floor = self.level;
        self.samples = 0;
        self.hold = HOLD_AFTER_LOSS;
    }

    /// Starts at [`DEFAULT_LEVEL`].
    #[inline]
    #[must_use = "the control is only created"]
    pub const fn new() -> Self { Self { average: None, floor: 0, hold: 0, level: DEFAULT_LEVEL, samples: 0 } }

    /// Takes a packet of ours that the central did not acknowledge.
    #[inline]
    pub fn on_loss(&mut self) {
        self.level = self.level.saturating_add(1).min(LEVELS_DBM.len().saturating_sub(1));
        self.samples = 0;
        self.hold = HOLD_AFTER_LOSS;
    }

    /// Takes the signal strength of a packet received with a valid CRC, in
    /// -dBm as the radio reports it.
    #[inline]
    pub fn on_packet(&mut self, rssi: u8) {
        let sample = i32::from(rssi).saturating_mul(-SCALE);
        self.average = Some(
            self.average
                .map_or(sample, |average| average.saturating_add(sample.saturating_sub(average) >> SMOOTHING_SHIFT)),
        );
        self.samples = self.samples.saturating_add(1);
        self.hold = self.hold.saturating_sub(1);
        if self.samples >= SAMPLES_PER_DECISION {
            self.samples = 0;
            self.decide();
        }
    }
}

impl Default for PowerControl {
    #[inline]
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settle(control: &mut PowerControl, rssi: u8) {
        for _ in 0..u32::from(SAMPLES_PER_DECISION) * 20 {
            control.on_packet(rssi);
        }
    }

    #[test]
    fn a_central_close_by_brings_the_power_to_the_minimum() {
        let mut control = PowerControl::new();
        settle(&mut control, 40);
        assert_eq!(control.level(), 0);
    }

    #[test]
    fn a_weak_central_brings_the_power_to_the_maximum() {
        let mut control = PowerControl::new();
        settle(&mut control, 85);
        assert_eq!(control.level(), LEVELS_DBM.len() - 1);
    }

    #[test]
    fn the_power_settles_where_the_central_hears_it_in_the_window() {
        for rssi in 45..80 {
            let mut control = PowerControl::new();
            settle(&mut control, rssi);
            let at_central = i32::from(LEVELS_DBM[control.level()]) - i32::from(rssi);
            let at_limit = control.level() == 0 || control.level() == LEVELS_DBM.len() - 1;
            assert!(at_limit || (TARGET_LOW_DBM..=TARGET_HIGH_DBM).contains(&at_central), "rssi -{rssi}");
        }
    }

    #[test]
    fn a_lost_packet_raises_the_power_at_once() {
        let mut control = PowerControl::new();
        settle(&mut control, 40);
        control.on_loss();
        assert_eq!(control.level(), 1);
        for _ in 0..20 {
            control.on_loss();
        }
        assert_eq!(control.level(), LEVELS_DBM.len() - 1);
    }

    #[test]
    fn after_a_loss_the_power_holds_before_stepping_down() {
        let mut control = PowerControl::new();
        settle(&mut control, 40);
        control.on_loss();
        for _ in 0..HOLD_AFTER_LOSS - 1 {
            control.on_packet(40);
        }
        assert_eq!(control.level(), 1);
        settle(&mut control, 40);
        assert_eq!(control.level(), 0);
    }

    #[test]
    fn a_requested_power_moves_to_the_closest_level_and_holds() {
        let mut control = PowerControl::new();
        control.move_to(-13);
        assert_eq!(LEVELS_DBM[control.level()], -12);
        control.move_to(40);
        assert_eq!(control.level(), LEVELS_DBM.len() - 1);
        control.move_to(-12);
        for _ in 0..SAMPLES_PER_DECISION {
            control.on_packet(40);
        }
        assert_eq!(LEVELS_DBM[control.level()], -12);
    }

    #[test]
    fn a_requested_power_is_the_floor_until_the_central_lowers_it() {
        let mut control = PowerControl::new();
        control.move_to(-4);
        settle(&mut control, 40);
        assert_eq!(LEVELS_DBM[control.level()], -4);
        settle(&mut control, 85);
        assert_eq!(control.level(), LEVELS_DBM.len() - 1);
        settle(&mut control, 40);
        assert_eq!(LEVELS_DBM[control.level()], -4);
        control.move_to(-12);
        settle(&mut control, 40);
        assert_eq!(LEVELS_DBM[control.level()], -12);
    }

    #[test]
    fn one_decision_moves_one_level() {
        let mut control = PowerControl::new();
        for _ in 0..SAMPLES_PER_DECISION {
            control.on_packet(40);
        }
        assert_eq!(control.level(), DEFAULT_LEVEL - 1);
    }
}
