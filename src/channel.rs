//! Data channel map and channel selection algorithms 1 and 2.

/// Number of data channels.
const DATA_CHANNELS: u8 = 37;

/// Used data channels.
#[derive(Clone, Copy)]
pub struct UsedChannels {
    /// Number of used channels.
    count: u8,
    /// Used channel indexes in ascending order, valid up to `count`.
    used:  [u8; 37],
}

impl UsedChannels {
    /// Whether the map holds a channel.
    fn contains(&self, channel: u8) -> bool {
        self.used.get(..usize::from(self.count)).is_some_and(|used| used.contains(&channel))
    }

    /// Builds the map from the 5-byte bit field of the link layer.
    #[inline]
    #[must_use = "the map is only built"]
    pub fn new(bits: [u8; 5]) -> Self {
        let mut map = Self { count: 0, used: [0; 37] };
        for channel in 0..DATA_CHANNELS {
            if is_set(bits, channel) {
                if let Some(slot) = map.used.get_mut(usize::from(map.count)) {
                    *slot = channel;
                }
                map.count = map.count.saturating_add(1);
            }
        }
        map
    }

    /// Maps an unmapped channel index to a used channel.
    fn remap(&self, unmapped: u8) -> u8 {
        if self.contains(unmapped) {
            return unmapped;
        }
        let index = unmapped.checked_rem(self.count).unwrap_or(0);
        self.used.get(usize::from(index)).copied().unwrap_or(0)
    }
}

/// Channel selection of a connection.
#[derive(Clone, Copy)]
#[non_exhaustive]
pub enum Hopping {
    /// Algorithm 1: a fixed hop increment.
    Csa1 {
        /// Hop increment.
        hop:           u8,
        /// Unmapped channel of the last connection event.
        last_unmapped: u8,
    },
    /// Algorithm 2: a pseudo-random channel per event counter.
    Csa2 {
        /// Channel identifier from the access address.
        identifier: u16,
    },
}

impl Hopping {
    /// The channel of connection event `counter`. Every event has to be
    /// passed in order, including the skipped ones.
    #[inline]
    pub fn channel(&mut self, map: &UsedChannels, counter: u16) -> u8 {
        match *self {
            Self::Csa1 { hop, last_unmapped } => {
                let next = last_unmapped.saturating_add(hop).checked_rem(DATA_CHANNELS).unwrap_or(0);
                *self = Self::Csa1 { hop, last_unmapped: next };
                map.remap(next)
            },
            Self::Csa2 { identifier } => {
                let random = csa2_random(counter, identifier);
                let unmapped = u8::try_from(random.checked_rem(u16::from(DATA_CHANNELS)).unwrap_or(0)).unwrap_or(0);
                if map.contains(unmapped) {
                    return unmapped;
                }
                let index = u32::from(map.count).saturating_mul(u32::from(random)) >> 16_u32;
                map.used.get(usize::try_from(index).unwrap_or(0)).copied().unwrap_or(0)
            },
        }
    }

    /// Algorithm 2 for the connection with `access_address`.
    #[inline]
    #[must_use = "the selection is only created"]
    pub const fn csa2(access_address: u32) -> Self {
        let [byte0, byte1, byte2, byte3] = access_address.to_le_bytes();
        let low = u16::from_le_bytes([byte0, byte1]);
        let high = u16::from_le_bytes([byte2, byte3]);
        Self::Csa2 { identifier: high ^ low }
    }

    /// Algorithm 1 with `hop`.
    #[inline]
    #[must_use = "the selection is only created"]
    pub const fn new(hop: u8) -> Self { Self::Csa1 { hop, last_unmapped: 0 } }
}

/// The pseudo-random number of algorithm 2 for event `counter` (Core, Vol 6,
/// Part B, 4.5.8.3.3).
fn csa2_random(counter: u16, identifier: u16) -> u16 {
    let mut value = counter ^ identifier;
    for _ in 0_u8..3 {
        let [high, low] = value.to_be_bytes();
        let permuted = u16::from_be_bytes([high.reverse_bits(), low.reverse_bits()]);
        value = permuted.wrapping_mul(17).wrapping_add(identifier);
    }
    value ^ identifier
}

/// Whether a channel bit is set in a link layer channel map.
fn is_set(bits: [u8; 5], channel: u8) -> bool {
    bits.get(usize::from(channel >> 3)).is_some_and(|byte| byte & 1_u8.wrapping_shl(u32::from(channel & 7)) != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hopping_stays_inside_a_sparse_channel_map() {
        let map = UsedChannels::new([0x08, 0, 0, 0, 0x10]);
        let mut hopping = Hopping::new(5);
        for counter in 0..=u16::MAX {
            assert!(matches!(hopping.channel(&map, counter), 3 | 36));
        }
        let mut hopping = Hopping::csa2(0x8E89_BED6);
        for counter in 0..=u16::MAX {
            assert!(matches!(hopping.channel(&map, counter), 3 | 36));
        }
    }

    #[test]
    fn hopping_with_all_channels_visits_every_channel_in_hop_order() {
        let map = UsedChannels::new([0xFF, 0xFF, 0xFF, 0xFF, 0x1F]);
        let mut hopping = Hopping::new(7);
        let channels: [u8; 37] = core::array::from_fn(|index| hopping.channel(&map, u16::try_from(index).unwrap()));
        assert_eq!(channels[..3], [7, 14, 21]);
        let mut sorted = channels;
        sorted.sort_unstable();
        assert_eq!(sorted, core::array::from_fn::<u8, 37, _>(|index| u8::try_from(index).unwrap()));
    }

    #[test]
    fn algorithm_2_matches_the_specification_samples() {
        // Core, Vol 6, Part C, 3.1: access address 0x8E89BED6.
        let mut hopping = Hopping::csa2(0x8E89_BED6);
        assert!(matches!(hopping, Hopping::Csa2 { identifier: 0x305F }));
        let all = UsedChannels::new([0xFF, 0xFF, 0xFF, 0xFF, 0x1F]);
        assert_eq!([1, 2, 3].map(|counter| hopping.channel(&all, counter)), [20, 6, 21]);
        // Channels 9, 10, 21, 22, 23, 33, 34, 35 and 36.
        let some = UsedChannels::new([0x00, 0x06, 0xE0, 0x00, 0x1E]);
        assert_eq!([6, 7, 8].map(|counter| hopping.channel(&some, counter)), [23, 9, 34]);
    }
}
