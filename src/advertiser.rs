//! Legacy advertising.

/// Legacy advertising.
pub mod legacy;

/// Advertising channels with their bit in the channel map.
const CHANNELS: [(u8, u8); 3] = [(37, 0x01), (38, 0x02), (39, 0x04)];
/// Time after the end of a packet until a request's access address must have
/// arrived: interframe space, preamble and access address, margin.
const LISTEN_US: u32 = 300;
