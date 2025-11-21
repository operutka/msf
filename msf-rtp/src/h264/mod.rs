//! H.264 video (de)packetizer.

mod au;
mod depacketizer;
mod dts;
mod packetizer;
mod reorder;

pub use self::{
    au::AccessUnit,
    depacketizer::{H264Depacketizer, H264DepacketizerBuilder},
    packetizer::H264Packetizer,
};

/// RTP clock rate.
pub const CLOCK_RATE: u32 = 90_000;

/// Packetization mode used by the packetizer as defined in RFC 6184.
pub const PACKETIZATION_MODE: u8 = 1;
