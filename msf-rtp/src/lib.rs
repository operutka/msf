//! RTP packet serialization/de-serialization + utilities as defined in RFC
//! 3550.

mod rtp;

pub mod depacketizer;
pub mod packetizer;
pub mod rtcp;
pub mod utils;

#[cfg(feature = "h264")]
pub mod h264;

#[cfg(feature = "pcm")]
pub mod pcm;

use std::fmt::{self, Display, Formatter};

pub use self::{
    depacketizer::{Depacketizer, MediaStream},
    packetizer::{MediaSink, Packetizer},
    rtcp::{CompoundRtcpPacket, RtcpHeader, RtcpPacket, RtcpPacketType},
    rtp::{RtpHeader, RtpHeaderExtension, RtpPacket},
};

/// Invalid input.
#[derive(Debug, Copy, Clone)]
pub struct InvalidInput;

impl Display for InvalidInput {
    #[inline]
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        f.write_str("invalid input")
    }
}

impl std::error::Error for InvalidInput {}

/// RTP or RTCP packet.
///
/// This is useful when RTP and RTCP packets can be multiplexed in a single
/// channel. See RFC 5761 for more info.
#[derive(Clone)]
pub enum PacketMux {
    Rtp(RtpPacket),
    Rtcp(CompoundRtcpPacket),
}

impl From<RtpPacket> for PacketMux {
    #[inline]
    fn from(packet: RtpPacket) -> Self {
        Self::Rtp(packet)
    }
}

impl From<RtcpPacket> for PacketMux {
    #[inline]
    fn from(packet: RtcpPacket) -> Self {
        Self::Rtcp(packet.into())
    }
}

impl From<CompoundRtcpPacket> for PacketMux {
    #[inline]
    fn from(packet: CompoundRtcpPacket) -> Self {
        Self::Rtcp(packet)
    }
}
