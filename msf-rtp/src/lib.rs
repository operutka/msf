//! RTP packet serialization/de-serialization + utilities as defined in RFC
//! 3550.

mod channel;
mod rtp;

pub mod depacketizer;
pub mod packetizer;
pub mod rtcp;
pub mod transceiver;
pub mod utils;

#[cfg(feature = "h264")]
pub mod h264;

#[cfg(feature = "pcm")]
pub mod pcm;

use std::fmt::{self, Display, Formatter};

pub use self::{
    channel::RtpChannel,
    depacketizer::{Depacketizer, MediaStream},
    packetizer::{MediaSink, Packetizer},
    rtcp::{CompoundRtcpPacket, RtcpHeader, RtcpPacket, RtcpPacketType},
    rtp::{IncomingRtpPacket, OrderedRtpPacket, RtpHeader, RtpHeaderExtension, RtpPacket},
};

/// Invalid input error.
#[derive(Debug, Copy, Clone)]
pub struct InvalidInput;

impl Display for InvalidInput {
    #[inline]
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        f.write_str("invalid input")
    }
}

impl std::error::Error for InvalidInput {}
