#![cfg_attr(docsrs, feature(doc_cfg))]

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
#[cfg_attr(docsrs, doc(cfg(feature = "h264")))]
pub mod h264;

#[cfg(feature = "opus")]
#[cfg_attr(docsrs, doc(cfg(feature = "opus")))]
pub mod opus;

#[cfg(feature = "pcm")]
#[cfg_attr(docsrs, doc(cfg(feature = "pcm")))]
pub mod pcm;

use std::fmt::{self, Display, Formatter};

pub use self::{
    channel::RtpChannel,
    depacketizer::{Depacketizer, MediaStream},
    packetizer::{MediaSink, Packetizer},
    rtcp::{CompoundRtcpPacket, RtcpHeader, RtcpPacket, RtcpPacketType},
    rtp::{IncomingRtpPacket, OrderedRtpPacket, RtpHeader, RtpHeaderExtension, RtpPacket},
};

/// General error type.
#[derive(Debug)]
pub struct Error {
    msg: &'static str,
}

impl Error {
    /// Create a new error with a given message.
    #[inline]
    const fn from_static_msg(msg: &'static str) -> Self {
        Self { msg }
    }
}

impl Display for Error {
    #[inline]
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        f.write_str(self.msg)
    }
}

impl std::error::Error for Error {}

impl From<InvalidInput> for Error {
    #[inline]
    fn from(_: InvalidInput) -> Self {
        Self::from_static_msg("invalid input")
    }
}

/// Invalid input error.
#[derive(Debug)]
pub struct InvalidInput(());

impl InvalidInput {
    /// Create a new invalid input error.
    #[inline]
    const fn new() -> Self {
        Self(())
    }
}

impl Display for InvalidInput {
    #[inline]
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        f.write_str("invalid input")
    }
}

impl std::error::Error for InvalidInput {}
