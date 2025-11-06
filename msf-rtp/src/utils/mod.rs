//! Helpers.

pub mod reorder;

use std::time::{Duration, SystemTime};

use crate::{
    rtcp::{CompoundRtcpPacket, RtcpPacket},
    rtp::{IncomingRtpPacket, OrderedRtpPacket, RtpPacket},
};

/// RTP or RTCP packet.
///
/// This is useful when RTP and RTCP packets can be multiplexed in a single
/// channel. See RFC 5761 for more info.
#[derive(Clone)]
pub enum PacketMux<P = RtpPacket> {
    Rtp(P),
    Rtcp(CompoundRtcpPacket),
}

impl From<RtpPacket> for PacketMux {
    #[inline]
    fn from(packet: RtpPacket) -> Self {
        Self::Rtp(packet)
    }
}

impl From<IncomingRtpPacket> for PacketMux<IncomingRtpPacket> {
    #[inline]
    fn from(packet: IncomingRtpPacket) -> Self {
        Self::Rtp(packet)
    }
}

impl From<OrderedRtpPacket> for PacketMux<OrderedRtpPacket> {
    #[inline]
    fn from(packet: OrderedRtpPacket) -> Self {
        Self::Rtp(packet)
    }
}

impl<P> From<RtcpPacket> for PacketMux<P> {
    #[inline]
    fn from(packet: RtcpPacket) -> Self {
        Self::Rtcp(packet.into())
    }
}

impl<P> From<CompoundRtcpPacket> for PacketMux<P> {
    #[inline]
    fn from(packet: CompoundRtcpPacket) -> Self {
        Self::Rtcp(packet)
    }
}

/// Get NTP timestamp as a 32.32 fixed point number.
///
/// This timestamp can be used for RTCP sender reports.
pub fn ntp_timestamp() -> u64 {
    let ts = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO);

    let s = ts.as_secs();
    let n = ts.subsec_nanos();

    let f = (n as u64) * (1u64 << 32) / 1_000_000_000u64;

    ((s + 2_208_988_800) << 32) + f
}
