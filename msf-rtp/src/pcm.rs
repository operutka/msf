//! PCM audio (de)packetizer.

use std::{
    convert::{Infallible, TryFrom},
    error::Error,
    fmt::{self, Display, Formatter},
    str::FromStr,
};

use bytes::Bytes;
use msf_sdp::{attribute::RTPMap, MediaDescription};

use crate::{depacketizer::Depacketizer, packetizer::Packetizer, rtp::RtpPacket};

/// PCM audio frame.
#[derive(Clone)]
pub struct AudioFrame {
    data: Bytes,
    timestamp: u32,
}

impl AudioFrame {
    /// Create a new audio frame with a given RTP timestamp.
    #[inline]
    pub const fn new(data: Bytes, timestamp: u32) -> Self {
        Self { data, timestamp }
    }

    /// Get the frame RTP timestamp.
    #[inline]
    pub fn timestamp(&self) -> u32 {
        self.timestamp
    }

    /// Get the frame data containing encoded audio samples.
    #[inline]
    pub fn data(&self) -> &Bytes {
        &self.data
    }

    /// Take the frame data.
    #[inline]
    pub fn into_data(self) -> Bytes {
        self.data
    }
}

/// Unknown encoding error.
#[derive(Debug, Copy, Clone)]
pub struct UnknownEncoding;

impl Display for UnknownEncoding {
    #[inline]
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.write_str("unknown encoding")
    }
}

impl Error for UnknownEncoding {}

/// Unsupported encoding error.
#[derive(Debug, Copy, Clone)]
pub struct UnsupportedEncoding;

impl Display for UnsupportedEncoding {
    #[inline]
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.write_str("unsupported encoding")
    }
}

impl Error for UnsupportedEncoding {}

impl From<UnknownEncoding> for UnsupportedEncoding {
    #[inline]
    fn from(_: UnknownEncoding) -> Self {
        Self
    }
}

/// Types of PCM encoding.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum PCMEncoding {
    L8,
    L16,
    PCMA,
    PCMU,
}

impl FromStr for PCMEncoding {
    type Err = UnknownEncoding;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let res = if s.eq_ignore_ascii_case("L8") {
            Self::L8
        } else if s.eq_ignore_ascii_case("L16") {
            Self::L16
        } else if s.eq_ignore_ascii_case("PCMA") {
            Self::PCMA
        } else if s.eq_ignore_ascii_case("PCMU") {
            Self::PCMU
        } else {
            return Err(UnknownEncoding);
        };

        Ok(res)
    }
}

/// PCM media information.
#[derive(Copy, Clone)]
pub struct PCMInfo {
    encoding: PCMEncoding,
    sample_rate: u32,
    clock_rate: u32,
    channels: u16,
}

impl PCMInfo {
    /// Get PCM info for a given static payload type.
    pub fn from_payload_type(payload_type: u8) -> Result<Self, UnsupportedEncoding> {
        let (encoding, clock_rate, channels) = match payload_type {
            0 => (PCMEncoding::PCMU, 8_000, 1),
            8 => (PCMEncoding::PCMA, 8_000, 1),
            10 => (PCMEncoding::L16, 44_100, 2),
            11 => (PCMEncoding::L16, 44_100, 1),
            _ => return Err(UnsupportedEncoding),
        };

        let res = Self {
            encoding,
            sample_rate: clock_rate,
            clock_rate,
            channels,
        };

        Ok(res)
    }

    /// Extract PCM info from a given media description.
    pub fn from_media_description(
        media_description: &MediaDescription,
        fmt: &str,
    ) -> Result<Self, UnsupportedEncoding> {
        let payload_type = u8::from_str(fmt).map_err(|_| UnsupportedEncoding)?;

        let is_present = media_description
            .formats()
            .iter()
            .any(|f| f.as_str() == fmt);

        assert!(is_present);

        let map = media_description
            .attributes()
            .get_all("rtpmap")
            .filter_map(|attr| attr.value())
            .filter_map(|val| {
                let (fmt, _) = val.split_once(' ')?;

                Some((fmt.trim(), val))
            })
            .filter(|(f, _)| *f == fmt)
            .map(|(_, val)| val)
            .next()
            .map(RTPMap::try_from)
            .transpose()
            .map_err(|_| UnsupportedEncoding)?;

        if let Some(map) = map {
            let encoding = PCMEncoding::from_str(map.encoding_name())?;

            let clock_rate = map.clock_rate();

            let channels = map
                .encoding_parameters()
                .map(u16::from_str)
                .transpose()
                .map_err(|_| UnsupportedEncoding)?
                .unwrap_or(1);

            let res = Self {
                encoding,
                sample_rate: clock_rate,
                clock_rate,
                channels,
            };

            Ok(res)
        } else {
            Self::from_payload_type(payload_type)
        }
    }

    /// Get the PCM encoding.
    #[inline]
    pub fn encoding(&self) -> PCMEncoding {
        self.encoding
    }

    /// Get the audio sampling rate.
    #[inline]
    pub fn sample_rate(&self) -> u32 {
        self.sample_rate
    }

    /// Get the RTP clock rate.
    #[inline]
    pub fn clock_rate(&self) -> u32 {
        self.clock_rate
    }

    /// Get the number of audio channels.
    #[inline]
    pub fn channels(&self) -> u16 {
        self.channels
    }
}

/// PCM depacketizer.
pub struct PCMDepacketizer {
    payload_type: u8,
    frame: Option<AudioFrame>,
}

impl PCMDepacketizer {
    /// Create a new PCM depacketizer.
    #[inline]
    pub const fn new(payload_type: u8) -> Self {
        Self {
            payload_type,
            frame: None,
        }
    }
}

impl Depacketizer for PCMDepacketizer {
    type Frame = AudioFrame;
    type Error = Infallible;

    #[inline]
    fn push(&mut self, packet: RtpPacket) -> Result<(), Self::Error> {
        if packet.payload_type() != self.payload_type {
            return Ok(());
        }

        assert!(self.frame.is_none());

        let timestamp = packet.timestamp();
        let data = packet.stripped_payload();

        self.frame = Some(AudioFrame::new(data, timestamp));

        Ok(())
    }

    #[inline]
    fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    #[inline]
    fn take(&mut self) -> Result<Option<Self::Frame>, Self::Error> {
        Ok(self.frame.take())
    }
}

/// PCM packetizer.
///
/// # TODO
/// * Allow splitting audio frames to fit a given MTU.
pub struct PCMPacketizer {
    payload_type: u8,
    ssrc: u32,
    sequence_number: u16,
    packet: Option<RtpPacket>,
}

impl PCMPacketizer {
    /// Create a new PCM packetizer.
    #[inline]
    pub const fn new(payload_type: u8, ssrc: u32) -> Self {
        Self {
            payload_type,
            ssrc,
            sequence_number: 0,
            packet: None,
        }
    }
}

impl Packetizer for PCMPacketizer {
    type Frame = AudioFrame;
    type Error = Infallible;

    #[inline]
    fn push(&mut self, frame: Self::Frame) -> Result<(), Self::Error> {
        assert!(self.packet.is_none());

        let packet = RtpPacket::new()
            .with_payload_type(self.payload_type)
            .with_ssrc(self.ssrc)
            .with_sequence_number(self.sequence_number)
            .with_timestamp(frame.timestamp())
            .with_marker(true)
            .with_payload(frame.into_data(), 0);

        self.sequence_number = self.sequence_number.wrapping_add(1);

        self.packet = Some(packet);

        Ok(())
    }

    #[inline]
    fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    #[inline]
    fn take(&mut self) -> Result<Option<RtpPacket>, Self::Error> {
        Ok(self.packet.take())
    }
}
