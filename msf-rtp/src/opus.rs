//! Opus audio (de)packetizer.

use std::convert::Infallible;

use bytes::Bytes;

use crate::{depacketizer::Depacketizer, packetizer::Packetizer, rtp::RtpPacket};

/// Opus audio frame.
#[derive(Clone)]
pub struct AudioFrame {
    data: Bytes,
    timestamp: u32,
}

impl AudioFrame {
    /// Create a new audio frame with a given RTP timestamp.
    #[inline]
    pub const fn new(timestamp: u32, data: Bytes) -> Self {
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

/// Opus depacketizer.
pub struct OpusDepacketizer {
    payload_type: u8,
    frame: Option<AudioFrame>,
}

impl OpusDepacketizer {
    /// Create a new Opus depacketizer.
    #[inline]
    pub const fn new(payload_type: u8) -> Self {
        Self {
            payload_type,
            frame: None,
        }
    }
}

impl Depacketizer for OpusDepacketizer {
    type Frame = AudioFrame;
    type Error = Infallible;

    fn push(&mut self, packet: RtpPacket) -> Result<(), Self::Error> {
        if packet.payload_type() != self.payload_type {
            return Ok(());
        }

        assert!(self.frame.is_none());

        let timestamp = packet.timestamp();
        let data = packet.stripped_payload();

        self.frame = Some(AudioFrame::new(timestamp, data));

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

/// Opus packetizer.
pub struct OpusPacketizer {
    payload_type: u8,
    ssrc: u32,
    sequence_number: u16,
    packet: Option<RtpPacket>,
}

impl OpusPacketizer {
    /// Create a new Opus packetizer.
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

impl Packetizer for OpusPacketizer {
    type Frame = AudioFrame;
    type Error = Infallible;

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
