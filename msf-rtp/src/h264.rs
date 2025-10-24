use std::collections::VecDeque;

use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::{InvalidInput, Packetizer, RtpPacket};

/// RTP clock rate.
pub const CLOCK_RATE: u32 = 90_000;

/// Packetization mode used by the packetizer as defined in RFC 6184.
pub const PACKETIZATION_MODE: u8 = 1;

/// H.264 access unit.
#[derive(Clone)]
pub struct AccessUnit {
    data: Bytes,
    timestamp: u32,
}

impl AccessUnit {
    /// Create a new access unit with a given RTP timestamp.
    #[inline]
    pub const fn new(data: Bytes, timestamp: u32) -> Self {
        Self { data, timestamp }
    }

    /// Get the RTP timestamp.
    #[inline]
    pub fn timestamp(&self) -> u32 {
        self.timestamp
    }

    /// Get the access unit data.
    #[inline]
    pub fn data(&self) -> &Bytes {
        &self.data
    }

    /// Take the access unit data.
    #[inline]
    pub fn into_data(self) -> Bytes {
        self.data
    }
}

/// H.264 packetizer.
pub struct H264Packetizer {
    payload_type: u8,
    ssrc: u32,
    sequence_number: u16,
    packets: VecDeque<RtpPacket>,
    fragmentation_threshold: usize,
}

impl H264Packetizer {
    /// Create a new H.264 packetizer.
    #[inline]
    pub const fn new(payload_type: u8, ssrc: u32) -> Self {
        Self {
            payload_type,
            ssrc,
            sequence_number: 0,
            packets: VecDeque::new(),
            fragmentation_threshold: 1188,
        }
    }

    /// Set the maximum RTP packet size.
    ///
    /// The default limit is 1200 bytes. This should be safe for UDP transport
    /// in IPv4/IPv6 networks with typical MTU sizes across the Internet.
    ///
    /// # Panics
    /// The method will panic if the given size is less than 128 bytes.
    #[inline]
    pub const fn with_max_rtp_packet_size(mut self, size: usize) -> Self {
        assert!(size >= 128);

        // NOTE: The minimum RTP header size is 12 bytes. We don't set any
        //   additional extensions or CSRC identifiers.
        self.fragmentation_threshold = size - 12;
        self
    }

    /// Create a single RTP packet from a given NAL unit.
    fn push_single_nal_unit(&mut self, timestamp: u32, marker: bool, nal_unit: Bytes) {
        debug_assert!(nal_unit.len() <= self.fragmentation_threshold);

        let packet = RtpPacket::new()
            .with_payload_type(self.payload_type)
            .with_ssrc(self.ssrc)
            .with_sequence_number(self.sequence_number)
            .with_timestamp(timestamp)
            .with_marker(marker)
            .with_payload(nal_unit, 0);

        self.sequence_number = self.sequence_number.wrapping_add(1);

        self.packets.push_back(packet)
    }

    /// Fragment a given NAL unit into several FU-A RTP packets.
    fn push_fragmented_nal_unit(&mut self, timestamp: u32, marker: bool, mut nal_unit: Bytes) {
        debug_assert!(nal_unit.len() > self.fragmentation_threshold);

        let nal_unit_type = nal_unit[0] & 0x1f;

        let indicator: u8 = (nal_unit[0] & 0xe0) | 28;

        let mut header: u8 = 0x80 | nal_unit_type;

        // skip the NAL unit type
        nal_unit.advance(1);

        while !nal_unit.is_empty() {
            let available = nal_unit.len();
            let take = available.min(self.fragmentation_threshold - 2);
            let chunk = nal_unit.split_to(take);

            // set the fragmentation end bit if this is the last chunk
            if nal_unit.is_empty() {
                header |= 0x40;
            }

            let mut payload = BytesMut::with_capacity(2 + chunk.len());

            payload.put_u8(indicator);
            payload.put_u8(header);
            payload.extend_from_slice(&chunk);

            // reset the start bit
            header &= 0x7f;

            let packet = RtpPacket::new()
                .with_payload_type(self.payload_type)
                .with_ssrc(self.ssrc)
                .with_sequence_number(self.sequence_number)
                .with_timestamp(timestamp)
                .with_marker(marker && nal_unit.is_empty())
                .with_payload(payload.freeze(), 0);

            self.sequence_number = self.sequence_number.wrapping_add(1);

            self.packets.push_back(packet);
        }
    }
}

impl Packetizer for H264Packetizer {
    type Frame = AccessUnit;
    type Error = InvalidInput;

    fn push(&mut self, unit: AccessUnit) -> Result<(), Self::Error> {
        let timestamp = unit.timestamp();

        let mut data = unit.into_data();

        let mut next_nal_unit = extract_nal_unit(&mut data)?;

        loop {
            let current_nal_unit = next_nal_unit;

            next_nal_unit = extract_nal_unit(&mut data)?;

            let nal_unit = if let Some(nal_unit) = current_nal_unit {
                if nal_unit.is_empty() {
                    continue;
                } else {
                    nal_unit
                }
            } else {
                break;
            };

            // check if this is the last NAL unit in the AU
            let marker = next_nal_unit.is_none();

            let nal_unit_type = nal_unit[0] & 0x1f;

            if nal_unit_type == 0 || nal_unit_type > 23 {
                return Err(InvalidInput);
            } else if nal_unit.len() > self.fragmentation_threshold {
                self.push_fragmented_nal_unit(timestamp, marker, nal_unit);
            } else {
                self.push_single_nal_unit(timestamp, marker, nal_unit);
            }
        }

        Ok(())
    }

    #[inline]
    fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    #[inline]
    fn take(&mut self) -> Result<Option<RtpPacket>, Self::Error> {
        Ok(self.packets.pop_front())
    }
}

/// Extract the next H.264 NAL unit.
fn extract_nal_unit(data: &mut Bytes) -> Result<Option<Bytes>, InvalidInput> {
    msf_util::h264::extract_nal_unit(data).map_err(|_| InvalidInput)
}
