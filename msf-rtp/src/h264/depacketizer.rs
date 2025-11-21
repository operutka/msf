use bytes::{Buf, Bytes, BytesMut};

use crate::{
    depacketizer::Depacketizer,
    h264::{
        au::{AccessUnit, AccessUnitBuilder},
        dts::DTSSequenceBuilder,
        reorder::ReorderingBuffer,
    },
    rtp::RtpPacket,
    Error,
};

/// Builder for the H.264 depacketizer.
pub struct H264DepacketizerBuilder {
    rtp_payload_type: u8,
    interleaving_depth: u16,
    max_don_diff: Option<u16>,
    ignore_decoding_errors: bool,
}

impl H264DepacketizerBuilder {
    /// Create a new H.264 depacketizer builder.
    #[inline]
    const fn new(rtp_payload_type: u8) -> Self {
        Self {
            rtp_payload_type,
            interleaving_depth: 0,
            max_don_diff: None,
            ignore_decoding_errors: true,
        }
    }

    /// Set the interleaving depth.
    ///
    /// The value should be equal to the `sprop-interleaving-depth` parameter
    /// from the corresponding session description. The default value is `0`.
    #[inline]
    pub const fn interleaving_depth(mut self, depth: u16) -> Self {
        self.interleaving_depth = depth;
        self
    }

    /// Set the maximum allowed DON difference for reordering.
    ///
    /// The value should be equal to the `sprop-max-don-diff` parameter from
    /// the corresponding session description. The default value is `None`.
    #[inline]
    pub const fn max_don_diff(mut self, max_don_diff: Option<u16>) -> Self {
        self.max_don_diff = max_don_diff;
        self
    }

    /// Set whether packet decoding errors should be ignored.
    ///
    /// The default is `true`.
    #[inline]
    pub const fn ignore_decoding_errors(mut self, ignore: bool) -> Self {
        self.ignore_decoding_errors = ignore;
        self
    }

    /// Build the H.264 depacketizer.
    pub fn build(self) -> H264Depacketizer {
        let max_nal_units = self.interleaving_depth as usize;

        let max_don_diff = if max_nal_units == 0 {
            0
        } else {
            self.max_don_diff.unwrap_or(32_768)
        };

        H264Depacketizer {
            ignore_decoding_errors: self.ignore_decoding_errors,

            rtp_payload_type: self.rtp_payload_type,
            last_rtp_seq: None,
            last_rtp_timestamp: None,
            session_rtp_timestamp: 0,

            fu_buffer: BytesMut::new(),
            fu_don: 0,
            fu_timestamp: 0,

            last_don: u16::MAX,
            reordering_buffer: ReorderingBuffer::new(max_don_diff, max_nal_units),
            au_builder: AccessUnitBuilder::new(),
            decoding_timestamps: DTSSequenceBuilder::new(),
        }
    }
}

/// H.264 depacketizer.
pub struct H264Depacketizer {
    ignore_decoding_errors: bool,

    rtp_payload_type: u8,
    last_rtp_seq: Option<u16>,
    last_rtp_timestamp: Option<u32>,
    session_rtp_timestamp: u64,

    fu_buffer: BytesMut,
    fu_don: u16,
    fu_timestamp: u32,

    last_don: u16,
    reordering_buffer: ReorderingBuffer<NalUnit>,
    au_builder: AccessUnitBuilder,
    decoding_timestamps: DTSSequenceBuilder,
}

impl H264Depacketizer {
    /// Get a builder for H.264 the depacketizer.
    #[inline]
    pub const fn builder(rtp_payload_type: u8) -> H264DepacketizerBuilder {
        H264DepacketizerBuilder::new(rtp_payload_type)
    }

    /// Try to decode NAL units from a given packet.
    fn decode_packet(&mut self, packet: InternalRtpPacket) -> Result<(), Error> {
        // drop packets with unexpected payload type
        if packet.payload_type() != self.rtp_payload_type {
            return Ok(());
        }

        self.check_packet_loss(&packet);

        self.last_rtp_seq = Some(packet.sequence_number());

        let header = packet.payload().first().copied().unwrap_or(0);

        let nal_unit_type = header & 0x1f;

        if !matches!(nal_unit_type, 0x1c | 0x1d) {
            // NOTE: We need to commit any unfinished FU before accepting a
            //   non-FU packet. The packet loss check should normally deal with
            //   it, so there's probably something wrong within the RTP stream
            //   and we need to indicate syntax violation.
            self.commit_fragmentation_unit(true);
        }

        // decode the packet according to its type
        match nal_unit_type {
            0x00 => Ok(()), // ignored type
            0x18 => self.decode_stapa_packet(packet),
            0x19 => self.decode_stapb_packet(packet),
            0x1a => self.decode_mtap16_packet(packet),
            0x1b => self.decode_mtap24_packet(packet),
            0x1c => self.decode_fua_packet(packet),
            0x1d => self.decode_fub_packet(packet),
            0x1e => Ok(()), // reserved, we have to ignore this type
            0x1f => Ok(()), // reserved, we have to ignore this type
            _ => self.decode_single_nal_unit_packet(packet),
        }

        // NOTE: Some RTSP servers set the marker bit for all packets, this
        //   leads to situations, where two consecutive access units have the
        //   same RTP timestamp. We'll ignore the marker bit and split the
        //   access units only by their timestamps.

        /*// finalize the current access unit if this is the last packet
        if packet.marker() {
            self.finalize_access_unit();
        }

        res*/
    }

    /// Check for packet loss by comparing a given packet with the previously
    /// received RTP sequence number.
    fn check_packet_loss(&mut self, packet: &InternalRtpPacket) {
        if let Some(n) = self.last_rtp_seq {
            if n.wrapping_add(1) != packet.sequence_number() {
                self.commit_fragmentation_unit(true);
            }
        }
    }

    /// Decode a given single NAL unit packet.
    fn decode_single_nal_unit_packet(&mut self, packet: InternalRtpPacket) -> Result<(), Error> {
        let timestamp = packet.timestamp();
        let payload = packet.payload();

        // NOTE: Even though DON is not associated with single NAL unit
        //   packets, we can craft an artificial DON value here to avoid
        //   handling non-interleaved streams as a special case. We simply
        //   increment the last DON value by one. This is safe because packets
        //   with explicit DON values (e.g., STAP-B, MTAP, FU-B) are not
        //   allowed to mix with packets without DON values.
        let don = self.last_don.wrapping_add(1);

        self.push_nal_unit(don, timestamp, payload.clone());

        Ok(())
    }

    /// Decode a given STAP-A packet.
    fn decode_stapa_packet(&mut self, packet: InternalRtpPacket) -> Result<(), Error> {
        let timestamp = packet.timestamp();
        let payload = packet.payload();

        let mut data = payload.clone();

        data.advance(1);

        while !data.is_empty() {
            let nal_unit_len = data
                .try_get_u16()
                .map(|v| v as usize)
                .map_err(|_| Error::from_static_msg("invalid STAP-A packet"))?;

            if data.len() < nal_unit_len {
                return Err(Error::from_static_msg("invalid STAP-A packet"));
            }

            // NOTE: See `decode_single_nal_unit_packet` for explanation of
            //   the artificial DON values.
            let don = self.last_don.wrapping_add(1);

            let nal_unit = data.split_to(nal_unit_len);

            if !nal_unit.is_empty() {
                self.push_nal_unit(don, timestamp, nal_unit);
            } else if !self.ignore_decoding_errors {
                return Err(Error::from_static_msg("invalid STAP-A packet"));
            }
        }

        Ok(())
    }

    /// Decode a given STAP-B packet.
    fn decode_stapb_packet(&mut self, packet: InternalRtpPacket) -> Result<(), Error> {
        let timestamp = packet.timestamp();
        let payload = packet.payload();

        let mut data = payload.clone();

        data.advance(1);

        let mut don = data
            .try_get_u16()
            .map_err(|_| Error::from_static_msg("invalid STAP-B packet"))?;

        while !data.is_empty() {
            let nal_unit_len = data
                .try_get_u16()
                .map(|v| v as usize)
                .map_err(|_| Error::from_static_msg("invalid STAP-B packet"))?;

            if data.len() < nal_unit_len {
                return Err(Error::from_static_msg("invalid STAP-B packet"));
            }

            let nal_unit = data.split_to(nal_unit_len);

            if !nal_unit.is_empty() {
                self.push_nal_unit(don, timestamp, nal_unit);
            } else if !self.ignore_decoding_errors {
                return Err(Error::from_static_msg("invalid STAP-B packet"));
            }

            don = don.wrapping_add(1);
        }

        Ok(())
    }

    /// Decode a given MTAP16 packet.
    fn decode_mtap16_packet(&mut self, packet: InternalRtpPacket) -> Result<(), Error> {
        let packet_rtp_timestamp = packet.timestamp();
        let payload = packet.payload();

        let mut data = payload.clone();

        data.advance(1);

        let donb = data
            .try_get_u16()
            .map_err(|_| Error::from_static_msg("invalid MTAP16 packet"))?;

        while !data.is_empty() {
            let header = Mtap16RawHeader::from_bytes(&mut data)?;

            if data.len() < header.nal_unit_size() {
                return Err(Error::from_static_msg("invalid MTAP16 packet"));
            }

            let nal_unit = data.split_to(header.nal_unit_size());

            if !nal_unit.is_empty() {
                let don = donb.wrapping_add(header.dond());
                let timestamp = packet_rtp_timestamp.wrapping_add(header.ts_offset());

                // XXX: Even though RFC 6184 does not guarantee monotonicity of
                //   RTP timestamps in MTAP packets, we have to assume it here
                //   to be able to reconstruct the session RTP timestamps.
                //   Otherwise, we wouldn't be able to calculate extended RTP
                //   timestamps.
                self.push_nal_unit(don, timestamp, nal_unit);
            } else if !self.ignore_decoding_errors {
                return Err(Error::from_static_msg("invalid MTAP16 packet"));
            }
        }

        Ok(())
    }

    /// Decode a given MTAP24 packet.
    fn decode_mtap24_packet(&mut self, packet: InternalRtpPacket) -> Result<(), Error> {
        let packet_rtp_timestamp = packet.timestamp();
        let payload = packet.payload();

        let mut data = payload.clone();

        data.advance(1);

        let donb = data
            .try_get_u16()
            .map_err(|_| Error::from_static_msg("invalid MTAP24 packet"))?;

        while !data.is_empty() {
            let header = Mtap24RawHeader::from_bytes(&mut data)?;

            if data.len() < header.nal_unit_size() {
                return Err(Error::from_static_msg("invalid MTAP24 packet"));
            }

            let nal_unit = data.split_to(header.nal_unit_size());

            if !nal_unit.is_empty() {
                let don = donb.wrapping_add(header.dond());
                let timestamp = packet_rtp_timestamp.wrapping_add(header.ts_offset());

                // XXX: Even though RFC 6184 does not guarantee monotonicity of
                //   RTP timestamps in MTAP packets, we have to assume it here
                //   to be able to reconstruct the session RTP timestamps.
                //   Otherwise, we wouldn't be able to calculate extended RTP
                //   timestamps.
                self.push_nal_unit(don, timestamp, nal_unit);
            } else if !self.ignore_decoding_errors {
                return Err(Error::from_static_msg("invalid MTAP24 packet"));
            }
        }

        Ok(())
    }

    /// Decode a given FU-A packet.
    fn decode_fua_packet(&mut self, packet: InternalRtpPacket) -> Result<(), Error> {
        let data = packet.payload();

        if data.len() < 2 {
            return Err(Error::from_static_msg("invalid FU-A packet"));
        }

        // start/end indicator
        let se_indicator = data[1] >> 6;

        if se_indicator == 0x00 || se_indicator == 0x01 {
            self.decode_fua_continuation_packet(packet)
        } else if se_indicator == 0x02 {
            self.decode_fua_start_packet(packet)
        } else {
            Err(Error::from_static_msg("invalid FU-A packet"))
        }
    }

    /// Decode a given FU-A start packet.
    fn decode_fua_start_packet(&mut self, packet: InternalRtpPacket) -> Result<(), Error> {
        let payload = packet.payload();

        let mut data = payload.clone();

        let nal_unit_header = (data[0] & 0xe0) | (data[1] & 0x1f);

        data.advance(2);

        // Commit the unfinished fragmentation unit (if any). The packet loss
        // check should normally deal with it, so there's probably something
        // wrong within the RTP stream. Set the forbidden zero bit to indicate
        // syntax errors within the NAL unit and finalize it.
        self.commit_fragmentation_unit(true);

        self.fu_timestamp = packet.timestamp();

        // NOTE: See `decode_single_nal_unit_packet` for explanation of
        //   the artificial DON values.
        self.fu_don = self.last_don.wrapping_add(1);

        self.fu_buffer.extend_from_slice(&[nal_unit_header]);

        self.fu_buffer.extend_from_slice(data.as_ref());

        Ok(())
    }

    /// Decode a given FU-A continuation packet.
    fn decode_fua_continuation_packet(&mut self, packet: InternalRtpPacket) -> Result<(), Error> {
        let payload = packet.payload();

        let mut data = payload.clone();

        let nal_unit_header = (data[0] & 0xe0) | (data[1] & 0x1f);

        // start/end indicator
        let se_indicator = data[1] >> 6;

        data.advance(2);

        // We have to ignore all remaining FU-A packets of the same NAL unit in
        // case of packet loss.
        if self.fu_buffer.is_empty() {
            return Ok(());
        }

        self.fu_buffer[0] |= nal_unit_header & 0x80;

        self.fu_buffer.extend_from_slice(data.as_ref());

        if se_indicator == 0x01 {
            self.commit_fragmentation_unit(false);
        }

        Ok(())
    }

    /// Decode a given FU-B packet.
    fn decode_fub_packet(&mut self, packet: InternalRtpPacket) -> Result<(), Error> {
        let payload = packet.payload();

        let mut data = payload.clone();

        if data.len() < (2 + std::mem::size_of::<u16>()) {
            return Err(Error::from_static_msg("invalid FU-B packet"));
        }

        let nal_unit_header = (data[0] & 0xe0) | (data[1] & 0x1f);

        // start indicator
        if (data[1] >> 6) != 0x02 {
            return Err(Error::from_static_msg("invalid FU-B packet"));
        }

        // remove the two header bytes
        data.advance(2);

        // Commit the unfinished fragmentation unit (if any). The packet loss
        // check should normally deal with it, so there's probably something
        // wrong within the RTP stream. Set the forbidden zero bit to indicate
        // syntax errors within the NAL unit and finalize it.
        self.commit_fragmentation_unit(true);

        self.fu_timestamp = packet.timestamp();

        self.fu_don = data.get_u16();

        self.fu_buffer.extend_from_slice(&[nal_unit_header]);

        self.fu_buffer.extend_from_slice(data.as_ref());

        Ok(())
    }

    /// Commit the current fragmentation unit.
    fn commit_fragmentation_unit(&mut self, syntax_violation: bool) {
        if self.fu_buffer.is_empty() {
            return;
        }

        if syntax_violation {
            self.fu_buffer[0] |= 0x80;
        }

        let data = self.fu_buffer.split();

        self.push_nal_unit(self.fu_don, self.fu_timestamp, data.freeze());
    }

    /// Finalize the current access unit (if needed) and put a given NAL unit
    /// into the current/new access unit.
    fn push_nal_unit(&mut self, don: u16, rtp_timestamp: u32, nal_unit: Bytes) {
        let previous_rtp_timestamp = self.last_rtp_timestamp.unwrap_or(rtp_timestamp);

        let rtp_timestamp_diff = rtp_timestamp.wrapping_sub(previous_rtp_timestamp);

        self.session_rtp_timestamp = self
            .session_rtp_timestamp
            .wrapping_add(rtp_timestamp_diff as u64);

        self.last_rtp_timestamp = Some(rtp_timestamp);

        self.last_don = don;

        self.decoding_timestamps
            .push_rtp_timestamp(self.session_rtp_timestamp);

        let nal_unit = NalUnit::new(self.session_rtp_timestamp, nal_unit);

        self.reordering_buffer.push(don, nal_unit);

        while let Some(nal_unit) = self.reordering_buffer.take() {
            self.au_builder
                .push(nal_unit.rtp_timestamp, nal_unit.as_ref());
        }

        // XXX: Sanity check to prevent the DTS queue from growing too long.
        //   Buggy RTP streams can have distinct RTP timestamps for every RTP
        //   packet instead of using the same RTP timestamp for all NAL units
        //   in the same access unit. This could cause a nasty memory leak.
        let max_decoding_timestamps =
            1 + self.reordering_buffer.len() + self.au_builder.available();

        while self.decoding_timestamps.available() > max_decoding_timestamps {
            self.decoding_timestamps.next_decoding_timestamp();
        }
    }
}

impl Depacketizer for H264Depacketizer {
    type Frame = AccessUnit;
    type Error = Error;

    fn push(&mut self, packet: RtpPacket) -> Result<(), Self::Error> {
        match self.decode_packet(packet.into()) {
            Ok(()) => Ok(()),
            Err(_) if self.ignore_decoding_errors => Ok(()),
            Err(err) => Err(err),
        }
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        // finalize the current fragmented NAL unit (if any)
        self.commit_fragmentation_unit(true);

        // ... flush the reordering buffer
        while let Some(nal_unit) = self.reordering_buffer.flush() {
            self.au_builder
                .push(nal_unit.rtp_timestamp, nal_unit.nal_unit.as_ref());
        }

        // ... and finalize the current access unit (if any)
        self.au_builder.flush();

        Ok(())
    }

    fn take(&mut self) -> Result<Option<Self::Frame>, Self::Error> {
        let Some(au) = self.au_builder.take() else {
            return Ok(None);
        };

        let dts = self.decoding_timestamps.next_decoding_timestamp();

        Ok(Some(au.with_decoding_timestamp(dts)))
    }
}

/// Helper struct.
struct InternalRtpPacket {
    payload_type: u8,
    sequence_number: u16,
    timestamp: u32,
    payload: Bytes,
}

impl InternalRtpPacket {
    /// Get the payload type.
    fn payload_type(&self) -> u8 {
        self.payload_type
    }

    /// Get the sequence number.
    fn sequence_number(&self) -> u16 {
        self.sequence_number
    }

    /// Get the timestamp.
    fn timestamp(&self) -> u32 {
        self.timestamp
    }

    /// Get the payload.
    fn payload(&self) -> &Bytes {
        &self.payload
    }
}

impl From<RtpPacket> for InternalRtpPacket {
    fn from(packet: RtpPacket) -> Self {
        Self {
            payload_type: packet.payload_type(),
            sequence_number: packet.sequence_number(),
            timestamp: packet.timestamp(),
            payload: packet.stripped_payload(),
        }
    }
}

/// H.264 NAL unit types.
#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum NalUnitType {
    NonIDR,
    IDR,
    PartitionA,
    PartitionB,
    PartitionC,
    SEI,
    SPS,
    PPS,
    Other(u8),
}

impl From<u8> for NalUnitType {
    fn from(id: u8) -> Self {
        match id & 0x1f {
            0x01 => Self::NonIDR,
            0x02 => Self::PartitionA,
            0x03 => Self::PartitionB,
            0x04 => Self::PartitionC,
            0x05 => Self::IDR,
            0x06 => Self::SEI,
            0x07 => Self::SPS,
            0x08 => Self::PPS,
            other => Self::Other(other),
        }
    }
}

/// NAL unit with the corresponding extended timestamp.
struct NalUnit {
    rtp_timestamp: u64,
    nal_unit: Bytes,
}

impl NalUnit {
    /// Create a new NAL unit.
    fn new(rtp_timestamp: u64, nal_unit: Bytes) -> Self {
        Self {
            rtp_timestamp,
            nal_unit,
        }
    }
}

impl AsRef<[u8]> for NalUnit {
    fn as_ref(&self) -> &[u8] {
        &self.nal_unit
    }
}

/// MTAP16 entity header.
#[repr(C, packed)]
#[derive(Copy, Clone)]
struct Mtap16RawHeader {
    nal_unit_size: u16,
    dond: u8,
    ts_offset: u16,
}

impl Mtap16RawHeader {
    /// Parse an MTAP16 entity header from given data.
    fn from_bytes(data: &mut Bytes) -> Result<Self, Error> {
        if data.len() < std::mem::size_of::<Self>() {
            return Err(Error::from_static_msg("invalid MTAP16 packet"));
        }

        let ptr = data.as_ptr() as *const Self;

        let hdr = unsafe { ptr.read_unaligned() };

        let res = Self {
            nal_unit_size: u16::from_be(hdr.nal_unit_size),
            dond: hdr.dond,
            ts_offset: u16::from_be(hdr.ts_offset),
        };

        data.advance(std::mem::size_of::<Self>());

        Ok(res)
    }

    /// Get size of the NAL unit.
    fn nal_unit_size(self) -> usize {
        self.nal_unit_size as usize
    }

    /// Get DOND.
    fn dond(self) -> u16 {
        self.dond as u16
    }

    /// Get RTP timestamp offset.
    fn ts_offset(self) -> u32 {
        self.ts_offset as u32
    }
}

/// MTAP24 entity header.
#[repr(C, packed)]
#[derive(Copy, Clone)]
struct Mtap24RawHeader {
    nal_unit_size: u16,
    dond_ts_offset: u32,
}

impl Mtap24RawHeader {
    /// Parse an MTAP24 entity header from given data.
    fn from_bytes(data: &mut Bytes) -> Result<Self, Error> {
        if data.len() < std::mem::size_of::<Self>() {
            return Err(Error::from_static_msg("invalid MTAP24 packet"));
        }

        let ptr = data.as_ptr() as *const Self;

        let hdr = unsafe { ptr.read_unaligned() };

        let res = Self {
            nal_unit_size: u16::from_be(hdr.nal_unit_size),
            dond_ts_offset: u32::from_be(hdr.dond_ts_offset),
        };

        data.advance(std::mem::size_of::<Self>());

        Ok(res)
    }

    /// Get size of the NAL unit.
    fn nal_unit_size(self) -> usize {
        self.nal_unit_size as usize
    }

    /// Get DOND.
    fn dond(self) -> u16 {
        (self.dond_ts_offset >> 24) as u16
    }

    /// Get RTP timestamp offset.
    fn ts_offset(self) -> u32 {
        self.dond_ts_offset & 0x00ff_ffff
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use crate::depacketizer::Depacketizer;

    use super::H264Depacketizer;

    #[test]
    fn test_dts_sequence_construction() {
        let mut depacketizer = H264Depacketizer::builder(96)
            .interleaving_depth(4)
            .max_don_diff(Some(3))
            .build();

        let mut push = |don, rtp_timestamp, nal_unit_type| {
            depacketizer.push_nal_unit(don, rtp_timestamp, Bytes::copy_from_slice(&[nal_unit_type]))
        };

        push(5, 0, 0x05);
        push(6, 0, 0x05);

        push(7, 1, 0x05);

        push(0, 3, 0x05);
        push(1, 3, 0x05);
        push(2, 3, 0x05);
        push(3, 3, 0x05);
        push(4, 3, 0x05);

        push(8, 4, 0x05);

        push(9, 5, 0x05);

        let au = depacketizer.take().unwrap().unwrap();

        assert_eq!(au.presentation_timestamp(), 3);
        assert_eq!(au.decoding_timestamp(), 0);

        depacketizer.flush().unwrap();

        let au = depacketizer.take().unwrap().unwrap();

        assert_eq!(au.presentation_timestamp(), 0);
        assert_eq!(au.decoding_timestamp(), 1);

        let au = depacketizer.take().unwrap().unwrap();

        assert_eq!(au.presentation_timestamp(), 1);
        assert_eq!(au.decoding_timestamp(), 3);

        let au = depacketizer.take().unwrap().unwrap();

        assert_eq!(au.presentation_timestamp(), 4);
        assert_eq!(au.decoding_timestamp(), 4);

        let au = depacketizer.take().unwrap().unwrap();

        assert_eq!(au.presentation_timestamp(), 5);
        assert_eq!(au.decoding_timestamp(), 5);

        let au = depacketizer.take().unwrap();

        assert!(au.is_none());
    }
}
