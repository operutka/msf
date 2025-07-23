//! RTCP types.

mod bye;
mod handler;
mod report;

use std::ops::Deref;

use bytes::{Buf, Bytes, BytesMut};

use crate::InvalidInput;

pub use self::{
    bye::ByePacket,
    handler::{MuxedRtcpHandler, RtcpHandler},
    report::{ReceiverReport, ReportBlock, SenderReport},
};

/// Compound RTCP packet.
#[derive(Clone)]
pub struct CompoundRtcpPacket {
    inner: Vec<RtcpPacket>,
}

impl CompoundRtcpPacket {
    /// Create a new compound packet.
    #[inline]
    pub fn new<T>(packets: T) -> Self
    where
        T: Into<Vec<RtcpPacket>>,
    {
        Self {
            inner: packets.into(),
        }
    }

    /// Decode a compound RTCP packet.
    #[inline]
    pub fn decode(mut frame: Bytes) -> Result<Self, InvalidInput> {
        let mut res = Vec::new();

        while !frame.is_empty() {
            res.push(RtcpPacket::decode(&mut frame)?);
        }

        Ok(res.into())
    }

    /// Encode the packet.
    #[inline]
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.reserve(self.raw_size());

        for packet in &self.inner {
            packet.encode(buf);
        }
    }

    /// Get encoded size of the compound packet.
    #[inline]
    pub fn raw_size(&self) -> usize {
        self.inner.iter().map(|packet| packet.length()).sum()
    }
}

impl Deref for CompoundRtcpPacket {
    type Target = [RtcpPacket];

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl From<RtcpPacket> for CompoundRtcpPacket {
    #[inline]
    fn from(packet: RtcpPacket) -> Self {
        Self {
            inner: vec![packet],
        }
    }
}

impl<T> From<T> for CompoundRtcpPacket
where
    T: Into<Vec<RtcpPacket>>,
{
    #[inline]
    fn from(packets: T) -> Self {
        Self::new(packets)
    }
}

/// RTCP packet type.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum RtcpPacketType {
    SR,
    RR,
    SDES,
    BYE,
    Other(u8),
}

impl RtcpPacketType {
    /// Get type ID.
    #[inline]
    pub fn raw_id(self) -> u8 {
        match self {
            RtcpPacketType::SR => 200,
            RtcpPacketType::RR => 201,
            RtcpPacketType::SDES => 202,
            RtcpPacketType::BYE => 203,
            RtcpPacketType::Other(id) => id,
        }
    }
}

impl From<u8> for RtcpPacketType {
    #[inline]
    fn from(id: u8) -> RtcpPacketType {
        match id {
            200 => RtcpPacketType::SR,
            201 => RtcpPacketType::RR,
            202 => RtcpPacketType::SDES,
            203 => RtcpPacketType::BYE,
            id => RtcpPacketType::Other(id),
        }
    }
}

/// Helper struct.
#[repr(C, packed)]
struct RawRtcpHeader {
    options: u8,
    packet_type: u8,
    length: u16,
}

/// RTCP header.
#[derive(Copy, Clone)]
pub struct RtcpHeader {
    options: u8,
    packet_type: RtcpPacketType,
    length: u16,
}

impl RtcpHeader {
    /// Create a new packet header.
    #[inline]
    pub const fn new(packet_type: RtcpPacketType) -> Self {
        Self {
            options: 2 << 6,
            packet_type,
            length: 0,
        }
    }

    /// Decode an RTCP header.
    pub fn decode(data: &mut Bytes) -> Result<Self, InvalidInput> {
        if data.len() < std::mem::size_of::<RawRtcpHeader>() {
            return Err(InvalidInput);
        }

        let ptr = data.as_ptr() as *const RawRtcpHeader;

        let raw = unsafe { ptr.read_unaligned() };

        if (raw.options >> 6) != 2 {
            return Err(InvalidInput);
        }

        let res = Self {
            options: raw.options,
            packet_type: raw.packet_type.into(),
            length: u16::from_be(raw.length),
        };

        data.advance(std::mem::size_of::<RawRtcpHeader>());

        Ok(res)
    }

    /// Encode the header.
    pub fn encode(&self, buf: &mut BytesMut) {
        let raw = RawRtcpHeader {
            options: self.options,
            packet_type: self.packet_type.raw_id(),
            length: self.length.to_be(),
        };

        let ptr = &raw as *const _ as *const u8;

        let data = unsafe { std::slice::from_raw_parts(ptr, std::mem::size_of::<RawRtcpHeader>()) };

        buf.extend_from_slice(data);
    }

    /// Check if the padding bit is set.
    #[inline]
    pub fn padding(&self) -> bool {
        (self.options & 0x20) != 0
    }

    /// Set the padding bit.
    #[inline]
    pub fn with_padding(mut self, padding: bool) -> Self {
        self.options &= !0x20;
        self.options |= (padding as u8) << 5;
        self
    }

    /// Get packet length in bytes.
    #[inline]
    pub fn packet_length(&self) -> usize {
        ((self.length as usize) + 1) << 2
    }

    /// Set the packet length in bytes.
    ///
    /// Please note that the packet length must be a multiple of four and it
    /// must be from the range `4..=262_144`.
    ///
    /// # Panics
    /// The method panics if the constraints on the packet length mentioned
    /// above are not met.
    #[inline]
    pub fn with_packet_length(mut self, length: usize) -> Self {
        assert!((4..=262_144).contains(&length) && (length & 3) == 0);

        self.length = ((length >> 2) - 1) as u16;
        self
    }

    /// Get RTCP packet type.
    #[inline]
    pub fn packet_type(&self) -> RtcpPacketType {
        self.packet_type
    }

    /// Set RTCP packet type.
    #[inline]
    pub fn with_packet_type(mut self, packet_type: RtcpPacketType) -> Self {
        self.packet_type = packet_type;
        self
    }

    /// Get number of items in the packet body.
    ///
    /// Note: Only the lower 5 bits are actually used.
    #[inline]
    pub fn item_count(&self) -> u8 {
        self.options & 0x1f
    }

    /// Set the number of items in the packet body.
    ///
    /// # Panics
    /// The method panics if the number of items is greater than 31.
    #[inline]
    pub fn with_item_count(mut self, count: u8) -> Self {
        assert!(count < 32);

        self.options &= !0x1f;
        self.options |= count & 0x1f;
        self
    }

    /// Get encoded size of the header.
    #[inline]
    pub fn raw_size(&self) -> usize {
        std::mem::size_of::<RawRtcpHeader>()
    }
}

/// RTCP packet.
#[derive(Clone)]
pub struct RtcpPacket {
    header: RtcpHeader,
    payload: Bytes,
}

impl RtcpPacket {
    /// Create a new packet.
    #[inline]
    pub const fn new(packet_type: RtcpPacketType) -> Self {
        Self {
            header: RtcpHeader::new(packet_type),
            payload: Bytes::new(),
        }
    }

    /// Create a new RTCP packet from given parts.
    pub fn from_parts(header: RtcpHeader, payload: Bytes) -> Result<Self, InvalidInput> {
        if header.padding() {
            let padding_len = payload.last().copied().ok_or(InvalidInput)? as usize;

            if padding_len == 0 || payload.len() < padding_len {
                return Err(InvalidInput);
            }
        }

        let packet_len = header.packet_length();

        if packet_len != (payload.len() + 4) {
            return Err(InvalidInput);
        }

        let res = Self { header, payload };

        Ok(res)
    }

    /// Deconstruct the packet into its header and payload.
    #[inline]
    pub fn deconstruct(self) -> (RtcpHeader, Bytes) {
        (self.header, self.payload)
    }

    /// Decode an RTCP packet.
    pub fn decode(data: &mut Bytes) -> Result<Self, InvalidInput> {
        let mut buffer = data.clone();

        let header = RtcpHeader::decode(&mut buffer)?;

        let payload_len = header.packet_length() - 4;

        if buffer.len() < payload_len {
            return Err(InvalidInput);
        }

        let res = Self::from_parts(header, buffer.split_to(payload_len))?;

        *data = buffer;

        Ok(res)
    }

    /// Encode the packet.
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.reserve(self.header.packet_length());

        self.header.encode(buf);

        buf.extend_from_slice(&self.payload);
    }

    /// Get the packet header.
    #[inline]
    pub fn header(&self) -> &RtcpHeader {
        &self.header
    }

    /// Get the packet type.
    #[inline]
    pub fn packet_type(&self) -> RtcpPacketType {
        self.header.packet_type()
    }

    /// Set the packet type.
    #[inline]
    pub fn with_packet_type(mut self, packet_type: RtcpPacketType) -> Self {
        self.header = self.header.with_packet_type(packet_type);
        self
    }

    /// Get number of items in the packet body.
    ///
    /// Note: Only the lower 5 bits are actually used.
    #[inline]
    pub fn item_count(&self) -> u8 {
        self.header.item_count()
    }

    /// Set the number of items in the packet body.
    ///
    /// # Panics
    /// The method panics if the number of items is greater than 31.
    #[inline]
    pub fn with_item_count(mut self, count: u8) -> Self {
        self.header = self.header.with_item_count(count);
        self
    }

    /// Get packet length in bytes.
    #[inline]
    pub fn length(&self) -> usize {
        self.header.packet_length()
    }

    /// Get length of the optional padding.
    ///
    /// Zero means that the padding is not used at all.
    #[inline]
    pub fn padding(&self) -> u8 {
        if self.header.padding() {
            *self.payload.last().unwrap()
        } else {
            0
        }
    }

    /// Get the packet payload including the optional padding.
    #[inline]
    pub fn payload(&self) -> &Bytes {
        &self.payload
    }

    /// Get the packet payload without any padding.
    #[inline]
    pub fn stripped_payload(&self) -> Bytes {
        let payload_len = self.payload.len();
        let padding_len = self.padding() as usize;

        let len = payload_len - padding_len;

        self.payload.slice(..len)
    }

    /// Set the payload and add padding of a given length.
    ///
    /// If the padding is zero, no padding will be added and the padding bit in
    /// the RTP header will be set to zero.
    ///
    /// # Panics
    /// The method panics if the payload length including padding is not a
    /// multiple of four or if the payload length including padding is greater
    /// than 262_140.
    #[inline]
    pub fn with_payload(mut self, mut payload: Bytes, padding: u8) -> Self {
        if padding > 0 {
            let len = payload.len() + (padding as usize);

            let mut buffer = BytesMut::with_capacity(len);

            buffer.extend_from_slice(&payload);
            buffer.resize(len, 0);

            buffer[len - 1] = padding;

            payload = buffer.freeze();

            self.header = self
                .header
                .with_padding(true)
                .with_packet_length(4 + payload.len());
        } else {
            self.header = self
                .header
                .with_padding(false)
                .with_packet_length(4 + payload.len());
        }

        self.payload = payload;

        self
    }

    /// Set the payload that already includes padding.
    ///
    /// # Panics
    /// The method panics if the following conditions are not met:
    /// * The payload must not be empty.
    /// * The last byte of the payload (i.e. the length of the padding) must
    ///   not be zero.
    /// * The length of the padding must not be greater than the length of the
    ///   payload itself.
    /// * The payload length including padding must be a multiple of four.
    /// * The payload length including padding must not be greater than
    ///   262_140.
    #[inline]
    pub fn with_padded_payload(mut self, payload: Bytes) -> Self {
        let padding_len = payload.last().copied().expect("empty payload") as usize;

        assert!(padding_len > 0 && payload.len() >= padding_len);

        self.header = self
            .header
            .with_padding(true)
            .with_packet_length(payload.len());

        self.payload = payload;
        self
    }

    /// Get encoded size of the packet.
    #[inline]
    pub fn raw_size(&self) -> usize {
        self.length()
    }
}
