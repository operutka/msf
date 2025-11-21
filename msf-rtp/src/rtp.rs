use std::{borrow::Borrow, ops::Deref, time::Instant};

use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::InvalidInput;

/// Helper struct.
#[repr(C, packed)]
struct RawRtpHeader {
    options: u16,
    sequence_number: u16,
    timestamp: u32,
    ssrc: u32,
}

/// RTP header.
#[derive(Clone)]
pub struct RtpHeader {
    options: u16,
    sequence_number: u16,
    timestamp: u32,
    ssrc: u32,
    csrcs: Vec<u32>,
    extension: Option<RtpHeaderExtension>,
}

impl RtpHeader {
    /// Create a new RTP header.
    #[inline]
    pub const fn new() -> Self {
        Self {
            options: 2 << 14,
            sequence_number: 0,
            timestamp: 0,
            ssrc: 0,
            csrcs: Vec::new(),
            extension: None,
        }
    }

    /// Decode an RTP header from given data.
    pub fn decode(data: &mut Bytes) -> Result<Self, InvalidInput> {
        let mut buffer = data.clone();

        if buffer.len() < std::mem::size_of::<RawRtpHeader>() {
            return Err(InvalidInput::new());
        }

        let ptr = buffer.as_ptr() as *const RawRtpHeader;

        let raw = unsafe { ptr.read_unaligned() };

        let mut res = Self {
            options: u16::from_be(raw.options),
            sequence_number: u16::from_be(raw.sequence_number),
            timestamp: u32::from_be(raw.timestamp),
            ssrc: u32::from_be(raw.ssrc),
            csrcs: Vec::new(),
            extension: None,
        };

        buffer.advance(std::mem::size_of::<RawRtpHeader>());

        if (res.options >> 14) != 2 {
            return Err(InvalidInput::new());
        }

        let csrc_count = ((res.options >> 8) & 0xf) as usize;

        if buffer.len() < (csrc_count << 2) {
            return Err(InvalidInput::new());
        }

        res.csrcs = Vec::with_capacity(csrc_count);

        for _ in 0..csrc_count {
            res.csrcs.push(buffer.get_u32());
        }

        if (res.options & 0x1000) != 0 {
            res.extension = Some(RtpHeaderExtension::decode(&mut buffer)?);
        }

        *data = buffer;

        Ok(res)
    }

    /// Encode the header.
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.reserve(self.raw_size());

        let raw = RawRtpHeader {
            options: self.options.to_be(),
            sequence_number: self.sequence_number.to_be(),
            timestamp: self.timestamp.to_be(),
            ssrc: self.ssrc.to_be(),
        };

        let ptr = &raw as *const _ as *const u8;

        let data = unsafe { std::slice::from_raw_parts(ptr, std::mem::size_of::<RawRtpHeader>()) };

        buf.extend_from_slice(data);

        for csrc in &self.csrcs {
            buf.put_u32(*csrc);
        }

        if let Some(extension) = self.extension.as_ref() {
            extension.encode(buf);
        }
    }

    /// Check if the RTP packet contains any padding.
    #[inline]
    pub fn padding(&self) -> bool {
        (self.options & 0x2000) != 0
    }

    /// Set the padding bit.
    #[inline]
    pub fn with_padding(mut self, padding: bool) -> Self {
        self.options &= !0x2000;
        self.options |= (padding as u16) << 13;
        self
    }

    /// Check if there is an RTP header extension.
    #[inline]
    pub fn extension(&self) -> Option<&RtpHeaderExtension> {
        self.extension.as_ref()
    }

    /// Set the extension bit.
    #[inline]
    pub fn with_extension(mut self, extension: Option<RtpHeaderExtension>) -> Self {
        self.options &= !0x1000;
        self.options |= (extension.is_some() as u16) << 12;
        self.extension = extension;
        self
    }

    /// Check if the RTP marker bit is set.
    #[inline]
    pub fn marker(&self) -> bool {
        (self.options & 0x0080) != 0
    }

    /// Set the marker bit.
    #[inline]
    pub fn with_marker(mut self, marker: bool) -> Self {
        self.options &= !0x0080;
        self.options |= (marker as u16) << 7;
        self
    }

    /// Get RTP payload type.
    ///
    /// Note: Only the lower 7 bits are used.
    #[inline]
    pub fn payload_type(&self) -> u8 {
        (self.options & 0x7f) as u8
    }

    /// Set the payload type.
    ///
    /// # Panics
    /// The method panics if the payload type is greater than 127.
    #[inline]
    pub fn with_payload_type(mut self, payload_type: u8) -> Self {
        assert!(payload_type < 128);

        self.options &= !0x7f;
        self.options |= (payload_type & 0x7f) as u16;
        self
    }

    /// Get RTP sequence number.
    #[inline]
    pub fn sequence_number(&self) -> u16 {
        self.sequence_number
    }

    /// Set the sequence number.
    #[inline]
    pub fn with_sequence_number(mut self, n: u16) -> Self {
        self.sequence_number = n;
        self
    }

    /// Get RTP timestamp.
    #[inline]
    pub fn timestamp(&self) -> u32 {
        self.timestamp
    }

    /// Set RTP timestamp.
    #[inline]
    pub fn with_timestamp(mut self, timestamp: u32) -> Self {
        self.timestamp = timestamp;
        self
    }

    /// Get the SSRC identifier.
    #[inline]
    pub fn ssrc(&self) -> u32 {
        self.ssrc
    }

    /// Set the SSRC identifier.
    #[inline]
    pub fn with_ssrc(mut self, ssrc: u32) -> Self {
        self.ssrc = ssrc;
        self
    }

    /// Get a list of CSRC identifiers.
    #[inline]
    pub fn csrcs(&self) -> &[u32] {
        &self.csrcs
    }

    /// Set the CSRC identifiers.
    ///
    /// # Panics
    /// The method panics if the number of identifiers is greater than 255.
    pub fn with_csrcs<T>(mut self, csrcs: T) -> Self
    where
        T: Into<Vec<u32>>,
    {
        let csrcs = csrcs.into();

        assert!(csrcs.len() <= 0xf);

        self.csrcs = csrcs;
        self.options &= !0xf00;
        self.options |= (self.csrcs.len() as u16) << 8;
        self
    }

    /// Get raw size of the header (i.e. byte length of the encoded header).
    pub fn raw_size(&self) -> usize {
        std::mem::size_of::<RawRtpHeader>()
            + (self.csrcs.len() << 2)
            + self.extension.as_ref().map(|e| e.raw_size()).unwrap_or(0)
    }
}

impl Default for RtpHeader {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

/// Helper struct.
#[repr(C, packed)]
struct RawHeaderExtension {
    misc: u16,
    length: u16,
}

/// RTP header extension.
#[derive(Clone)]
pub struct RtpHeaderExtension {
    misc: u16,
    data: Bytes,
}

impl RtpHeaderExtension {
    /// Create a new header extension.
    #[inline]
    pub const fn new() -> Self {
        Self {
            misc: 0,
            data: Bytes::new(),
        }
    }

    /// Decode RTP header extension from given data.
    pub fn decode(data: &mut Bytes) -> Result<Self, InvalidInput> {
        let mut buffer = data.clone();

        if buffer.len() < std::mem::size_of::<RawHeaderExtension>() {
            return Err(InvalidInput::new());
        }

        let ptr = buffer.as_ptr() as *const RawHeaderExtension;

        let raw = unsafe { ptr.read_unaligned() };

        let extension_length = (u16::from_be(raw.length) as usize) << 2;
        let misc = u16::from_be(raw.misc);

        buffer.advance(std::mem::size_of::<RawHeaderExtension>());

        if buffer.len() < extension_length {
            return Err(InvalidInput::new());
        }

        let res = Self {
            misc,
            data: buffer.split_to(extension_length),
        };

        *data = buffer;

        Ok(res)
    }

    /// Encode the header extension.
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.reserve(self.raw_size());

        let length = (self.data.len() >> 2) as u16;

        let raw = RawHeaderExtension {
            misc: self.misc.to_be(),
            length: length.to_be(),
        };

        let ptr = &raw as *const _ as *const u8;

        let header =
            unsafe { std::slice::from_raw_parts(ptr, std::mem::size_of::<RawHeaderExtension>()) };

        buf.extend_from_slice(header);
        buf.extend_from_slice(&self.data);
    }

    /// Get the first 16 bits of the header extension.
    #[inline]
    pub fn misc(&self) -> u16 {
        self.misc
    }

    /// Set the first 16 bits of the header extension.
    #[inline]
    pub fn with_misc(mut self, misc: u16) -> Self {
        self.misc = misc;
        self
    }

    /// Get header extension data.
    #[inline]
    pub fn data(&self) -> &Bytes {
        &self.data
    }

    /// Set the extension data.
    ///
    /// # Panics
    /// The method panics if the length of the data is not a multiple of four
    /// or if the length is greater than 262140.
    #[inline]
    pub fn with_data(mut self, data: Bytes) -> Self {
        assert_eq!(data.len() & 3, 0);

        let words = data.len() >> 2;

        assert!(words <= (u16::MAX as usize));

        self.data = data;
        self
    }

    /// Get raw size of the header extension (i.e. byte length of the encoded
    /// header extension).
    #[inline]
    pub fn raw_size(&self) -> usize {
        std::mem::size_of::<RawHeaderExtension>() + self.data.len()
    }
}

impl Default for RtpHeaderExtension {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

/// RTP packet.
#[derive(Clone)]
pub struct RtpPacket {
    header: RtpHeader,
    payload: Bytes,
}

impl RtpPacket {
    /// Create a new RTP packet.
    #[inline]
    pub const fn new() -> Self {
        Self {
            header: RtpHeader::new(),
            payload: Bytes::new(),
        }
    }

    /// Create a new RTP packets from given parts.
    pub fn from_parts(header: RtpHeader, payload: Bytes) -> Result<Self, InvalidInput> {
        if header.padding() {
            let padding_len = payload.last().copied().ok_or_else(InvalidInput::new)? as usize;

            if padding_len == 0 || payload.len() < padding_len {
                return Err(InvalidInput::new());
            }
        }

        let res = Self { header, payload };

        Ok(res)
    }

    /// Deconstruct the packet into its parts.
    #[inline]
    pub fn deconstruct(self) -> (RtpHeader, Bytes) {
        (self.header, self.payload)
    }

    /// Decode RTP packet from given data frame.
    pub fn decode(mut frame: Bytes) -> Result<Self, InvalidInput> {
        let header = RtpHeader::decode(&mut frame)?;

        let payload = frame;

        Self::from_parts(header, payload)
    }

    /// Encode the packet.
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.reserve(self.raw_size());

        self.header.encode(buf);

        buf.extend_from_slice(&self.payload);
    }

    /// Get the RTP header.
    #[inline]
    pub fn header(&self) -> &RtpHeader {
        &self.header
    }

    /// Get the marker bit value.
    #[inline]
    pub fn marker(&self) -> bool {
        self.header.marker()
    }

    /// Set the marker bit.
    #[inline]
    pub fn with_marker(mut self, marker: bool) -> Self {
        self.header = self.header.with_marker(marker);
        self
    }

    /// Get the payload type.
    ///
    /// Note: Only the lower 7 bits are used.
    #[inline]
    pub fn payload_type(&self) -> u8 {
        self.header.payload_type()
    }

    /// Set the payload type.
    ///
    /// # Panics
    /// The method panics if the payload type is greater than 127.
    #[inline]
    pub fn with_payload_type(mut self, payload_type: u8) -> Self {
        self.header = self.header.with_payload_type(payload_type);
        self
    }

    /// Get the RTP sequence number.
    #[inline]
    pub fn sequence_number(&self) -> u16 {
        self.header.sequence_number()
    }

    /// Set the RTP sequence number.
    #[inline]
    pub fn with_sequence_number(mut self, sequence_number: u16) -> Self {
        self.header = self.header.with_sequence_number(sequence_number);
        self
    }

    /// Get the RTP timestamp.
    #[inline]
    pub fn timestamp(&self) -> u32 {
        self.header.timestamp()
    }

    /// Set the RTP timestamp.
    #[inline]
    pub fn with_timestamp(mut self, timestamp: u32) -> Self {
        self.header = self.header.with_timestamp(timestamp);
        self
    }

    /// Get the SSRC identifier.
    #[inline]
    pub fn ssrc(&self) -> u32 {
        self.header.ssrc()
    }

    /// Set the SSRC identifier.
    #[inline]
    pub fn with_ssrc(mut self, ssrc: u32) -> Self {
        self.header = self.header.with_ssrc(ssrc);
        self
    }

    /// Get the CSRC identifiers.
    #[inline]
    pub fn csrcs(&self) -> &[u32] {
        self.header.csrcs()
    }

    /// Set the CSRC identifiers.
    ///
    /// # Panics
    /// The method panics if the number of identifiers is greater than 255.
    pub fn with_csrcs<T>(mut self, csrcs: T) -> Self
    where
        T: Into<Vec<u32>>,
    {
        self.header = self.header.with_csrcs(csrcs);
        self
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
    pub fn with_payload(mut self, payload: Bytes, padding: u8) -> Self {
        if padding > 0 {
            let len = payload.len() + (padding as usize);

            let mut buffer = BytesMut::with_capacity(len);

            buffer.extend_from_slice(&payload);
            buffer.resize(len, 0);

            buffer[len - 1] = padding;

            self.header = self.header.with_padding(true);
            self.payload = buffer.freeze();
        } else {
            self.header = self.header.with_padding(false);
            self.payload = payload;
        }

        self
    }

    /// Set the payload that already includes padding.
    ///
    /// # Panics
    /// The method panics if the given payload is empty, if the last byte is
    /// zero or if the length of the padding is greater than the length of the
    /// payload.
    pub fn with_padded_payload(mut self, payload: Bytes) -> Self {
        let padding_len = payload.last().copied().expect("empty payload") as usize;

        assert!(padding_len > 0 && payload.len() >= padding_len);

        self.header = self.header.with_padding(true);
        self.payload = payload;
        self
    }

    /// Get raw size of the packet (i.e. byte length of the encoded packet).
    #[inline]
    pub fn raw_size(&self) -> usize {
        self.header.raw_size() + self.payload.len()
    }
}

impl Default for RtpPacket {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

/// RTP packet wrapper containing also the instant when the packet was
/// received.
#[derive(Clone)]
pub struct IncomingRtpPacket {
    inner: RtpPacket,
    received_at: Instant,
}

impl IncomingRtpPacket {
    /// Create a new incoming RTP packet.
    #[inline]
    pub const fn new(packet: RtpPacket, received_at: Instant) -> Self {
        Self {
            inner: packet,
            received_at,
        }
    }

    /// Get the instant when the packet was received.
    #[inline]
    pub fn received_at(&self) -> Instant {
        self.received_at
    }
}

impl AsRef<RtpPacket> for IncomingRtpPacket {
    #[inline]
    fn as_ref(&self) -> &RtpPacket {
        &self.inner
    }
}

impl Borrow<RtpPacket> for IncomingRtpPacket {
    #[inline]
    fn borrow(&self) -> &RtpPacket {
        &self.inner
    }
}

impl Deref for IncomingRtpPacket {
    type Target = RtpPacket;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl From<IncomingRtpPacket> for RtpPacket {
    #[inline]
    fn from(packet: IncomingRtpPacket) -> Self {
        packet.inner
    }
}

/// Ordered RTP packet.
#[derive(Clone)]
pub struct OrderedRtpPacket {
    inner: IncomingRtpPacket,
    index: u64,
}

impl OrderedRtpPacket {
    /// Create a new ordered RTP packet.
    #[inline]
    pub const fn new(inner: IncomingRtpPacket, index: u64) -> Self {
        Self { inner, index }
    }

    /// Get the estimated packet index (a.k.a. extended sequence number).
    #[inline]
    pub fn index(&self) -> u64 {
        self.index
    }
}

impl AsRef<RtpPacket> for OrderedRtpPacket {
    #[inline]
    fn as_ref(&self) -> &RtpPacket {
        &self.inner
    }
}

impl AsRef<IncomingRtpPacket> for OrderedRtpPacket {
    #[inline]
    fn as_ref(&self) -> &IncomingRtpPacket {
        &self.inner
    }
}

impl Borrow<RtpPacket> for OrderedRtpPacket {
    #[inline]
    fn borrow(&self) -> &RtpPacket {
        &self.inner
    }
}

impl Borrow<IncomingRtpPacket> for OrderedRtpPacket {
    #[inline]
    fn borrow(&self) -> &IncomingRtpPacket {
        &self.inner
    }
}

impl Deref for OrderedRtpPacket {
    type Target = IncomingRtpPacket;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl From<OrderedRtpPacket> for RtpPacket {
    #[inline]
    fn from(packet: OrderedRtpPacket) -> Self {
        packet.inner.into()
    }
}

impl From<OrderedRtpPacket> for IncomingRtpPacket {
    #[inline]
    fn from(packet: OrderedRtpPacket) -> Self {
        packet.inner
    }
}
