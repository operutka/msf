use std::time::Duration;

use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::{InvalidInput, RtcpPacket, RtcpPacketType};

/// Helper struct.
#[repr(packed)]
struct RawReportBlock {
    ssrc: u32,
    loss: u32,
    extended_sequence_number: u32,
    jitter: u32,
    last_sr_timestamp: u32,
    delay_since_last_sr: u32,
}

/// Sender/receiver report block.
#[derive(Copy, Clone)]
pub struct ReportBlock {
    ssrc: u32,
    loss: u32,
    extended_sequence_number: u32,
    jitter: u32,
    last_sr_timestamp: u32,
    delay_since_last_sr: u32,
}

impl ReportBlock {
    /// Create a new report block.
    #[inline]
    pub const fn new() -> Self {
        Self {
            ssrc: 0,
            loss: 0,
            extended_sequence_number: 0,
            jitter: 0,
            last_sr_timestamp: 0,
            delay_since_last_sr: 0,
        }
    }

    /// Decode a report block from given data.
    pub fn decode(data: &mut Bytes) -> Result<Self, InvalidInput> {
        if data.len() < std::mem::size_of::<RawReportBlock>() {
            return Err(InvalidInput);
        }

        let ptr = data.as_ptr() as *const RawReportBlock;
        let raw = unsafe { &*ptr };

        let res = Self {
            ssrc: u32::from_be(raw.ssrc),
            loss: u32::from_be(raw.loss),
            extended_sequence_number: u32::from_be(raw.extended_sequence_number),
            jitter: u32::from_be(raw.jitter),
            last_sr_timestamp: u32::from_be(raw.last_sr_timestamp),
            delay_since_last_sr: u32::from_be(raw.delay_since_last_sr),
        };

        data.advance(std::mem::size_of::<RawReportBlock>());

        Ok(res)
    }

    /// Encode the report block.
    pub fn encode(&self, buf: &mut BytesMut) {
        let raw = RawReportBlock {
            ssrc: self.ssrc.to_be(),
            loss: self.loss.to_be(),
            extended_sequence_number: self.extended_sequence_number.to_be(),
            jitter: self.jitter.to_be(),
            last_sr_timestamp: self.last_sr_timestamp.to_be(),
            delay_since_last_sr: self.delay_since_last_sr.to_be(),
        };

        let ptr = &raw as *const _ as *const u8;

        let data =
            unsafe { std::slice::from_raw_parts(ptr, std::mem::size_of::<RawReportBlock>()) };

        buf.extend_from_slice(data);
    }

    /// Get SSRC.
    #[inline]
    pub fn ssrc(&self) -> u32 {
        self.ssrc
    }

    /// Set SSRC.
    #[inline]
    pub fn with_ssrc(mut self, ssrc: u32) -> Self {
        self.ssrc = ssrc;
        self
    }

    /// Get fractional loss as 0.8 fixed point number.
    #[inline]
    pub fn fractional_loss(&self) -> u8 {
        (self.loss >> 24) as u8
    }

    /// Set fractional loss as 0.8 fixed point number.
    #[inline]
    pub fn with_fractional_loss(mut self, loss: u8) -> Self {
        self.loss &= 0x00ffffff;
        self.loss |= (loss as u32) << 24;
        self
    }

    /// Get cumulative packet loss (the precision is only up to 24 bits).
    #[inline]
    pub fn cumulative_loss(&self) -> i32 {
        ((self.loss << 8) as i32) >> 8
    }

    /// Set cumulative packet loss (the precision is only up to 24 bits).
    #[inline]
    pub fn with_cumulative_loss(mut self, loss: i32) -> Self {
        let min = -(1i32 << 23);
        let max = (1i32 << 23) - 1;

        let loss = loss.max(min).min(max) as u32;

        self.loss &= 0xff000000;
        self.loss |= loss & 0x00ffffff;
        self
    }

    /// Get extended highest sequence number.
    #[inline]
    pub fn extended_sequence_number(&self) -> u32 {
        self.extended_sequence_number
    }

    /// Set the extended sequence number.
    #[inline]
    pub fn with_extended_sequence_number(mut self, n: u32) -> Self {
        self.extended_sequence_number = n;
        self
    }

    /// Get jitter.
    #[inline]
    pub fn jitter(&self) -> u32 {
        self.jitter
    }

    /// Set the jitter.
    #[inline]
    pub fn with_jitter(mut self, jitter: u32) -> Self {
        self.jitter = jitter;
        self
    }

    /// Get NTP timestamp of the last sender report (after truncating to the
    /// middle 32 bits).
    ///
    /// The returned timestamp is a 32.32 fixed point number.
    #[inline]
    pub fn last_sr_timestamp(&self) -> u64 {
        (self.last_sr_timestamp as u64) << 16
    }

    /// Set NTP timestamp of the last sender report.
    ///
    /// The timestamp is expected to be a 32.32 fixed point number and it will
    /// be truncated to the middle 32 bits.
    #[inline]
    pub fn with_last_sr_timestamp(mut self, ts: u64) -> Self {
        self.last_sr_timestamp = (ts >> 16) as u32;
        self
    }

    /// Get delay since the last sender report.
    #[inline]
    pub fn delay_since_last_sr(&self) -> Duration {
        let secs = (self.delay_since_last_sr >> 16) as u64;
        let nanos = ((self.delay_since_last_sr & 0xffff) as u64 * 1_000_000_000) >> 16;

        Duration::new(secs, nanos as u32)
    }

    /// Set delay since the last sender report.
    #[inline]
    pub fn with_delay_since_last_sr(mut self, delay: Duration) -> Self {
        let secs = (delay.as_secs() << 16) as u32;
        let fraction = (((delay.subsec_nanos() as u64) << 16) / 1_000_000_000) as u32;

        self.delay_since_last_sr = secs + fraction;
        self
    }

    /// Get size of the encoded report block.
    #[inline]
    pub fn raw_size(&self) -> usize {
        std::mem::size_of::<RawReportBlock>()
    }
}

impl Default for ReportBlock {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

/// Helper struct.
#[repr(packed)]
struct RawSenderReportHeader {
    ssrc: u32,
    ntp_timestamp: u64,
    rtp_timestamp: u32,
    packet_count: u32,
    octet_count: u32,
}

/// Sender report.
#[derive(Clone)]
pub struct SenderReport {
    ssrc: u32,
    ntp_timestamp: u64,
    rtp_timestamp: u32,
    packet_count: u32,
    octet_count: u32,
    blocks: Vec<ReportBlock>,
}

impl SenderReport {
    /// Create a new sender report.
    #[inline]
    pub const fn new() -> Self {
        Self {
            ssrc: 0,
            ntp_timestamp: 0,
            rtp_timestamp: 0,
            packet_count: 0,
            octet_count: 0,
            blocks: Vec::new(),
        }
    }

    /// Decode sender report.
    pub fn decode(packet: &RtcpPacket) -> Result<Self, InvalidInput> {
        let header = packet.header();

        let mut data = packet.stripped_payload();

        if data.len() < std::mem::size_of::<RawSenderReportHeader>() {
            return Err(InvalidInput);
        }

        let ptr = data.as_ptr() as *const RawSenderReportHeader;
        let raw = unsafe { &*ptr };

        let mut res = Self {
            ssrc: u32::from_be(raw.ssrc),
            ntp_timestamp: u64::from_be(raw.ntp_timestamp),
            rtp_timestamp: u32::from_be(raw.rtp_timestamp),
            packet_count: u32::from_be(raw.packet_count),
            octet_count: u32::from_be(raw.octet_count),
            blocks: Vec::with_capacity(header.item_count() as usize),
        };

        data.advance(std::mem::size_of::<RawSenderReportHeader>());

        for _ in 0..header.item_count() {
            res.blocks.push(ReportBlock::decode(&mut data)?);
        }

        Ok(res)
    }

    /// Encode the sender report.
    pub fn encode(&self) -> RtcpPacket {
        let mut payload = BytesMut::with_capacity(self.raw_size());

        let raw = RawSenderReportHeader {
            ssrc: self.ssrc.to_be(),
            ntp_timestamp: self.ntp_timestamp.to_be(),
            rtp_timestamp: self.rtp_timestamp.to_be(),
            packet_count: self.packet_count.to_be(),
            octet_count: self.octet_count.to_be(),
        };

        let ptr = &raw as *const _ as *const u8;

        let data = unsafe {
            std::slice::from_raw_parts(ptr, std::mem::size_of::<RawSenderReportHeader>())
        };

        payload.extend_from_slice(data);

        for block in &self.blocks {
            block.encode(&mut payload);
        }

        RtcpPacket::new(RtcpPacketType::SR)
            .with_item_count(self.blocks.len() as u8)
            .with_payload(payload.freeze(), 0)
    }

    /// Get SSRC identifier of the sender.
    #[inline]
    pub fn ssrc(&self) -> u32 {
        self.ssrc
    }

    /// Set the SSRC identifier of the sender.
    #[inline]
    pub fn with_ssrc(mut self, ssrc: u32) -> Self {
        self.ssrc = ssrc;
        self
    }

    /// Get NTP timestamp as a 32.32 fixed point number.
    #[inline]
    pub fn ntp_timestamp(&self) -> u64 {
        self.ntp_timestamp
    }

    /// Set the NTP timestamp as a 32.32. fixed point number.
    #[inline]
    pub fn with_ntp_timestamp(mut self, timestamp: u64) -> Self {
        self.ntp_timestamp = timestamp;
        self
    }

    /// Get RTP timestamp.
    #[inline]
    pub fn rtp_timestamp(&self) -> u32 {
        self.rtp_timestamp
    }

    /// Set the RTP timestamp.
    #[inline]
    pub fn with_rtp_timestamp(mut self, timestamp: u32) -> Self {
        self.rtp_timestamp = timestamp;
        self
    }

    /// Get packet count.
    #[inline]
    pub fn packet_count(&self) -> u32 {
        self.packet_count
    }

    /// Set the packet count.
    #[inline]
    pub fn with_packet_count(mut self, count: u32) -> Self {
        self.packet_count = count;
        self
    }

    /// Get octet count.
    #[inline]
    pub fn octet_count(&self) -> u32 {
        self.octet_count
    }

    /// Set the octet count.
    #[inline]
    pub fn with_octet_count(mut self, count: u32) -> Self {
        self.octet_count = count;
        self
    }

    /// Get report blocks.
    #[inline]
    pub fn report_blocks(&self) -> &[ReportBlock] {
        &self.blocks
    }

    /// Set the report blocks.
    ///
    /// # Panics
    /// The method will panic if the number of report blocks is greater than
    /// 31.
    #[inline]
    pub fn with_report_blocks<T>(mut self, blocks: T) -> Self
    where
        T: Into<Vec<ReportBlock>>,
    {
        let blocks = blocks.into();

        assert!(blocks.len() < 32);

        self.blocks = blocks;
        self
    }

    /// Get size of the encoded sender report.
    #[inline]
    pub fn raw_size(&self) -> usize {
        std::mem::size_of::<RawSenderReportHeader>()
            + std::mem::size_of::<RawReportBlock>() * self.blocks.len()
    }
}

impl Default for SenderReport {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

/// Receiver report.
#[derive(Clone)]
pub struct ReceiverReport {
    ssrc: u32,
    blocks: Vec<ReportBlock>,
}

impl ReceiverReport {
    /// Create a new receiver report.
    #[inline]
    pub const fn new() -> Self {
        Self {
            ssrc: 0,
            blocks: Vec::new(),
        }
    }

    /// Decode receiver report.
    pub fn decode(packet: &RtcpPacket) -> Result<Self, InvalidInput> {
        let header = packet.header();

        let mut data = packet.stripped_payload();

        if data.len() < 4 {
            return Err(InvalidInput);
        }

        let mut res = Self {
            ssrc: data.get_u32(),
            blocks: Vec::with_capacity(header.item_count() as usize),
        };

        for _ in 0..header.item_count() {
            res.blocks.push(ReportBlock::decode(&mut data)?);
        }

        Ok(res)
    }

    /// Encode the sender report.
    pub fn encode(&self) -> RtcpPacket {
        let mut payload = BytesMut::with_capacity(self.raw_size());

        payload.put_u32(self.ssrc);

        for block in &self.blocks {
            block.encode(&mut payload);
        }

        RtcpPacket::new(RtcpPacketType::RR)
            .with_item_count(self.blocks.len() as u8)
            .with_payload(payload.freeze(), 0)
    }

    /// Get SSRC identifier of the sender.
    #[inline]
    pub fn ssrc(&self) -> u32 {
        self.ssrc
    }

    /// Set the SSRC identifier of the sender.
    #[inline]
    pub fn with_ssrc(mut self, ssrc: u32) -> Self {
        self.ssrc = ssrc;
        self
    }

    /// Get report blocks.
    #[inline]
    pub fn report_blocks(&self) -> &[ReportBlock] {
        &self.blocks
    }

    /// Set the report blocks.
    ///
    /// # Panics
    /// The method will panic if the number of report blocks is greater than
    /// 31.
    #[inline]
    pub fn with_report_blocks<T>(mut self, blocks: T) -> Self
    where
        T: Into<Vec<ReportBlock>>,
    {
        let blocks = blocks.into();

        assert!(blocks.len() < 32);

        self.blocks = blocks;
        self
    }

    /// Get size of the encoded sender report.
    #[inline]
    pub fn raw_size(&self) -> usize {
        4 + std::mem::size_of::<RawReportBlock>() * self.blocks.len()
    }
}

impl Default for ReceiverReport {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}
