use bytes::{BufMut, BytesMut};

use super::{RtcpPacket, RtcpPacketType};

/// Source description.
#[derive(Clone)]
pub struct SourceDescription {
    ssrc: u32,
    cname: String,
}

impl SourceDescription {
    /// Create a new source description.
    pub fn new<T>(ssrc: u32, cname: T) -> Self
    where
        T: Into<String>,
    {
        let cname = cname.into();

        assert!(cname.len() < 256);

        Self { ssrc, cname }
    }

    /// Encode this source description.
    fn encode(&self, buf: &mut BytesMut) {
        let old_buffer_length = buf.len();

        buf.put_u32(self.ssrc);

        let data = self.cname.as_bytes();

        buf.put_u8(1);
        buf.put_u8(data.len() as u8);
        buf.extend_from_slice(data);
        buf.put_u8(0);

        while ((buf.len() - old_buffer_length) & 0x03) != 0 {
            buf.put_u8(0);
        }
    }

    /// Get the source description size in bytes.
    fn raw_size(&self) -> usize {
        let len = std::mem::size_of::<u32>() + self.cname.len() + 3;

        (len + 3) & !3
    }
}

/// Source description packet.
#[derive(Clone)]
pub struct SourceDescriptionPacket {
    chunks: Vec<SourceDescription>,
}

impl SourceDescriptionPacket {
    /// Create a new source description packet.
    #[inline]
    pub const fn new() -> Self {
        Self { chunks: Vec::new() }
    }

    /// Set the source descriptions.
    ///
    /// # Panics
    /// The method will panic if the number of source descriptions is greater
    /// than 31.
    pub fn with_source_descriptions<T>(mut self, descriptions: T) -> Self
    where
        T: Into<Vec<SourceDescription>>,
    {
        let chunks = descriptions.into();

        assert!(chunks.len() < 32);

        self.chunks = chunks;
        self
    }

    /// Encode the source description packet.
    pub fn encode(&self) -> RtcpPacket {
        let mut payload = BytesMut::with_capacity(self.raw_size());

        for chunk in &self.chunks {
            chunk.encode(&mut payload);
        }

        RtcpPacket::new(RtcpPacketType::SDES)
            .with_item_count(self.chunks.len() as u8)
            .with_payload(payload.freeze(), 0)
    }

    /// Get size of the encoded source description packet.
    pub fn raw_size(&self) -> usize {
        self.chunks.iter().map(|chunk| chunk.raw_size()).sum()
    }
}
