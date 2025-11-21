use bytes::{Buf, BufMut, BytesMut};

use crate::{InvalidInput, RtcpPacket, RtcpPacketType};

/// BYE packet.
#[derive(Clone)]
pub struct ByePacket {
    sources: Vec<u32>,
}

impl ByePacket {
    /// Create a new BYE packet for given sources.
    ///
    /// # Panics
    /// The method panics if the number of sources is greater than 31.
    #[inline]
    pub fn new<T>(sources: T) -> Self
    where
        T: Into<Vec<u32>>,
    {
        let sources = sources.into();

        assert!(sources.len() < 32);

        Self { sources }
    }

    /// Decode a BYE packet.
    pub fn decode(packet: &RtcpPacket) -> Result<Self, InvalidInput> {
        let header = packet.header();

        let mut data = packet.stripped_payload();

        if data.len() < ((header.item_count() as usize) << 2) {
            return Err(InvalidInput::new());
        }

        let mut sources = Vec::with_capacity(header.item_count() as usize);

        for _ in 0..header.item_count() {
            sources.push(data.get_u32());
        }

        Ok(Self::new(sources))
    }

    /// Encode the BYE packet.
    pub fn encode(&self) -> RtcpPacket {
        let mut payload = BytesMut::with_capacity(self.raw_size());

        for ssrc in &self.sources {
            payload.put_u32(*ssrc);
        }

        RtcpPacket::new(RtcpPacketType::BYE)
            .with_item_count(self.sources.len() as u8)
            .with_payload(payload.freeze(), 0)
    }

    /// Get sources.
    #[inline]
    pub fn sources(&self) -> &[u32] {
        &self.sources
    }

    /// Get size of the encoded BYE packet.
    #[inline]
    pub fn raw_size(&self) -> usize {
        self.sources.len() << 2
    }
}
