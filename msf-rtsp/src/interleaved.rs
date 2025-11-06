use bytes::{Buf, Bytes, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

use crate::Error;

/// Interleaved RTSP stream item.
#[derive(Clone)]
pub enum InterleavedItem<T> {
    PrimaryMessage(T),
    ChannelData(ChannelData),
}

/// Codec mode.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
enum InterleavedCodecMode {
    Unknown,
    PrimaryMessage,
    ChannelData,
}

/// Interleaved RTSP codec.
pub struct InterleavedCodec<T> {
    message_codec: T,
    data_codec: ChannelDataCodec,
    codec_mode: InterleavedCodecMode,
}

impl<T> InterleavedCodec<T> {
    /// Create a new interleaved RTSP codec from a given RTSP message codec.
    #[inline]
    pub fn new(message_codec: T) -> Self {
        Self {
            message_codec,
            data_codec: ChannelDataCodec,
            codec_mode: InterleavedCodecMode::Unknown,
        }
    }
}

impl<T> Decoder for InterleavedCodec<T>
where
    T: Decoder,
    T::Error: From<Error>,
{
    type Item = InterleavedItem<T::Item>;
    type Error = T::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let res = loop {
            match self.codec_mode {
                InterleavedCodecMode::Unknown => {
                    if src.is_empty() {
                        return Ok(None);
                    } else if src[0] == b'$' {
                        self.codec_mode = InterleavedCodecMode::ChannelData;
                    } else {
                        self.codec_mode = InterleavedCodecMode::PrimaryMessage;
                    }
                }
                InterleavedCodecMode::PrimaryMessage => {
                    break self
                        .message_codec
                        .decode(src)?
                        .map(InterleavedItem::PrimaryMessage);
                }
                InterleavedCodecMode::ChannelData => {
                    break self
                        .data_codec
                        .decode(src)?
                        .map(InterleavedItem::ChannelData);
                }
            }
        };

        if res.is_some() {
            self.codec_mode = InterleavedCodecMode::Unknown;
        }

        Ok(res)
    }

    fn decode_eof(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let res = loop {
            match self.codec_mode {
                InterleavedCodecMode::Unknown => {
                    if src.is_empty() {
                        return Ok(None);
                    } else if src[0] == 0x24 {
                        self.codec_mode = InterleavedCodecMode::ChannelData;
                    } else {
                        self.codec_mode = InterleavedCodecMode::PrimaryMessage;
                    }
                }
                InterleavedCodecMode::PrimaryMessage => {
                    break self
                        .message_codec
                        .decode_eof(src)?
                        .map(InterleavedItem::PrimaryMessage);
                }
                InterleavedCodecMode::ChannelData => {
                    break self
                        .data_codec
                        .decode_eof(src)?
                        .map(InterleavedItem::ChannelData);
                }
            }
        };

        if res.is_some() {
            self.codec_mode = InterleavedCodecMode::Unknown;
        }

        Ok(res)
    }
}

impl<T, U> Encoder<InterleavedItem<U>> for InterleavedCodec<T>
where
    T: Encoder<U>,
    T::Error: From<Error>,
{
    type Error = T::Error;

    fn encode(&mut self, item: InterleavedItem<U>, dst: &mut BytesMut) -> Result<(), Self::Error> {
        match item {
            InterleavedItem::PrimaryMessage(msg) => self.message_codec.encode(msg, dst)?,
            InterleavedItem::ChannelData(data) => self.data_codec.encode(data, dst)?,
        }

        Ok(())
    }
}

/// Header of interleaved channel data.
#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
struct ChannelDataHeader {
    dollar: u8,
    channel: u8,
    size: u16,
}

impl ChannelDataHeader {
    /// Create a new header.
    fn new(channel: u8, size: u16) -> Self {
        Self {
            dollar: 0x24,
            channel,
            size,
        }
    }

    /// Decode header from given data.
    fn decode(data: &[u8]) -> Result<Option<Self>, Error> {
        if data.len() < std::mem::size_of::<Self>() {
            return Ok(None);
        }

        let ptr = data.as_ptr() as *const Self;

        let be_header = unsafe { ptr.read_unaligned() };

        if be_header.dollar != 0x24 {
            return Err(Error::from_static_msg("invalid interleaved data header"));
        }

        let res = Self {
            dollar: be_header.dollar,
            channel: be_header.channel,
            size: u16::from_be(be_header.size),
        };

        Ok(Some(res))
    }

    /// Encode the header.
    fn encode(&self, buf: &mut BytesMut) {
        let be_header = Self {
            dollar: self.dollar,
            channel: self.channel,
            size: self.size.to_be(),
        };

        let ptr = &be_header as *const Self;

        let data = unsafe {
            std::slice::from_raw_parts(ptr as *const u8, std::mem::size_of_val(&be_header))
        };

        buf.extend_from_slice(data);
    }
}

/// Interleaved channel data.
#[derive(Clone)]
pub struct ChannelData {
    channel: u8,
    data: Bytes,
}

impl ChannelData {
    /// Create a new channel data item.
    ///
    /// # Panics
    /// The method panics if the length of `data` is more than 65535 bytes.
    #[inline]
    pub const fn new(channel: u8, data: Bytes) -> Self {
        assert!(data.len() <= 0xffff);

        Self { channel, data }
    }

    /// Get channel.
    #[inline]
    pub fn channel(&self) -> u8 {
        self.channel
    }

    /// Get data.
    #[inline]
    pub fn data(&self) -> &Bytes {
        &self.data
    }

    /// Take the data.
    #[inline]
    pub fn into_data(self) -> Bytes {
        self.data
    }
}

/// Decoder/encoder for interleaved channel data.
struct ChannelDataCodec;

impl Decoder for ChannelDataCodec {
    type Item = ChannelData;
    type Error = Error;

    fn decode(&mut self, data: &mut BytesMut) -> Result<Option<ChannelData>, Error> {
        let Some(header) = ChannelDataHeader::decode(data)? else {
            return Ok(None);
        };

        let header_size = std::mem::size_of_val(&header);

        let target_size = header_size + header.size as usize;

        if data.len() < target_size {
            return Ok(None);
        }

        let mut chunk = data.split_to(target_size);

        chunk.advance(header_size);

        let res = ChannelData {
            channel: header.channel,
            data: chunk.freeze(),
        };

        Ok(Some(res))
    }

    fn decode_eof(&mut self, data: &mut BytesMut) -> Result<Option<ChannelData>, Error> {
        if let Some(chunk) = self.decode(data)? {
            Ok(Some(chunk))
        } else if data.is_empty() {
            Ok(None)
        } else {
            Err(Error::from_static_msg("incomplete RTSP channel data"))
        }
    }
}

impl Encoder<ChannelData> for ChannelDataCodec {
    type Error = Error;

    fn encode(&mut self, item: ChannelData, buffer: &mut BytesMut) -> Result<(), Error> {
        let channel = item.channel();
        let data = item.data();
        let data_len = data.len();

        let header = ChannelDataHeader::new(channel, data_len as u16);

        let header_len = std::mem::size_of_val(&header);

        buffer.reserve(header_len + data_len);
        header.encode(buffer);
        buffer.extend_from_slice(data);

        Ok(())
    }
}
