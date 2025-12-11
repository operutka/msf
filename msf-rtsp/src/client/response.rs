use std::ops::Deref;

use bytes::{Bytes, BytesMut};
use tokio_util::codec::Decoder;

use crate::{
    Error,
    response::{Response, ResponseHeader, ResponseHeaderDecoder, ResponseHeaderDecoderOptions},
    ttpkit::body::{FixedSizeBodyDecoder, MessageBodyDecoder},
};

/// Incoming RTSP response.
pub struct IncomingResponse {
    inner: Response,
}

impl IncomingResponse {
    /// Create a new incoming response.
    pub(crate) fn new(response: Response) -> Self {
        Self { inner: response }
    }

    /// Deconstruct the response into its header and body.
    #[inline]
    pub fn deconstruct(self) -> (ResponseHeader, Bytes) {
        self.inner.deconstruct()
    }
}

impl Deref for IncomingResponse {
    type Target = Response;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// Response decoder options.
#[derive(Copy, Clone)]
pub struct ResponseDecoderOptions {
    header_decoder_options: ResponseHeaderDecoderOptions,
    max_body_size: Option<usize>,
}

impl ResponseDecoderOptions {
    /// Create a new response decoder options builder.
    #[inline]
    pub const fn new() -> Self {
        let header_decoder_options = ResponseHeaderDecoderOptions::new()
            .accept_all_line_endings(false)
            .max_line_length(Some(4096))
            .max_header_field_length(Some(4096))
            .max_header_fields(Some(64));

        Self {
            header_decoder_options,
            max_body_size: Some(2 << 20),
        }
    }

    /// Enable or disable acceptance of all line endings (CR, LF, CRLF).
    #[inline]
    pub const fn accept_all_line_endings(mut self, enabled: bool) -> Self {
        self.header_decoder_options = self.header_decoder_options.accept_all_line_endings(enabled);
        self
    }

    /// Set maximum line length for response header lines and chunked body
    /// headers.
    #[inline]
    pub const fn max_line_length(mut self, max_length: Option<usize>) -> Self {
        self.header_decoder_options = self.header_decoder_options.max_line_length(max_length);
        self
    }

    /// Set maximum header field length.
    #[inline]
    pub const fn max_header_field_length(mut self, max_length: Option<usize>) -> Self {
        self.header_decoder_options = self
            .header_decoder_options
            .max_header_field_length(max_length);

        self
    }

    /// Set maximum number of lines for the response header.
    #[inline]
    pub const fn max_header_fields(mut self, max_fields: Option<usize>) -> Self {
        self.header_decoder_options = self.header_decoder_options.max_header_fields(max_fields);
        self
    }

    /// Set the maximum size of a response body.
    #[inline]
    pub const fn max_body_size(mut self, size: Option<usize>) -> Self {
        self.max_body_size = size;
        self
    }
}

impl Default for ResponseDecoderOptions {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

/// RTSP response decoder.
///
/// It is a greedy decoder, i.e. it will consume all data until a complete
/// response can be returned.
pub struct ResponseDecoder {
    header_decoder: ResponseHeaderDecoder,
    header: Option<ResponseHeader>,
    body_decoder: FixedSizeBodyDecoder,
    body: BytesMut,
    max_body_size: Option<usize>,
}

impl ResponseDecoder {
    /// Create a new RTSP response decoder with given options.
    pub fn new(options: ResponseDecoderOptions) -> Self {
        Self {
            header_decoder: ResponseHeaderDecoder::new(options.header_decoder_options),
            header: None,
            body_decoder: FixedSizeBodyDecoder::new(0),
            body: BytesMut::new(),
            max_body_size: options.max_body_size,
        }
    }

    /// Try to decode an RTSP header.
    fn decode_header(&mut self, data: &mut BytesMut) -> Result<Option<ResponseHeader>, Error> {
        self.header_decoder.decode(data).map_err(|err| {
            Error::from_static_msg_and_cause("unable to decode a response header", err)
        })
    }

    /// Try to decode an RTSP header at the end of stream.
    fn decode_header_eof(&mut self, data: &mut BytesMut) -> Result<Option<ResponseHeader>, Error> {
        self.header_decoder.decode_eof(data).map_err(|err| {
            Error::from_static_msg_and_cause("unable to decode a response header", err)
        })
    }

    /// Try to decode a chunk of response body.
    fn decode_body(&mut self, data: &mut BytesMut) -> Result<Option<Bytes>, Error> {
        self.body_decoder.decode(data).map_err(|err| {
            Error::from_static_msg_and_cause("unable to decode a response body", err)
        })
    }

    /// Try to decode a chunk of response body at the end of stream.
    fn decode_body_eof(&mut self, data: &mut BytesMut) -> Result<Option<Bytes>, Error> {
        self.body_decoder.decode_eof(data).map_err(|err| {
            Error::from_static_msg_and_cause("unable to decode a response body", err)
        })
    }

    /// Process a given response header.
    fn process_header(&mut self, header: ResponseHeader) -> Result<(), Error> {
        let content_length = header
            .get_header_field_value("content-length")
            .map(|value| value.parse())
            .transpose()
            .map_err(|_| Error::from_static_msg("invalid response Content-Length value"))?
            .unwrap_or(0);

        if let Some(max_body_size) = self.max_body_size
            && content_length > max_body_size
        {
            return Err(Error::from_static_msg(
                "maximum response body size exceeded",
            ));
        }

        self.header = Some(header);

        self.body_decoder = FixedSizeBodyDecoder::new(content_length);

        Ok(())
    }

    /// Take the current response.
    fn take_response(&mut self) -> Option<Response> {
        self.header_decoder.reset();

        let header = self.header.take()?;
        let body = self.body.split();

        Some(Response::new(header, body.freeze()))
    }
}

impl Decoder for ResponseDecoder {
    type Item = Response;
    type Error = Error;

    fn decode(&mut self, data: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        loop {
            if self.header.is_none() {
                if let Some(header) = self.decode_header(data)? {
                    self.process_header(header)?;
                } else {
                    return Ok(None);
                }
            } else if self.body_decoder.is_complete() {
                return Ok(self.take_response());
            } else if let Some(chunk) = self.decode_body(data)? {
                self.body.extend_from_slice(&chunk);
            } else {
                return Ok(None);
            }
        }
    }

    fn decode_eof(&mut self, data: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        loop {
            if self.header.is_none() {
                if let Some(header) = self.decode_header_eof(data)? {
                    self.process_header(header)?;
                } else if data.is_empty() {
                    return Ok(None);
                } else {
                    return Err(Error::from_static_msg("incomplete response"));
                }
            } else if self.body_decoder.is_complete() {
                return Ok(self.take_response());
            } else if let Some(chunk) = self.decode_body_eof(data)? {
                self.body.extend_from_slice(&chunk);
            } else {
                return Err(Error::from_static_msg("incomplete response"));
            }
        }
    }
}
