//! RTSP server request types.

use std::{ops::Deref, str::FromStr};

use bytes::{Bytes, BytesMut};
use tokio_util::codec::Decoder;

use crate::{
    Error, Scheme,
    request::{Request, RequestHeader, RequestHeaderDecoder, RequestHeaderDecoderOptions},
    server::{ConnectionHandle, DefaultConnectionInfo, error::BadRequest},
    ttpkit::body::{FixedSizeBodyDecoder, MessageBodyDecoder},
    url::{IntoUrl, Url, query::QueryDict},
};

/// Incoming RTSP request.
#[derive(Clone)]
pub struct IncomingRequest<I = DefaultConnectionInfo> {
    inner: Box<InnerRequest<I>>,
}

impl<I> IncomingRequest<I> {
    /// Create a new incoming RTSP request.
    pub(crate) fn new(request: Request, connection: ConnectionHandle<I>) -> Result<Self, Error> {
        let context = RequestContext::new(&request)?;

        let inner = InnerRequest {
            connection,
            inner: request,
            context,
        };

        let res = Self {
            inner: Box::new(inner),
        };

        Ok(res)
    }

    /// Get the request URL.
    #[inline]
    pub fn url(&self) -> Option<&Url> {
        self.inner.context.url.as_ref()
    }

    /// Get the query parameters.
    #[inline]
    pub fn query_parameters(&self) -> &QueryDict {
        &self.inner.context.query
    }

    /// Get the connection handle.
    #[inline]
    pub fn connection(&self) -> &ConnectionHandle<I> {
        &self.inner.connection
    }

    /// Split the request into header and body.
    #[inline]
    pub fn deconstruct(self) -> (RequestHeader, Bytes) {
        self.inner.inner.deconstruct()
    }
}

impl<I> Deref for IncomingRequest<I> {
    type Target = Request;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.inner.inner
    }
}

/// Inner struct for the incoming request.
///
/// NOTE: The `IncomingRequest` contains only a boxed struct (this one) to
/// avoid passing around big objects.
#[derive(Clone)]
struct InnerRequest<I> {
    connection: ConnectionHandle<I>,
    inner: Request,
    context: RequestContext,
}

/// Helper struct separating non-generic stuff.
#[derive(Clone)]
struct RequestContext {
    url: Option<Url>,
    query: QueryDict,
}

impl RequestContext {
    /// Create a new request context from a given request.
    fn new(request: &Request) -> Result<Self, Error> {
        let path = request.path();

        let url = if path.as_ref() == b"*" {
            None
        } else {
            let res = path
                .to_str()
                .ok()
                .map(IntoUrl::into_url)
                .and_then(|res| res.ok())
                .ok_or_else(|| Error::from_static_msg("invalid request URL"))?;

            Scheme::from_str(res.scheme())
                .map_err(|_| Error::from_static_msg("invalid request URL scheme"))?;

            Some(res)
        };

        let query = if let Some(url) = url.as_ref() {
            url.query()
                .unwrap_or("")
                .parse()
                .map_err(|_| Error::from_static_msg("unable to parse request query parameters"))?
        } else {
            QueryDict::new()
        };

        let res = Self { url, query };

        Ok(res)
    }
}

/// Request decoder options.
#[derive(Copy, Clone)]
pub struct RequestDecoderOptions {
    header_decoder_options: RequestHeaderDecoderOptions,
    max_body_size: Option<usize>,
}

impl RequestDecoderOptions {
    /// Create a new request decoder options builder.
    #[inline]
    pub const fn new() -> Self {
        let max_body_size = Some(2_048_000);

        let header_decoder_options = RequestHeaderDecoderOptions::new()
            .max_line_length(Some(4096))
            .max_header_field_length(Some(4096))
            .max_header_fields(Some(64));

        Self {
            header_decoder_options,
            max_body_size,
        }
    }

    /// Enable or disable acceptance of all line endings (CR, LF, CRLF).
    #[inline]
    pub const fn accept_all_line_endings(mut self, enabled: bool) -> Self {
        self.header_decoder_options = self.header_decoder_options.accept_all_line_endings(enabled);
        self
    }

    /// Set maximum line length for request header lines and chunked body
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

    /// Set maximum number of lines for the request header.
    #[inline]
    pub const fn max_header_fields(mut self, max_fields: Option<usize>) -> Self {
        self.header_decoder_options = self.header_decoder_options.max_header_fields(max_fields);
        self
    }

    /// Set the maximum size of a request body.
    #[inline]
    pub const fn max_body_size(mut self, size: Option<usize>) -> Self {
        self.max_body_size = size;
        self
    }
}

impl Default for RequestDecoderOptions {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

/// RTSP request decoder.
///
/// It is a greedy decoder, i.e. it will consume all data until a complete
/// request can be returned.
pub struct RequestDecoder {
    header_decoder: RequestHeaderDecoder,
    header: Option<RequestHeader>,
    body_decoder: FixedSizeBodyDecoder,
    body: BytesMut,
    max_body_size: Option<usize>,
}

impl RequestDecoder {
    /// Create a new RTSP request decoder with given options.
    pub fn new(options: RequestDecoderOptions) -> Self {
        Self {
            header_decoder: RequestHeaderDecoder::new(options.header_decoder_options),
            header: None,
            body_decoder: FixedSizeBodyDecoder::new(0),
            body: BytesMut::new(),
            max_body_size: options.max_body_size,
        }
    }

    /// Try to decode an RTSP header.
    fn decode_header(&mut self, data: &mut BytesMut) -> Result<Option<RequestHeader>, Error> {
        self.header_decoder.decode(data).map_err(|err| {
            Error::from_static_msg_and_cause("unable to decode a request header", err)
        })
    }

    /// Try to decode an RTSP header at the end of stream.
    fn decode_header_eof(&mut self, data: &mut BytesMut) -> Result<Option<RequestHeader>, Error> {
        self.header_decoder.decode_eof(data).map_err(|err| {
            Error::from_static_msg_and_cause("unable to decode a request header", err)
        })
    }

    /// Try to decode a chunk of request body.
    fn decode_body(&mut self, data: &mut BytesMut) -> Result<Option<Bytes>, Error> {
        self.body_decoder
            .decode(data)
            .map_err(|err| Error::from_static_msg_and_cause("unable to decode a request body", err))
    }

    /// Try to decode a chunk of request body at the end of stream.
    fn decode_body_eof(&mut self, data: &mut BytesMut) -> Result<Option<Bytes>, Error> {
        self.body_decoder
            .decode_eof(data)
            .map_err(|err| Error::from_static_msg_and_cause("unable to decode a request body", err))
    }

    /// Process a given request header.
    fn process_header(&mut self, header: RequestHeader) -> Result<(), Error> {
        let content_length = header
            .get_header_field_value("content-length")
            .map(|value| value.parse())
            .transpose()
            .map_err(|_| BadRequest::from_static_msg("invalid Content-Length value"))?
            .unwrap_or(0);

        if let Some(max_body_size) = self.max_body_size
            && content_length > max_body_size
        {
            return Err(Error::from(BadRequest::from_static_msg(
                "maximum request body size exceeded",
            )));
        }

        self.header = Some(header);

        self.body_decoder = FixedSizeBodyDecoder::new(content_length);

        Ok(())
    }

    /// Take the current request.
    fn take_request(&mut self) -> Option<Request> {
        self.header_decoder.reset();

        let header = self.header.take()?;
        let body = self.body.split();

        Some(Request::new(header, body.freeze()))
    }
}

impl Decoder for RequestDecoder {
    type Item = Request;
    type Error = Error;

    fn decode(&mut self, data: &mut BytesMut) -> Result<Option<Request>, Error> {
        loop {
            if self.header.is_none() {
                if let Some(header) = self.decode_header(data)? {
                    self.process_header(header)?;
                } else {
                    return Ok(None);
                }
            } else if self.body_decoder.is_complete() {
                return Ok(self.take_request());
            } else if let Some(chunk) = self.decode_body(data)? {
                self.body.extend_from_slice(&chunk);
            } else {
                return Ok(None);
            }
        }
    }

    fn decode_eof(&mut self, data: &mut BytesMut) -> Result<Option<Request>, Error> {
        loop {
            if self.header.is_none() {
                if let Some(header) = self.decode_header_eof(data)? {
                    self.process_header(header)?;
                } else if data.is_empty() {
                    return Ok(None);
                } else {
                    return Err(Error::from_static_msg("incomplete request"));
                }
            } else if self.body_decoder.is_complete() {
                return Ok(self.take_request());
            } else if let Some(chunk) = self.decode_body_eof(data)? {
                self.body.extend_from_slice(&chunk);
            } else {
                return Err(Error::from_static_msg("incomplete request"));
            }
        }
    }
}
