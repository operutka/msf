//! Request types.

use bytes::{Bytes, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

use crate::{
    CodecError, Method, Protocol, Version,
    header::{FieldIter, HeaderField, HeaderFieldValue, Iter},
    ttpkit::request::{
        RequestHeader as GenericRequestHeader, RequestHeaderBuilder as GenericRequestHeaderBuilder,
        RequestHeaderDecoder as GenericRequestHeaderDecoder,
        RequestHeaderEncoder as GenericRequestHeaderEncoder,
    },
};

pub use crate::ttpkit::request::{RequestHeaderDecoderOptions, RequestPath};

/// RTSP request header.
#[derive(Clone)]
pub struct RequestHeader {
    inner: GenericRequestHeader<Protocol, Version, Method>,
}

impl RequestHeader {
    /// Create a new request header.
    #[inline]
    pub(crate) const fn new(header: GenericRequestHeader<Protocol, Version, Method>) -> Self {
        Self { inner: header }
    }

    /// Get the request method.
    #[inline]
    pub fn method(&self) -> Method {
        *self.inner.method()
    }

    /// Get the request protocol version.
    #[inline]
    pub fn version(&self) -> Version {
        *self.inner.version()
    }

    /// Get the request path.
    #[inline]
    pub fn path(&self) -> &RequestPath {
        self.inner.path()
    }

    /// Get all header fields.
    #[inline]
    pub fn get_all_header_fields(&self) -> Iter<'_> {
        self.inner.get_all_header_fields()
    }

    /// Get header fields corresponding to a given name.
    pub fn get_header_fields<'a, N>(&'a self, name: &'a N) -> FieldIter<'a>
    where
        N: AsRef<[u8]> + ?Sized,
    {
        self.inner.get_header_fields(name)
    }

    /// Get the last header field of a given name.
    pub fn get_header_field<'a, N>(&'a self, name: &'a N) -> Option<&'a HeaderField>
    where
        N: AsRef<[u8]> + ?Sized,
    {
        self.inner.get_header_field(name)
    }

    /// Get value of the last header field with a given name.
    pub fn get_header_field_value<'a, N>(&'a self, name: &'a N) -> Option<&'a HeaderFieldValue>
    where
        N: AsRef<[u8]> + ?Sized,
    {
        self.inner.get_header_field_value(name)
    }
}

/// RTSP request builder.
#[derive(Clone)]
pub struct RequestBuilder {
    inner: GenericRequestHeaderBuilder<Protocol, Version, Method>,
}

impl RequestBuilder {
    /// Create a new builder.
    #[inline]
    const fn new(version: Version, method: Method, path: RequestPath) -> Self {
        Self {
            inner: GenericRequestHeader::builder(Protocol, version, method, path),
        }
    }

    /// Set the protocol version.
    #[inline]
    pub fn set_version(mut self, version: Version) -> Self {
        self.inner = self.inner.set_version(version);
        self
    }

    /// Set the request method.
    #[inline]
    pub fn set_method(mut self, method: Method) -> Self {
        self.inner = self.inner.set_method(method);
        self
    }

    /// Set the request path.
    #[inline]
    pub fn set_path(mut self, path: RequestPath) -> Self {
        self.inner = self.inner.set_path(path);
        self
    }

    /// Replace the current header fields having the same name (if any).
    pub fn set_header_field<T>(mut self, field: T) -> Self
    where
        T: Into<HeaderField>,
    {
        self.inner = self.inner.set_header_field(field);
        self
    }

    /// Add a given header field.
    pub fn add_header_field<T>(mut self, field: T) -> Self
    where
        T: Into<HeaderField>,
    {
        self.inner = self.inner.add_header_field(field);
        self
    }

    /// Remove all header fields with a given name.
    pub fn remove_header_fields<N>(mut self, name: &N) -> Self
    where
        N: AsRef<[u8]> + ?Sized,
    {
        self.inner = self.inner.remove_header_fields(name);
        self
    }

    /// Build just the request header.
    #[inline]
    pub fn header(self) -> RequestHeader {
        RequestHeader::new(self.inner.build())
    }

    /// Build the request.
    pub fn body(self, body: Bytes) -> Request {
        Request::new(self.header(), body)
    }
}

impl From<RequestHeader> for RequestBuilder {
    #[inline]
    fn from(header: RequestHeader) -> Self {
        Self {
            inner: header.inner.into(),
        }
    }
}

/// HTTP request.
#[derive(Clone)]
pub struct Request {
    header: RequestHeader,
    body: Bytes,
}

impl Request {
    /// Get a request builder.
    #[inline]
    pub const fn builder(version: Version, method: Method, path: RequestPath) -> RequestBuilder {
        RequestBuilder::new(version, method, path)
    }

    /// Create a new request.
    pub(crate) const fn new(header: RequestHeader, body: Bytes) -> Self {
        Self { header, body }
    }

    /// Get the request header.
    #[inline]
    pub fn header(&self) -> &RequestHeader {
        &self.header
    }

    /// Get the request method.
    #[inline]
    pub fn method(&self) -> Method {
        self.header.method()
    }

    /// Get the request protocol version.
    #[inline]
    pub fn version(&self) -> Version {
        self.header.version()
    }

    /// Get the request path.
    #[inline]
    pub fn path(&self) -> &RequestPath {
        self.header.path()
    }

    /// Get all header fields.
    #[inline]
    pub fn get_all_header_fields(&self) -> Iter<'_> {
        self.header.get_all_header_fields()
    }

    /// Get header fields corresponding to a given name.
    pub fn get_header_fields<'a, N>(&'a self, name: &'a N) -> FieldIter<'a>
    where
        N: AsRef<[u8]> + ?Sized,
    {
        self.header.get_header_fields(name)
    }

    /// Get the last header field of a given name.
    pub fn get_header_field<'a, N>(&'a self, name: &'a N) -> Option<&'a HeaderField>
    where
        N: AsRef<[u8]> + ?Sized,
    {
        self.header.get_header_field(name)
    }

    /// Get value of the last header field with a given name.
    pub fn get_header_field_value<'a, N>(&'a self, name: &'a N) -> Option<&'a HeaderFieldValue>
    where
        N: AsRef<[u8]> + ?Sized,
    {
        self.header.get_header_field_value(name)
    }

    /// Get the request body.
    #[inline]
    pub fn body(&self) -> &Bytes {
        &self.body
    }

    /// Split the request into its header and body.
    #[inline]
    pub fn deconstruct(self) -> (RequestHeader, Bytes) {
        (self.header, self.body)
    }
}

/// Request header decoder.
pub struct RequestHeaderDecoder {
    inner: GenericRequestHeaderDecoder<Protocol, Version, Method>,
}

impl RequestHeaderDecoder {
    /// Create a new decoder.
    #[inline]
    pub fn new(options: RequestHeaderDecoderOptions) -> Self {
        Self {
            inner: GenericRequestHeaderDecoder::new(options),
        }
    }

    /// Reset the decoder and make it ready for parsing a new request header.
    #[inline]
    pub fn reset(&mut self) {
        self.inner.reset();
    }

    /// Decode a given request header chunk.
    pub fn decode(&mut self, data: &mut BytesMut) -> Result<Option<RequestHeader>, CodecError> {
        let res = self.inner.decode(data)?.map(RequestHeader::new);

        Ok(res)
    }

    /// Decode a given request header chunk at the end of the stream.
    pub fn decode_eof(&mut self, data: &mut BytesMut) -> Result<Option<RequestHeader>, CodecError> {
        let res = self.inner.decode_eof(data)?.map(RequestHeader::new);

        Ok(res)
    }
}

impl Decoder for RequestHeaderDecoder {
    type Item = RequestHeader;
    type Error = CodecError;

    #[inline]
    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        Self::decode(self, buf)
    }

    #[inline]
    fn decode_eof(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        Self::decode_eof(self, buf)
    }
}

/// Request header encoder.
pub struct RequestHeaderEncoder {
    inner: GenericRequestHeaderEncoder,
}

impl RequestHeaderEncoder {
    /// Create a new encoder.
    #[inline]
    pub const fn new() -> Self {
        Self {
            inner: GenericRequestHeaderEncoder::new(),
        }
    }

    /// Encode a given request header into a given buffer.
    #[inline]
    pub fn encode(&mut self, header: &RequestHeader, dst: &mut BytesMut) {
        self.inner.encode(&header.inner, dst);
    }
}

impl Default for RequestHeaderEncoder {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl Encoder<&RequestHeader> for RequestHeaderEncoder {
    type Error = CodecError;

    #[inline]
    fn encode(&mut self, header: &RequestHeader, dst: &mut BytesMut) -> Result<(), Self::Error> {
        Self::encode(self, header, dst);

        Ok(())
    }
}
