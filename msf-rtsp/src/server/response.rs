//! RTSP server response types.

use std::{borrow::Borrow, fmt::Display, ops::Deref};

use bytes::Bytes;

use crate::{
    Version,
    header::{HeaderField, HeaderFieldValue, ValueListDisplay},
    response::{Response, ResponseBuilder, ResponseHeader},
};

pub use crate::response::Status;

/// Builder for outgoing RTSP responses.
pub struct OutgoingResponseBuilder {
    inner: ResponseBuilder,
    body: Bytes,
}

impl OutgoingResponseBuilder {
    /// Create a new builder.
    #[inline]
    pub const fn new() -> Self {
        Self {
            inner: Response::builder(),
            body: Bytes::new(),
        }
    }

    /// Create a new response builder with a given status.
    #[inline]
    pub fn new_with_status(status: Status) -> Self {
        Self {
            inner: ResponseBuilder::new_with_status(status),
            body: Bytes::new(),
        }
    }

    /// Set the RTSP version.
    #[inline]
    pub fn set_version(mut self, version: Version) -> Self {
        self.inner = self.inner.set_version(version);
        self
    }

    /// Set response status.
    #[inline]
    pub fn set_status(mut self, status: Status) -> Self {
        self.inner = self.inner.set_status(status);
        self
    }

    /// Replace all header fields having the same name (if any).
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

    /// Set the response body.
    pub fn set_body<B>(mut self, body: B) -> Self
    where
        B: Into<Bytes>,
    {
        self.body = body.into();
        self
    }

    /// Build the response.
    pub fn build(self) -> OutgoingResponse {
        let inner = self
            .inner
            .set_header_field(("Content-Length", self.body.len()))
            .body(self.body)
            .into();

        OutgoingResponse { inner }
    }
}

impl Default for OutgoingResponseBuilder {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl From<ResponseHeader> for OutgoingResponseBuilder {
    #[inline]
    fn from(header: ResponseHeader) -> Self {
        Self {
            inner: header.into(),
            body: Bytes::new(),
        }
    }
}

impl From<OutgoingResponse> for OutgoingResponseBuilder {
    #[inline]
    fn from(response: OutgoingResponse) -> Self {
        let (header, body) = response.deconstruct();

        Self {
            inner: header.into(),
            body,
        }
    }
}

/// Outgoing RTSP response.
#[derive(Clone)]
pub struct OutgoingResponse {
    inner: Box<Response>,
}

impl OutgoingResponse {
    /// Get a builder for the outgoing RTSP response.
    #[inline]
    pub const fn builder() -> OutgoingResponseBuilder {
        OutgoingResponseBuilder::new()
    }

    /// Deconstruct the response back into its response header and body.
    #[inline]
    pub fn deconstruct(self) -> (ResponseHeader, Bytes) {
        self.inner.deconstruct()
    }
}

impl AsRef<Response> for OutgoingResponse {
    #[inline]
    fn as_ref(&self) -> &Response {
        &self.inner
    }
}

impl Borrow<Response> for OutgoingResponse {
    #[inline]
    fn borrow(&self) -> &Response {
        &self.inner
    }
}

impl Deref for OutgoingResponse {
    type Target = Response;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// Create a new empty response with a given status.
#[inline(never)]
pub fn empty_response(status: Status) -> OutgoingResponse {
    OutgoingResponse::builder().set_status(status).build()
}

/// Create a new plain text response with a given status and body.
pub fn plain_text_response<T>(status: Status, body: T) -> OutgoingResponse
where
    T: Into<String>,
{
    // helper function to avoid expensive monomorphizations
    #[inline(never)]
    fn inner(status: Status, body: String) -> OutgoingResponse {
        OutgoingResponse::builder()
            .set_status(status)
            .add_header_field(("Content-Type", "text/plain"))
            .set_body(Bytes::from(body))
            .build()
    }

    inner(status, body.into())
}

/// Create a new OK response.
#[inline]
pub fn ok() -> OutgoingResponse {
    empty_response(Status::OK)
}

/// Create a new No Content response.
#[inline]
pub fn no_content() -> OutgoingResponse {
    empty_response(Status::NO_CONTENT)
}

/// Create a new Bad Request response.
pub fn bad_request<T>(msg: T) -> OutgoingResponse
where
    T: Into<String>,
{
    plain_text_response(Status::BAD_REQUEST, msg)
}

/// Create a new Unauthorized response.
pub fn unauthorized<T, I>(challenges: T) -> OutgoingResponse
where
    T: IntoIterator<Item = I>,
    I: Into<HeaderFieldValue>,
{
    let mut builder = OutgoingResponse::builder().set_status(Status::UNAUTHORIZED);

    for challenge in challenges {
        builder = builder.add_header_field(("WWW-Authenticate", challenge));
    }

    builder.build()
}

/// Create a new Not Found response.
#[inline]
pub fn not_found() -> OutgoingResponse {
    empty_response(Status::NOT_FOUND)
}

/// Create a new Session Not Found response.
#[inline]
pub fn session_not_found() -> OutgoingResponse {
    empty_response(Status::SESSION_NOT_FOUND)
}

/// Create a new Method Not Allowed response.
pub fn method_not_allowed<T>(allow: T) -> OutgoingResponse
where
    T: Into<HeaderFieldValue>,
{
    // helper function to avoid expensive monomorphizations
    fn inner(allow: HeaderFieldValue) -> OutgoingResponse {
        OutgoingResponse::builder()
            .set_status(Status::METHOD_NOT_ALLOWED)
            .add_header_field(("Allow", allow))
            .build()
    }

    inner(allow.into())
}

/// Create a new Method Not Valid in This State response.
#[inline]
pub fn method_not_valid_in_this_state() -> OutgoingResponse {
    empty_response(Status::METHOD_NOT_VALID_IN_THIS_STATE)
}

/// Create a new Invalid Range response.
#[inline]
pub fn invalid_range() -> OutgoingResponse {
    empty_response(Status::INVALID_RANGE)
}

/// Create a new Unsupported Transport response.
#[inline]
pub fn unsupported_transport() -> OutgoingResponse {
    empty_response(Status::UNSUPPORTED_TRANSPORT)
}

/// A function returning Destination Prohibited response.
#[inline]
pub fn destination_prohibited() -> OutgoingResponse {
    empty_response(Status::DESTINATION_PROHIBITED)
}

/// Create a new Internal Server Error response.
#[inline]
pub fn internal_server_error<T>(msg: T) -> OutgoingResponse
where
    T: Into<String>,
{
    plain_text_response(Status::INTERNAL_SERVER_ERROR, msg)
}

/// Create a new Not Implemented response.
pub fn not_implemented<T>(public: T) -> OutgoingResponse
where
    T: Into<HeaderFieldValue>,
{
    // helper function to avoid expensive monomorphizations
    fn inner(public: HeaderFieldValue) -> OutgoingResponse {
        OutgoingResponse::builder()
            .set_status(Status::NOT_IMPLEMENTED)
            .add_header_field(("Public", public))
            .build()
    }

    inner(public.into())
}

/// Create a new Bad Gateway response.
pub fn bad_gateway<T>(msg: T) -> OutgoingResponse
where
    T: Into<String>,
{
    plain_text_response(Status::BAD_GATEWAY, msg)
}

/// Create a new RTSP Version Not Supported response.
#[inline]
pub fn rtsp_version_not_supported() -> OutgoingResponse {
    empty_response(Status::RTSP_VERSION_NOT_SUPPORTED)
}

/// Create a new Option Not Supported response.
pub fn option_not_supported<T, I>(unsupported: T) -> OutgoingResponse
where
    T: IntoIterator<Item = I> + Clone,
    I: Display,
{
    // helper function to avoid expensive monomorphizations
    fn inner(unsupported: HeaderFieldValue) -> OutgoingResponse {
        OutgoingResponse::builder()
            .set_status(Status::OPTION_NOT_SUPPORTED)
            .add_header_field(("Unsupported", unsupported))
            .build()
    }

    let unsupported = ValueListDisplay::new(", ", unsupported);

    inner(unsupported.into())
}
