//! RTSP error types.

use std::{
    borrow::Cow,
    fmt::{self, Debug, Display, Formatter},
};

use crate::{
    Error, ErrorToResponse,
    header::HeaderFieldValue,
    server::response::{self, OutgoingResponse, Status},
};

macro_rules! empty_error_response {
    ($t:ident, $msg:expr, $response_fn:ident) => {
        /// Error response.
        #[derive(Debug)]
        pub struct $t;

        impl Display for $t {
            #[inline]
            fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
                f.write_str($msg)
            }
        }

        impl std::error::Error for $t {}

        impl ErrorToResponse for $t {
            #[inline]
            fn to_response(&self) -> OutgoingResponse {
                response::$response_fn()
            }
        }
    };
}

/// Bad Request error.
#[derive(Debug)]
pub struct BadRequest {
    msg: Cow<'static, str>,
}

impl BadRequest {
    /// Create a new Bad Request error with a given message.
    #[inline]
    pub const fn from_static_msg(msg: &'static str) -> Self {
        Self {
            msg: Cow::Borrowed(msg),
        }
    }
}

impl Display for BadRequest {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&self.msg)
    }
}

impl std::error::Error for BadRequest {}

impl ErrorToResponse for BadRequest {
    #[inline]
    fn to_response(&self) -> OutgoingResponse {
        response::bad_request(self.msg.to_string())
    }
}

/// Unauthorized error.
#[derive(Debug)]
pub struct Unauthorized<T> {
    challenges: T,
}

impl<T> Unauthorized<T> {
    /// Create a new Unauthorized error.
    #[inline]
    pub fn new(challenges: T) -> Self {
        Self { challenges }
    }
}

impl<T> Display for Unauthorized<T> {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("unauthorized")
    }
}

impl<T> std::error::Error for Unauthorized<T> where T: Debug {}

impl<T, I> ErrorToResponse for Unauthorized<T>
where
    T: IntoIterator<Item = I> + Clone + Debug,
    I: Into<HeaderFieldValue>,
{
    #[inline]
    fn to_response(&self) -> OutgoingResponse {
        response::unauthorized(self.challenges.clone())
    }
}

empty_error_response!(NotFound, "not found", not_found);

/// Method Not Allowed error.
#[derive(Debug)]
pub struct MethodNotAllowed {
    allowed: HeaderFieldValue,
}

impl MethodNotAllowed {
    /// Create a new Method Not Allowed error.
    pub fn new<T>(allowed: T) -> Self
    where
        T: Into<HeaderFieldValue>,
    {
        Self {
            allowed: allowed.into(),
        }
    }
}

impl Display for MethodNotAllowed {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("method not allowed")
    }
}

impl std::error::Error for MethodNotAllowed {}

impl ErrorToResponse for MethodNotAllowed {
    #[inline]
    fn to_response(&self) -> OutgoingResponse {
        response::method_not_allowed(self.allowed.clone())
    }
}

empty_error_response!(SessionNotFound, "session not found", session_not_found);

empty_error_response!(
    MethodNotValidInThisState,
    "method not valid in this state",
    method_not_valid_in_this_state
);

/// Header Field Not Valid for Resource error.
#[derive(Debug)]
pub struct HeaderFieldNotValidForResource {
    accept_ranges: Option<HeaderFieldValue>,
}

impl HeaderFieldNotValidForResource {
    /// Create a new Header Field Not Valid for Resource error with a given
    /// Accept-Ranges response header.
    pub fn accept_ranges<T>(ranges: T) -> Self
    where
        T: Into<HeaderFieldValue>,
    {
        Self {
            accept_ranges: Some(ranges.into()),
        }
    }
}

impl Display for HeaderFieldNotValidForResource {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("header field not valid")
    }
}

impl std::error::Error for HeaderFieldNotValidForResource {}

impl ErrorToResponse for HeaderFieldNotValidForResource {
    fn to_response(&self) -> OutgoingResponse {
        let mut builder =
            OutgoingResponse::builder().set_status(Status::HEADER_FIELD_NOT_VALID_FOR_RESOURCE);

        if let Some(accept_ranges) = self.accept_ranges.as_ref() {
            builder = builder.add_header_field(("Accept-Ranges", accept_ranges.clone()));
        }

        builder.build()
    }
}

empty_error_response!(InvalidRange, "invalid range", invalid_range);

empty_error_response!(
    UnsupportedTransport,
    "unsupported transport",
    unsupported_transport
);

empty_error_response!(
    DestinationProhibited,
    "destination prohibited",
    destination_prohibited
);

/// Internal Server Error.
#[derive(Debug)]
pub struct InternalServerError {
    msg: Cow<'static, str>,
    cause: Box<dyn std::error::Error + Send + Sync>,
}

impl InternalServerError {
    /// Create a new Internal Server Error with a given message and cause.
    ///
    /// The message will be sent over to the client. The cause won't be
    /// exposed.
    pub fn from_msg_and_cause<T, E>(msg: T, cause: E) -> Self
    where
        T: Into<String>,
        E: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        Self {
            msg: Cow::Owned(msg.into()),
            cause: cause.into(),
        }
    }

    /// Create a new Internal Server Error with a given message and cause.
    ///
    /// The message will be sent over to the client. The cause won't be
    /// exposed.
    pub fn from_static_msg_and_cause<E>(msg: &'static str, cause: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        Self {
            msg: Cow::Borrowed(msg),
            cause: cause.into(),
        }
    }
}

impl Display for InternalServerError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.msg, self.cause)
    }
}

impl std::error::Error for InternalServerError {
    #[inline]
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.cause.as_ref())
    }
}

impl ErrorToResponse for InternalServerError {
    #[inline]
    fn to_response(&self) -> OutgoingResponse {
        response::internal_server_error(self.msg.to_string())
    }
}

/// Not Implemented error.
#[derive(Debug)]
pub struct NotImplemented {
    public: HeaderFieldValue,
}

impl NotImplemented {
    /// Create a new Not Implemented error.
    pub fn new<T>(public: T) -> Self
    where
        T: Into<HeaderFieldValue>,
    {
        Self {
            public: public.into(),
        }
    }
}

impl Display for NotImplemented {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("not implemented")
    }
}

impl std::error::Error for NotImplemented {}

impl ErrorToResponse for NotImplemented {
    #[inline]
    fn to_response(&self) -> OutgoingResponse {
        response::not_implemented(self.public.clone())
    }
}

/// Bad Gateway error.
#[derive(Debug)]
pub struct BadGateway {
    inner: Error,
}

impl BadGateway {
    /// Create a new Bad Gateway error with a given message.
    #[inline]
    pub const fn from_static_msg(msg: &'static str) -> Self {
        Self {
            inner: Error::from_static_msg(msg),
        }
    }

    /// Create a new Bad Gateway error with a given message and cause.
    pub fn from_static_msg_and_cause<E>(msg: &'static str, cause: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        Self {
            inner: Error::from_static_msg_and_cause(msg, cause),
        }
    }

    /// Create a new Bad Gateway error from a given cause.
    pub fn from_cause<E>(cause: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        Self {
            inner: Error::from_other(cause),
        }
    }
}

impl Display for BadGateway {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.inner, f)
    }
}

impl std::error::Error for BadGateway {
    #[inline]
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.inner.source()
    }
}

impl ErrorToResponse for BadGateway {
    #[inline]
    fn to_response(&self) -> OutgoingResponse {
        response::bad_gateway(self.inner.to_string())
    }
}
