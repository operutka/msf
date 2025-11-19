#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(any(feature = "client", feature = "server"))]
mod connection;

#[cfg(any(feature = "client", feature = "server"))]
mod interleaved;

#[cfg(feature = "client")]
#[cfg_attr(docsrs, doc(cfg(feature = "client")))]
pub mod client;

pub mod header;
pub mod request;
pub mod response;

#[cfg(feature = "server")]
#[cfg_attr(docsrs, doc(cfg(feature = "server")))]
pub mod server;

#[cfg(any(feature = "client", feature = "server"))]
#[cfg_attr(docsrs, doc(cfg(any(feature = "client", feature = "server"))))]
pub mod udp;

use std::{
    convert::Infallible,
    fmt::{self, Display, Formatter},
    io,
    str::FromStr,
};

use bytes::Bytes;
use ttpkit::Error as BaseError;

#[cfg(feature = "server")]
use self::server::OutgoingResponse;

pub use msf_rtp as rtp;
pub use msf_sdp as sdp;

pub use ttpkit::{self, error::CodecError};

#[cfg(any(feature = "client", feature = "server"))]
#[cfg_attr(docsrs, doc(cfg(any(feature = "client", feature = "server"))))]
pub use ttpkit_url as url;

pub use self::{
    request::{Request, RequestHeader},
    response::{Response, ResponseHeader, Status},
};

/// Inner error.
#[derive(Debug)]
enum InnerError {
    Error(BaseError),

    #[cfg(feature = "server")]
    ErrorWithResponse(Box<dyn ErrorToResponse + Send + Sync>),
}

/// Error type.
#[derive(Debug)]
pub struct Error {
    inner: InnerError,
}

impl Error {
    /// Create a new error with a given message.
    pub fn from_msg<T>(msg: T) -> Self
    where
        T: Into<String>,
    {
        Self {
            inner: InnerError::Error(BaseError::from_msg(msg)),
        }
    }

    /// Create a new error with a given message.
    #[inline]
    pub const fn from_static_msg(msg: &'static str) -> Self {
        Self {
            inner: InnerError::Error(BaseError::from_static_msg(msg)),
        }
    }

    /// Create a new error with a given message and cause.
    pub fn from_msg_and_cause<T, E>(msg: T, cause: E) -> Self
    where
        T: Into<String>,
        E: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        Self {
            inner: InnerError::Error(BaseError::from_msg_and_cause(msg, cause)),
        }
    }

    /// Create a new error with a given message and cause.
    pub fn from_static_msg_and_cause<E>(msg: &'static str, cause: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        Self {
            inner: InnerError::Error(BaseError::from_static_msg_and_cause(msg, cause)),
        }
    }

    /// Create a new error from a given custom error.
    pub fn from_other<T>(err: T) -> Self
    where
        T: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        Self {
            inner: InnerError::Error(BaseError::from_cause(err)),
        }
    }

    /// Create a new error from a given custom error.
    #[cfg(feature = "server")]
    #[cfg_attr(docsrs, doc(cfg(feature = "server")))]
    pub fn from_other_with_response<T>(err: T) -> Self
    where
        T: ErrorToResponse + Send + Sync + 'static,
    {
        Self {
            inner: InnerError::ErrorWithResponse(Box::new(err)),
        }
    }

    /// Get error response (if supported).
    #[cfg(feature = "server")]
    #[cfg_attr(docsrs, doc(cfg(feature = "server")))]
    pub fn to_response(&self) -> Option<OutgoingResponse> {
        if let InnerError::ErrorWithResponse(err) = &self.inner {
            Some(err.to_response())
        } else {
            None
        }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        match &self.inner {
            InnerError::Error(err) => Display::fmt(err, f),

            #[cfg(feature = "server")]
            InnerError::ErrorWithResponse(err) => Display::fmt(err, f),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.inner {
            InnerError::Error(err) => err.source(),

            #[cfg(feature = "server")]
            InnerError::ErrorWithResponse(err) => err.source(),
        }
    }
}

impl From<Infallible> for Error {
    #[inline]
    fn from(_: Infallible) -> Self {
        unreachable!()
    }
}

impl From<io::Error> for Error {
    #[inline]
    fn from(err: io::Error) -> Self {
        Self::from_msg_and_cause("IO", err)
    }
}

impl From<str_reader::ParseError> for Error {
    #[inline]
    fn from(err: str_reader::ParseError) -> Self {
        Self::from_other(err)
    }
}

#[cfg(feature = "server")]
impl<T> From<T> for Error
where
    T: ErrorToResponse + Send + Sync + 'static,
{
    fn from(err: T) -> Self {
        Self::from_other_with_response(err)
    }
}

impl From<Error> for ttpkit::Error {
    fn from(err: Error) -> Self {
        match err.inner {
            InnerError::Error(err) => err,

            #[cfg(feature = "server")]
            InnerError::ErrorWithResponse(_) => ttpkit::Error::from_cause(err),
        }
    }
}

/// Trait for errors that can generate an error response.
#[cfg(feature = "server")]
#[cfg_attr(docsrs, doc(cfg(feature = "server")))]
pub trait ErrorToResponse: std::error::Error {
    /// Create a custom RTSP error response.
    fn to_response(&self) -> OutgoingResponse;
}

/// Type placeholder for RTSP protocol.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
struct Protocol;

impl AsRef<[u8]> for Protocol {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        b"RTSP"
    }
}

impl TryFrom<Bytes> for Protocol {
    type Error = Error;

    fn try_from(value: Bytes) -> Result<Self, Self::Error> {
        if value.as_ref() == b"RTSP" {
            Ok(Self)
        } else {
            Err(Error::from_msg(format!(
                "invalid protocol string \"{}\"",
                value.escape_ascii()
            )))
        }
    }
}

/// RTSP version.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Version {
    Version10,
    Version20,
}

impl AsRef<[u8]> for Version {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Version10 => b"1.0",
            Self::Version20 => b"2.0",
        }
    }
}

impl AsRef<str> for Version {
    #[inline]
    fn as_ref(&self) -> &str {
        match self {
            Self::Version10 => "1.0",
            Self::Version20 => "2.0",
        }
    }
}

impl Display for Version {
    #[inline]
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.write_str(self.as_ref())
    }
}

impl TryFrom<Bytes> for Version {
    type Error = Error;

    fn try_from(value: Bytes) -> Result<Self, Self::Error> {
        let res = match value.as_ref() {
            b"1.0" => Self::Version10,
            b"2.0" => Self::Version20,
            _ => {
                return Err(Error::from_msg(format!(
                    "unsupported RTSP protocol version: \"{}\"",
                    value.escape_ascii()
                )));
            }
        };

        Ok(res)
    }
}

/// RTSP method.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Method {
    Options,
    Describe,
    Announce,
    Setup,
    Play,
    Pause,
    Teardown,
    GetParameter,
    SetParameter,
    Redirect,
    Record,
}

impl AsRef<[u8]> for Method {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Options => b"OPTIONS",
            Self::Describe => b"DESCRIBE",
            Self::Announce => b"ANNOUNCE",
            Self::Setup => b"SETUP",
            Self::Play => b"PLAY",
            Self::Pause => b"PAUSE",
            Self::Teardown => b"TEARDOWN",
            Self::GetParameter => b"GET_PARAMETER",
            Self::SetParameter => b"SET_PARAMETER",
            Self::Redirect => b"REDIRECT",
            Self::Record => b"RECORD",
        }
    }
}

impl AsRef<str> for Method {
    fn as_ref(&self) -> &str {
        match self {
            Self::Options => "OPTIONS",
            Self::Describe => "DESCRIBE",
            Self::Announce => "ANNOUNCE",
            Self::Setup => "SETUP",
            Self::Play => "PLAY",
            Self::Pause => "PAUSE",
            Self::Teardown => "TEARDOWN",
            Self::GetParameter => "GET_PARAMETER",
            Self::SetParameter => "SET_PARAMETER",
            Self::Redirect => "REDIRECT",
            Self::Record => "RECORD",
        }
    }
}

impl Display for Method {
    #[inline]
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.write_str(self.as_ref())
    }
}

impl TryFrom<Bytes> for Method {
    type Error = Error;

    fn try_from(value: Bytes) -> Result<Self, Self::Error> {
        let res = match value.as_ref() {
            b"OPTIONS" => Self::Options,
            b"DESCRIBE" => Self::Describe,
            b"ANNOUNCE" => Self::Announce,
            b"SETUP" => Self::Setup,
            b"PLAY" => Self::Play,
            b"PAUSE" => Self::Pause,
            b"TEARDOWN" => Self::Teardown,
            b"GET_PARAMETER" => Self::GetParameter,
            b"SET_PARAMETER" => Self::SetParameter,
            b"REDIRECT" => Self::Redirect,
            b"RECORD" => Self::Record,
            _ => {
                return Err(Error::from_msg(format!(
                    "unsupported RTSP method: \"{}\"",
                    value.escape_ascii()
                )));
            }
        };

        Ok(res)
    }
}

/// Valid URL schemes.
#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Scheme {
    RTSP,
}

impl Scheme {
    /// Get default port for this URL scheme.
    #[inline]
    pub fn default_port(self) -> u16 {
        match self {
            Self::RTSP => 554,
        }
    }
}

impl AsRef<str> for Scheme {
    #[inline]
    fn as_ref(&self) -> &str {
        match self {
            Self::RTSP => "rtsp",
        }
    }
}

impl Display for Scheme {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_ref())
    }
}

impl FromStr for Scheme {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.eq_ignore_ascii_case("rtsp") {
            Ok(Self::RTSP)
        } else {
            Err(Error::from_msg(format!("invalid URL scheme: \"{value}\"")))
        }
    }
}
