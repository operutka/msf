//! RTSP client and related types.

mod connector;
mod request;
mod response;
mod session;

pub mod auth;

use std::{sync::Arc, time::Duration};

use self::{auth::NoAuthProvider, response::ResponseDecoderOptions};

pub use self::{
    connector::{
        Connection, ConnectionInfo, Connector, DefaultConnectionInfo, DefaultConnector,
        InterleavedChannel,
    },
    request::OutgoingRequest,
    response::IncomingResponse,
    session::{Session, SessionBuilder},
};

/// RTSP client builder.
pub struct ClientBuilder<C = DefaultConnector> {
    connector: C,
    options: ClientOptions,
}

impl ClientBuilder {
    /// Create a new client builder.
    #[inline]
    const fn new() -> Self {
        Self {
            connector: DefaultConnector::new(),
            options: ClientOptions::new(),
        }
    }
}

impl<C> ClientBuilder<C> {
    /// Enable or disable acceptance of all line endings (CR, LF, CRLF).
    ///
    /// The default is false (i.e. only CRLF will be accepted).
    #[inline]
    pub const fn accept_all_line_endings(mut self, enabled: bool) -> Self {
        self.options.response_decoder_options = self
            .options
            .response_decoder_options
            .accept_all_line_endings(enabled);

        self
    }

    /// Set maximum line length for response header lines and chunked body
    /// headers.
    ///
    /// The default limit is 4096 bytes.
    #[inline]
    pub const fn max_line_length(mut self, max_length: Option<usize>) -> Self {
        self.options.response_decoder_options = self
            .options
            .response_decoder_options
            .max_line_length(max_length);

        self
    }

    /// Set maximum header field length.
    ///
    /// The default limit is 4096 bytes.
    #[inline]
    pub const fn max_header_field_length(mut self, max_length: Option<usize>) -> Self {
        self.options.response_decoder_options = self
            .options
            .response_decoder_options
            .max_header_field_length(max_length);

        self
    }

    /// Set maximum number of lines for the response header.
    ///
    /// The default limit is 64.
    #[inline]
    pub const fn max_header_fields(mut self, max_fields: Option<usize>) -> Self {
        self.options.response_decoder_options = self
            .options
            .response_decoder_options
            .max_header_fields(max_fields);

        self
    }

    /// Set the maximum size of a response body.
    ///
    /// The default limit is 2 MiB.
    #[inline]
    pub const fn max_body_size(mut self, size: Option<usize>) -> Self {
        self.options.response_decoder_options =
            self.options.response_decoder_options.max_body_size(size);

        self
    }

    /// Set the request timeout duration.
    ///
    /// The default value is 60 seconds.
    #[inline]
    pub const fn request_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.options.request_timeout = timeout;
        self
    }

    /// Use a given RTSP connector.
    #[inline]
    pub fn connector<T>(self, connector: T) -> ClientBuilder<T> {
        ClientBuilder {
            connector,
            options: self.options,
        }
    }

    /// Build the RTSP client.
    #[inline]
    pub fn build(self) -> Client<C> {
        Client {
            connector: self.connector.into(),
            options: self.options,
        }
    }
}

impl Default for ClientBuilder {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

/// RTSP client options.
#[derive(Clone)]
struct ClientOptions {
    response_decoder_options: ResponseDecoderOptions,
    request_timeout: Option<Duration>,
}

impl ClientOptions {
    /// Create new client options with default values.
    #[inline]
    const fn new() -> Self {
        let response_decoder_options = ResponseDecoderOptions::new()
            .accept_all_line_endings(false)
            .max_line_length(Some(4096))
            .max_header_field_length(Some(4096))
            .max_header_fields(Some(64))
            .max_body_size(Some(2 << 20));

        Self {
            response_decoder_options,
            request_timeout: Some(Duration::from_secs(60)),
        }
    }
}

/// RTSP client.
pub struct Client<C = DefaultConnector> {
    connector: Arc<C>,
    options: ClientOptions,
}

impl Client {
    /// Create a new RTSP client with default options.
    #[inline]
    pub fn new() -> Self {
        Self {
            connector: Arc::new(DefaultConnector::new()),
            options: ClientOptions::new(),
        }
    }

    /// Get a client builder.
    #[inline]
    pub const fn builder() -> ClientBuilder {
        ClientBuilder::new()
    }
}

impl<C> Client<C> {
    /// Create a new RTSP session.
    #[inline]
    pub fn create_session(&self) -> SessionBuilder<NoAuthProvider, C> {
        let connector = self.connector.clone();
        let options = self.options.clone();

        SessionBuilder::new(connector, options)
    }
}

impl Default for Client {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}
