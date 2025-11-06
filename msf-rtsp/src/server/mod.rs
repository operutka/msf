//! RTSP server and related types.

mod connection;

pub mod error;
pub mod request;
pub mod response;

use std::{
    borrow::Cow,
    marker::PhantomData,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use futures::{Sink, SinkExt, Stream, StreamExt, TryStreamExt};
use tokio::{net::TcpListener, sync::Semaphore};

use self::{
    connection::InternalConnection,
    request::{RequestDecoder, RequestDecoderOptions},
    response::Status,
};

use crate::{Error, Version, header::ValueListDisplay};

pub use self::{
    connection::{
        Acceptor, Connection, ConnectionHandle, ConnectionInfo, DefaultConnectionInfo,
        InterleavedChannel, RtpTransport,
    },
    request::IncomingRequest,
    response::{OutgoingResponse, OutgoingResponseBuilder},
};

/// RTSP connection handler.
///
/// This is a low-level trait for handling RTSP connections. It can be used to
/// wrap the default connection handling logic with custom behavior, such as
/// logging or metrics collection.
pub trait ConnectionHandler {
    type Connection: Connection<Info = Self::ConnectionInfo>;
    type ConnectionInfo: ConnectionInfo;
    type RtspChannel: RtspChannel<<Self::Connection as Connection>::Info>;

    /// Handle a given connection.
    fn handle_connection(
        &self,
        connection: Self::Connection,
    ) -> impl Future<Output = Result<(), Error>> + Send + 'static {
        let res = connection
            .info()
            .map(|info| self.create_rtsp_channel(connection, info))
            .map(|channel| self.handle_rtsp_channel(channel));

        async move { res?.await }
    }

    /// Create a new RTSP channel from a given connection.
    fn create_rtsp_channel(
        &self,
        connection: Self::Connection,
        connection_info: Self::ConnectionInfo,
    ) -> Self::RtspChannel;

    /// Handle a given RTSP channel.
    fn handle_rtsp_channel(
        &self,
        channel: Self::RtspChannel,
    ) -> impl Future<Output = Result<(), Error>> + Send + 'static;
}

/// RTSP channel.
///
/// It's a stream-sink combination for incoming RTSP requests and outgoing RTSP
/// responses. It's a low-level trait for handling RTSP connections. It can be
/// used to wrap the default RTSP channel with custom behavior, such as logging
/// or metrics collection.
pub trait RtspChannel<I>:
    Stream<Item = Result<IncomingRequest<I>, Error>> + Sink<OutgoingResponse, Error = Error>
{
}

impl<T, I> RtspChannel<I> for T
where
    T: Stream<Item = Result<IncomingRequest<I>, Error>>,
    T: Sink<OutgoingResponse, Error = Error>,
{
}

/// RTSP request handler.
#[trait_variant::make(Send)]
pub trait RequestHandler<I = DefaultConnectionInfo> {
    /// Handle a given request and return a response or an error.
    async fn try_handle_request(
        self,
        request: IncomingRequest<I>,
    ) -> Result<OutgoingResponse, Error>;

    /// Handle a given request and return a response.
    fn handle_request(
        self,
        request: IncomingRequest<I>,
    ) -> impl Future<Output = OutgoingResponse> + Send
    where
        Self: Sized,
        I: Send + Sync,
    {
        async move {
            self.try_handle_request(request)
                .await
                .unwrap_or_else(|err| {
                    err.to_response()
                        .unwrap_or_else(|| response::empty_response(Status::INTERNAL_SERVER_ERROR))
                })
        }
    }
}

/// Builder for the RTSP server.
pub struct RtspServerBuilder {
    options: ServerOptions,
}

impl RtspServerBuilder {
    /// Create a new builder.
    #[inline]
    pub const fn new() -> Self {
        Self {
            options: ServerOptions::new(),
        }
    }

    /// Set read timeout for client connections.
    ///
    /// The default value is 60 seconds.
    #[inline]
    pub const fn read_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.options.read_timeout = timeout;
        self
    }

    /// Set write timeout for client connections.
    ///
    /// The default value is 60 seconds.
    #[inline]
    pub const fn write_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.options.write_timeout = timeout;
        self
    }

    /// Enable or disable acceptance of all line endings (CR, LF, CRLF).
    ///
    /// The default is disabled.
    #[inline]
    pub const fn accept_all_line_endings(mut self, enabled: bool) -> Self {
        self.options.request_decoder_options = self
            .options
            .request_decoder_options
            .accept_all_line_endings(enabled);

        self
    }

    /// Set maximum line length for request header lines and chunked body
    /// headers.
    ///
    /// The default value is 4096 bytes.
    #[inline]
    pub const fn max_line_length(mut self, max_length: Option<usize>) -> Self {
        self.options.request_decoder_options = self
            .options
            .request_decoder_options
            .max_line_length(max_length);

        self
    }

    /// Set maximum header field length.
    ///
    /// The default value is 4096 bytes.
    #[inline]
    pub const fn max_header_field_length(mut self, max_length: Option<usize>) -> Self {
        self.options.request_decoder_options = self
            .options
            .request_decoder_options
            .max_header_field_length(max_length);

        self
    }

    /// Set maximum number of lines for the request header.
    ///
    /// The default value is 64.
    #[inline]
    pub const fn max_header_fields(mut self, max_fields: Option<usize>) -> Self {
        self.options.request_decoder_options = self
            .options
            .request_decoder_options
            .max_header_fields(max_fields);

        self
    }

    /// Set the maximum size of a request body.
    ///
    /// The default value is 2 MiB.
    #[inline]
    pub const fn max_body_size(mut self, size: Option<usize>) -> Self {
        self.options.request_decoder_options =
            self.options.request_decoder_options.max_body_size(size);

        self
    }

    /// Set the maximum number of concurrent client connections.
    ///
    /// The default value is 100.
    #[inline]
    pub fn max_connections(mut self, max: Option<u32>) -> Self {
        self.options.max_connections = max;
        self
    }

    /// Set the maximum number of in-progress requests per connection.
    ///
    /// The default value is 10.
    #[inline]
    pub fn request_pipeline_depth(mut self, depth: usize) -> Self {
        self.options.request_pipeline_depth = depth;
        self
    }

    /// Enable RTSP/1.0.
    ///
    /// The default is enabled.
    #[inline]
    pub fn enable_rtsp_10(mut self, enabled: bool) -> Self {
        self.options.rtsp_10_enabled = enabled;
        self
    }

    /// Enable RTSP/2.0.
    ///
    /// The default is disabled.
    #[inline]
    pub fn enable_rtsp_20(mut self, enabled: bool) -> Self {
        self.options.rtsp_20_enabled = enabled;
        self
    }

    /// Add a given server feature.
    pub fn server_feature<T>(mut self, feature: T) -> Self
    where
        T: Into<Cow<'static, str>>,
    {
        let feature = feature.into();

        self.options.supported_features.retain(|f| f != &feature);
        self.options.supported_features.push(feature);
        self
    }

    /// Build the RTSP server.
    pub fn build<A>(mut self, acceptor: A) -> RtspServer<A> {
        if self.options.rtsp_20_enabled {
            self = self.server_feature("play.basic");
        }

        RtspServer {
            acceptor,
            options: self.options.into(),
        }
    }
}

impl Default for RtspServerBuilder {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

/// Helper type.
struct ServerOptions {
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
    rtsp_10_enabled: bool,
    rtsp_20_enabled: bool,
    supported_features: Vec<Cow<'static, str>>,
    request_decoder_options: RequestDecoderOptions,
    max_connections: Option<u32>,
    request_pipeline_depth: usize,
}

impl ServerOptions {
    /// Create new server options with default values.
    #[inline]
    const fn new() -> Self {
        let request_decoder_options = RequestDecoderOptions::new()
            .accept_all_line_endings(false)
            .max_line_length(Some(4096))
            .max_header_field_length(Some(4096))
            .max_header_fields(Some(64))
            .max_body_size(Some(2 * 1024 * 1024));

        Self {
            read_timeout: Some(Duration::from_secs(60)),
            write_timeout: Some(Duration::from_secs(60)),
            rtsp_10_enabled: true,
            rtsp_20_enabled: false,
            supported_features: Vec::new(),
            request_decoder_options,
            max_connections: Some(100),
            request_pipeline_depth: 10,
        }
    }
}

/// RTSP server.
pub struct RtspServer<A = TcpListener> {
    acceptor: A,
    options: Arc<ServerOptions>,
}

impl RtspServer<()> {
    /// Get an RTSP server builder.
    #[inline]
    pub const fn builder() -> RtspServerBuilder {
        RtspServerBuilder::new()
    }
}

impl<A, C, I> RtspServer<A>
where
    A: Acceptor<Connection = C> + 'static,
    C: Connection<Info = I> + Send + 'static,
    I: ConnectionInfo + Send + Sync + 'static,
{
    /// Start serving requests.
    pub async fn serve<T>(self, request_handler: T) -> Result<(), Error>
    where
        T: RequestHandler<I> + Clone + 'static,
    {
        self.serve_with_connection_handler(request_handler, |base| base)
            .await
    }

    /// Start serving requests with a custom connection handler.
    pub async fn serve_with_connection_handler<T, F, U>(
        mut self,
        request_handler: T,
        make_connection_handler: F,
    ) -> Result<(), Error>
    where
        T: RequestHandler<I>,
        F: FnOnce(DefaultConnectionHandler<C, I, T>) -> U,
        U: ConnectionHandler<Connection = C>,
    {
        let base_handler = DefaultConnectionHandler::new(request_handler, self.options.clone());

        let connection_handler = (make_connection_handler)(base_handler);

        let semaphore = self
            .options
            .max_connections
            .map(usize::try_from)
            .map(|res| res.unwrap_or(usize::MAX))
            .map(|max| Arc::new(Semaphore::new(max)));

        loop {
            let permit = if let Some(semaphore) = semaphore.clone() {
                Some(semaphore.acquire_owned().await.unwrap())
            } else {
                None
            };

            let connection = self.acceptor.accept().await?;

            let session = connection_handler.handle_connection(connection);

            tokio::spawn(async move {
                // We ignore any errors here. It's the connection handler's
                // responsibility to handle them appropriately.
                let _ = session.await;

                std::mem::drop(permit);
            });
        }
    }
}

/// Default RTSP connection handler.
pub struct DefaultConnectionHandler<C, I, T> {
    options: Arc<ServerOptions>,
    request_handler: InternalRequestHandler<T, I>,
    _connection: std::marker::PhantomData<C>,
}

impl<C, I, T> DefaultConnectionHandler<C, I, T> {
    /// Create a new RTSP connection handler.
    fn new(request_handler: T, options: Arc<ServerOptions>) -> Self {
        Self {
            options: options.clone(),
            request_handler: InternalRequestHandler::new(request_handler, options),
            _connection: std::marker::PhantomData,
        }
    }
}

impl<C, I, T> ConnectionHandler for DefaultConnectionHandler<C, I, T>
where
    C: Connection<Info = I> + Send + 'static,
    I: ConnectionInfo + Send + Sync + 'static,
    T: RequestHandler<I> + Clone + 'static,
{
    type Connection = C;
    type ConnectionInfo = I;
    type RtspChannel = DefaultRtspChannel<I>;

    fn create_rtsp_channel(
        &self,
        connection: Self::Connection,
        connection_info: Self::ConnectionInfo,
    ) -> Self::RtspChannel {
        let connection = ttpkit_utils::io::Connection::builder()
            .read_timeout(self.options.read_timeout)
            .write_timeout(self.options.write_timeout)
            .build(connection);

        let request_decoder = RequestDecoder::new(self.options.request_decoder_options);
        let connection = InternalConnection::new(connection, connection_info, request_decoder);

        DefaultRtspChannel { connection }
    }

    fn handle_rtsp_channel(
        &self,
        channel: Self::RtspChannel,
    ) -> impl Future<Output = Result<(), Error>> + Send + 'static {
        let request_handler = self.request_handler.clone();

        let (mut tx, rx) = channel.split();

        let mut responses = rx
            .map_ok(move |request| {
                let request_handler = request_handler.clone();
                let future = request_handler.handle_request(request);

                async move { Ok(future.await) }
            })
            .try_buffered(self.options.request_pipeline_depth);

        async move {
            while let Some(item) = responses.next().await {
                let response = item.or_else(|err| {
                    if let Some(response) = err.to_response() {
                        Ok(response)
                    } else {
                        Err(err)
                    }
                })?;

                tx.send(response).await?;
            }

            Ok(())
        }
    }
}

/// Default RTSP channel.
pub struct DefaultRtspChannel<I> {
    connection: InternalConnection<I>,
}

impl<I> Stream for DefaultRtspChannel<I> {
    type Item = Result<IncomingRequest<I>, Error>;

    #[inline]
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.connection.poll_next_unpin(cx)
    }
}

impl<I> Sink<OutgoingResponse> for DefaultRtspChannel<I> {
    type Error = Error;

    #[inline]
    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.connection.poll_ready_unpin(cx)
    }

    #[inline]
    fn start_send(mut self: Pin<&mut Self>, response: OutgoingResponse) -> Result<(), Self::Error> {
        self.connection.start_send_unpin(response)
    }

    #[inline]
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.connection.poll_flush_unpin(cx)
    }

    #[inline]
    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.connection.poll_close_unpin(cx)
    }
}

/// Internal RTSP request handler.
struct InternalRequestHandler<T, I> {
    inner: T,
    options: Arc<ServerOptions>,
    _info: PhantomData<I>,
}

impl<T, I> InternalRequestHandler<T, I> {
    /// Create a new internal request handler.
    fn new(inner: T, options: Arc<ServerOptions>) -> Self {
        Self {
            inner,
            options,
            _info: PhantomData,
        }
    }
}

impl<T, I> InternalRequestHandler<T, I>
where
    T: RequestHandler<I> + Clone,
    I: Send + Sync,
{
    /// Handle a given request.
    async fn handle_request(self, request: IncomingRequest<I>) -> OutgoingResponse {
        let options = self.options.clone();

        let timestamp = request.get_header_field_value("Timestamp").cloned();

        let version = request.version();

        // NOTE: The Supported header is specific for RTSP/2.0. We need to
        //   ignore it if the request protocol is RTSP/1.0.
        let has_supported_header = request
            .get_header_field_value("Supported")
            .filter(|_| version == Version::Version20)
            .is_some();

        let mut response = if let Some(cseq) = request.get_header_field_value("CSeq") {
            let cseq = cseq.clone();

            self.handle_request_inner(request)
                .await
                .set_header_field(("CSeq", cseq))
        } else {
            OutgoingResponse::builder()
                .set_status(Status::BAD_REQUEST)
                .add_header_field(("Content-Type", "text/plain"))
                .set_body("missing CSeq header")
        };

        response = response.set_version(version);

        if let Some(t) = timestamp {
            response = response.set_header_field(("Timestamp", t));
        }

        if has_supported_header {
            response = response.set_header_field((
                "Supported",
                ValueListDisplay::new(", ", &options.supported_features),
            ));
        }

        response.build()
    }

    /// Handle a given request (inner part).
    async fn handle_request_inner(self, request: IncomingRequest<I>) -> OutgoingResponseBuilder {
        match request.version() {
            Version::Version10 if self.options.rtsp_10_enabled => (),
            Version::Version20 if self.options.rtsp_20_enabled => (),
            _ => {
                return OutgoingResponseBuilder::new_with_status(
                    Status::RTSP_VERSION_NOT_SUPPORTED,
                );
            }
        }

        let unsupported = request
            .get_header_field_value("Require")
            .map(|v| v.as_ref())
            .unwrap_or(b"")
            .split(|&b| b == b',')
            .map(|feature| feature.trim_ascii())
            .filter(|feature| !feature.is_empty())
            .map(String::from_utf8_lossy)
            .filter(|feature| {
                !self
                    .options
                    .supported_features
                    .contains(&Cow::Borrowed(feature))
            })
            .collect::<Vec<_>>();

        if unsupported.is_empty() {
            self.inner.handle_request(request).await.into()
        } else {
            OutgoingResponse::builder()
                .set_status(Status::OPTION_NOT_SUPPORTED)
                .add_header_field(("Unsupported", ValueListDisplay::new(", ", &unsupported)))
        }
    }
}

impl<T, I> Clone for InternalRequestHandler<T, I>
where
    T: Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            options: self.options.clone(),
            _info: PhantomData,
        }
    }
}
