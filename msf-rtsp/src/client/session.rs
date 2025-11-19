use std::{net::IpAddr, sync::Arc, time::Duration};

use bytes::Bytes;
use futures::{SinkExt, StreamExt};

use crate::{
    Error, Method,
    client::{
        ClientOptions,
        auth::{AuthProvider, NoAuthProvider},
        connector::{
            Connection, ConnectionInfo, Connector, DefaultConnectionInfo, DefaultConnector,
            InterleavedChannel, RtspChannel,
        },
        request::OutgoingRequest,
        response::{IncomingResponse, ResponseDecoder},
    },
    request::{Request, RequestBuilder, RequestHeader},
    udp::UdpChannel,
    url::{IntoUrl, Url},
};

/// RTSP session builder.
pub struct SessionBuilder<A = NoAuthProvider, C = DefaultConnector> {
    connector: Arc<C>,
    options: ClientOptions,
    auth: A,
}

impl<C> SessionBuilder<NoAuthProvider, C> {
    /// Create a new session builder.
    #[inline]
    pub(super) const fn new(connector: Arc<C>, options: ClientOptions) -> Self {
        Self {
            connector,
            options,
            auth: NoAuthProvider::new(),
        }
    }
}

impl<A, C> SessionBuilder<A, C> {
    /// Use a given authentication provider.
    pub fn auth_provider<T>(self, auth: T) -> SessionBuilder<T, C>
    where
        A: AuthProvider,
    {
        SessionBuilder {
            connector: self.connector,
            options: self.options,
            auth,
        }
    }

    /// Build the RTSP session.
    pub fn build<T>(
        self,
        base_url: T,
    ) -> Result<Session<A, C, <C::Connection as Connection>::Info>, Error>
    where
        C: Connector,
        T: IntoUrl,
    {
        let base_url = base_url
            .into_url()
            .map_err(|_| Error::from_static_msg("invalid URL"))?;

        let res = Session {
            connector: self.connector,
            options: self.options,
            base_url,
            connection: None,
            auth: self.auth,
            cseq: 1,
        };

        Ok(res)
    }
}

/// RTSP session.
pub struct Session<A = NoAuthProvider, C = DefaultConnector, I = DefaultConnectionInfo> {
    connector: Arc<C>,
    options: ClientOptions,
    base_url: Url,
    connection: Option<RtspChannel<I>>,
    auth: A,
    cseq: u64,
}

impl<A, C, I> Session<A, C, I> {
    /// Create a new RTSP request.
    pub fn request<U>(
        &mut self,
        method: Method,
        url: U,
    ) -> Result<OutgoingRequest<'_, A, C, I>, Error>
    where
        U: IntoUrl,
    {
        let url = url
            .into_url()
            .map_err(|_| Error::from_static_msg("invalid URL"))?
            .with_fragment(None)
            .expect("unable to strip fragment from URL");

        Ok(OutgoingRequest::new(self, method, url))
    }

    /// Create a new OPTIONS request.
    pub fn options<U>(&mut self, url: U) -> Result<OutgoingRequest<'_, A, C, I>, Error>
    where
        U: IntoUrl,
    {
        self.request(Method::Options, url)
    }

    /// Create a new DESCRIBE request.
    pub fn describe<U>(&mut self, url: U) -> Result<OutgoingRequest<'_, A, C, I>, Error>
    where
        U: IntoUrl,
    {
        self.request(Method::Describe, url)
    }

    /// Create a new SETUP request.
    pub fn setup<U>(&mut self, url: U) -> Result<OutgoingRequest<'_, A, C, I>, Error>
    where
        U: IntoUrl,
    {
        self.request(Method::Setup, url)
    }

    /// Create a new PLAY request.
    pub fn play<U>(&mut self, url: U) -> Result<OutgoingRequest<'_, A, C, I>, Error>
    where
        U: IntoUrl,
    {
        self.request(Method::Play, url)
    }

    /// Create a new GET_PARAMETER request.
    pub fn get_parameter<U>(&mut self, url: U) -> Result<OutgoingRequest<'_, A, C, I>, Error>
    where
        U: IntoUrl,
    {
        self.request(Method::GetParameter, url)
    }

    /// Create a new SET_PARAMETER request.
    pub fn set_parameter<U>(&mut self, url: U) -> Result<OutgoingRequest<'_, A, C, I>, Error>
    where
        U: IntoUrl,
    {
        self.request(Method::SetParameter, url)
    }

    /// Create a new TEARDOWN request.
    pub fn teardown<U>(&mut self, url: U) -> Result<OutgoingRequest<'_, A, C, I>, Error>
    where
        U: IntoUrl,
    {
        self.request(Method::Teardown, url)
    }

    /// Get the underlying connection info.
    ///
    /// The method returns `None` if the session is not connected to the remote
    /// peer or if the connection info is not available (e.g. when connected
    /// via a proxy).
    #[inline]
    pub fn connection_info(&self) -> Option<&I> {
        self.connection.as_ref().and_then(|conn| conn.info())
    }

    /// Get an interleaved channel.
    pub fn get_interleaved_channel(
        &self,
        channel: Option<u8>,
    ) -> Result<InterleavedChannel, Error> {
        self.connection
            .as_ref()
            .ok_or_else(|| Error::from_static_msg("not connected"))?
            .get_interleaved_channel(channel)
    }

    /// Keep reading data from the underlying connection until it gets closed.
    ///
    /// This method must be called if the interleaved data transports are being
    /// used. Calling this method will keep the data flowing.
    pub async fn join(&mut self) -> Result<(), Error> {
        if let Some(connection) = self.connection.as_mut() {
            while let Some(item) = connection.next().await {
                item?;
            }
        }

        Ok(())
    }
}

impl<A, C, I> Session<A, C, I>
where
    I: ConnectionInfo,
{
    /// Create a new UDP channel to the remote peer.
    ///
    /// # Arguments
    /// * `local_port` - local UDP port
    /// * `remote_port` - remote UDP port
    /// * `remote_host` - remote host (it can be used to override the peer
    ///   address)
    pub async fn get_udp_channel(
        &self,
        local_port: u16,
        remote_port: u16,
        remote_host: Option<IpAddr>,
    ) -> Result<UdpChannel, Error> {
        self.connection
            .as_ref()
            .ok_or_else(|| Error::from_static_msg("not connected"))?
            .get_udp_channel(local_port, remote_port, remote_host)
            .await
    }
}

impl<A, C, I> Session<A, C, I>
where
    C: Connector,
    C::Connection: Connection<Info = I> + Send + 'static,
{
    /// Get a connection to the remote peer.
    async fn connect(&mut self) -> Result<RtspChannel<I>, Error> {
        if let Some(connection) = self.connection.take() {
            return Ok(connection);
        }

        self.cseq = 1;

        let transport = self.connector.connect(&self.base_url).await?;

        let decoder = ResponseDecoder::new(self.options.response_decoder_options);

        let connection = RtspChannel::new(transport, decoder)?;

        Ok(connection)
    }
}

impl<A, C, I> Session<A, C, I>
where
    C: Connector,
    C::Connection: Connection<Info = I> + Send + 'static,
    A: AuthProvider,
{
    /// Send a given RTSP request.
    pub(crate) async fn send_request(
        &mut self,
        request: Request,
        timeout: Option<Duration>,
    ) -> Result<IncomingResponse, Error> {
        let (header, body) = request.deconstruct();

        let timeout = timeout.or(self.options.request_timeout);

        self.auth.reset();

        loop {
            let header = header.clone();
            let body = body.clone();

            let send = self.try_send_request(header, body);

            let response = if let Some(timeout) = timeout {
                tokio::time::timeout(timeout, send)
                    .await
                    .map_err(|_| Error::from_static_msg("request timeout"))??
            } else {
                send.await?
            };

            if let Some(response) = response {
                return Ok(response);
            }
        }
    }

    /// Try to send a given RTSP request.
    async fn try_send_request(
        &mut self,
        header: RequestHeader,
        body: Bytes,
    ) -> Result<Option<IncomingResponse>, Error> {
        let mut connection = self.connect().await?;

        let request = RequestBuilder::from(header.clone())
            .set_header_field(("CSeq", self.cseq))
            .body(body.clone());

        self.cseq = self.cseq.wrapping_add(1);

        let request = self.auth.authorize_request(request)?;

        connection.send(request).await?;

        let response = connection
            .next()
            .await
            .ok_or_else(|| Error::from_static_msg("connection lost"))?
            .map_err(|err| {
                Error::from_static_msg_and_cause("unable to read an RTSP response", err)
            })?;

        let connection_header = response
            .get_header_field_value("connection")
            .map(|val| val.as_ref());

        // do not reuse the connection if the server intends to close it
        if connection_header != Some(b"close") {
            self.connection = Some(connection);
        }

        let response = self
            .auth
            .process_response(response)?
            .map(IncomingResponse::new);

        Ok(response)
    }
}
