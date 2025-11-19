use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    str::FromStr,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::BytesMut;
use futures::{Sink, Stream};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};
use tokio_util::codec::{Decoder, Encoder, Framed};

use crate::{
    Error, Scheme,
    client::response::ResponseDecoder,
    connection::BaseRtspConnection,
    interleaved::InterleavedCodec,
    request::{Request, RequestHeaderEncoder},
    response::Response,
    udp::UdpChannel,
    url::Url,
};

pub use crate::connection::InterleavedChannel;

/// RTSP connector.
#[trait_variant::make(Send)]
pub trait Connector {
    type Connection: Connection;

    /// Connect to a network location specified by a given URL.
    async fn connect(&self, url: &Url) -> Result<Self::Connection, Error>;
}

impl<C> Connector for Arc<C>
where
    C: Connector + Sync + ?Sized,
{
    type Connection = C::Connection;

    #[inline]
    fn connect(&self, url: &Url) -> impl Future<Output = Result<Self::Connection, Error>> + Send {
        C::connect(self, url)
    }
}

/// Default RTSP connector.
#[derive(Default)]
pub struct DefaultConnector(());

impl DefaultConnector {
    /// Create a new default connector.
    #[inline]
    pub const fn new() -> Self {
        Self(())
    }
}

impl Connector for DefaultConnector {
    type Connection = TcpStream;

    async fn connect(&self, url: &Url) -> Result<Self::Connection, Error> {
        let scheme = url.scheme();
        let host = url.host();
        let port = url.port();

        let scheme = Scheme::from_str(scheme)
            .map_err(|_| Error::from_msg(format!("invalid RTSP URL scheme: {scheme}")))?;

        let stream = if port.is_some() {
            TcpStream::connect(url.netloc()).await?
        } else {
            TcpStream::connect((host, scheme.default_port())).await?
        };

        Ok(stream)
    }
}

/// RTSP connection.
pub trait Connection: AsyncRead + AsyncWrite {
    type Info: ConnectionInfo;

    /// Get the connection info.
    ///
    /// The method should return `Ok(None)` if the connection was made via a
    /// proxy and only interleaved data transport is available.
    fn info(&self) -> io::Result<Option<Self::Info>>;
}

impl Connection for TcpStream {
    type Info = DefaultConnectionInfo;

    fn info(&self) -> io::Result<Option<Self::Info>> {
        let local_addr = self.local_addr()?;
        let remote_addr = self.peer_addr()?;

        let res = DefaultConnectionInfo::new(local_addr, remote_addr);

        Ok(Some(res))
    }
}

/// Connection info.
pub trait ConnectionInfo {
    /// Get the local address.
    fn local_addr(&self) -> SocketAddr;

    /// Get the peer address.
    fn remote_addr(&self) -> SocketAddr;
}

/// Default connection info.
#[derive(Copy, Clone)]
pub struct DefaultConnectionInfo {
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
}

impl DefaultConnectionInfo {
    /// Create a new connection info.
    #[inline]
    pub const fn new(local_addr: SocketAddr, remote_addr: SocketAddr) -> Self {
        Self {
            local_addr,
            remote_addr,
        }
    }
}

impl ConnectionInfo for DefaultConnectionInfo {
    #[inline]
    fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    #[inline]
    fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }
}

pin_project_lite::pin_project! {
    /// RTSP channel.
    pub struct RtspChannel<I = DefaultConnectionInfo> {
        #[pin]
        inner: BaseRtspConnection<Response, Request, Error>,
        info: Option<I>,
    }
}

impl<I> RtspChannel<I> {
    /// Create a new RTSP channel from a given connection.
    pub fn new<T>(connection: T, response_decoder: ResponseDecoder) -> io::Result<Self>
    where
        T: Connection<Info = I> + Send + 'static,
    {
        let info = connection.info()?;

        let message_codec = ClientCodec::from(response_decoder);
        let interleaved_codec = InterleavedCodec::new(message_codec);
        let stream = Framed::new(connection, interleaved_codec);

        let res = Self {
            inner: BaseRtspConnection::new(stream),
            info,
        };

        Ok(res)
    }

    /// Get the connection info.
    pub fn info(&self) -> Option<&I> {
        self.info.as_ref()
    }

    /// Get an interleaved channel.
    pub fn get_interleaved_channel(
        &self,
        channel: Option<u8>,
    ) -> Result<InterleavedChannel, Error> {
        self.inner.get_interleaved_channel(channel)
    }
}

impl<I> RtspChannel<I>
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
        let remote_host = if let Some(host) = remote_host {
            host
        } else {
            self.info
                .as_ref()
                .ok_or_else(|| Error::from_static_msg("the peer address is not known"))?
                .remote_addr()
                .ip()
        };

        let remote_addr = SocketAddr::from((remote_host, remote_port));

        let local_addr = match remote_addr {
            SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, local_port)),
            SocketAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, local_port)),
        };

        UdpChannel::new(local_addr, remote_addr)
            .await
            .map_err(Error::from)
    }
}

impl<I> Stream for RtspChannel<I> {
    type Item = Result<Response, Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();

        this.inner.poll_next(cx)
    }
}

impl<I> Sink<Request> for RtspChannel<I> {
    type Error = Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        let this = self.project();

        this.inner.poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, request: Request) -> Result<(), Self::Error> {
        let this = self.project();

        this.inner.start_send(request)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.project();

        this.inner.poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.project();

        this.inner.poll_flush(cx)
    }
}

/// Client message stream codec.
struct ClientCodec {
    request_header_encoder: RequestHeaderEncoder,
    response_decoder: ResponseDecoder,
    output_buffer: BytesMut,
}

impl From<ResponseDecoder> for ClientCodec {
    fn from(decoder: ResponseDecoder) -> Self {
        Self {
            request_header_encoder: RequestHeaderEncoder::new(),
            response_decoder: decoder,
            output_buffer: BytesMut::new(),
        }
    }
}

impl Decoder for ClientCodec {
    type Item = Response;
    type Error = Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        self.response_decoder.decode(src)
    }

    fn decode_eof(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        self.response_decoder.decode_eof(src)
    }
}

impl Encoder<Request> for ClientCodec {
    type Error = Error;

    fn encode(&mut self, response: Request, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let (header, body) = response.deconstruct();

        self.request_header_encoder
            .encode(&header, &mut self.output_buffer);

        let header = self.output_buffer.split();

        let header_len = header.len();
        let body_len = body.len();

        dst.reserve(header_len + body_len);

        dst.extend_from_slice(&header);
        dst.extend_from_slice(&body);

        Ok(())
    }
}
