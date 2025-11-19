use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use bytes::{Bytes, BytesMut};
use futures::{Sink, SinkExt, Stream, StreamExt, TryStreamExt, ready};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream},
};
use tokio_util::codec::{Decoder, Encoder, Framed};

use crate::{
    Error,
    connection::{BaseRtspConnection, BaseRtspConnectionHandle},
    interleaved::InterleavedCodec,
    request::Request,
    response::ResponseHeaderEncoder,
    rtp::{
        InvalidInput, OrderedRtpPacket, RtpChannel, RtpPacket,
        rtcp::{RtcpChannel, RtcpHandler, RtcpHandlerOptions},
        transceiver::{DefaultRtpTransceiver, RtpTransceiverOptions},
    },
    server::{
        request::{IncomingRequest, RequestDecoder},
        response::OutgoingResponse,
    },
    udp::UdpChannel,
};

pub use crate::connection::InterleavedChannel;

/// Server connection acceptor.
#[trait_variant::make(Send)]
pub trait Acceptor {
    type Connection: Connection;

    /// Accept a new connection.
    async fn accept(&mut self) -> io::Result<Self::Connection>;
}

impl Acceptor for TcpListener {
    type Connection = TcpStream;

    async fn accept(&mut self) -> io::Result<Self::Connection> {
        let (stream, _) = TcpListener::accept(self).await?;

        Ok(stream)
    }
}

/// Server connection.
pub trait Connection: AsyncRead + AsyncWrite {
    type Info: ConnectionInfo;

    /// Get connection info.
    fn info(&self) -> io::Result<Self::Info>;
}

impl Connection for TcpStream {
    type Info = DefaultConnectionInfo;

    fn info(&self) -> io::Result<Self::Info> {
        let local_addr = self.local_addr()?;
        let remote_addr = self.peer_addr()?;

        let res = DefaultConnectionInfo::new(local_addr, remote_addr);

        Ok(res)
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

/// RTSP server connection.
pub struct InternalConnection<I> {
    inner: BaseRtspConnection<Request, OutgoingResponse, Error>,
    info: Arc<I>,
}

impl<I> InternalConnection<I> {
    /// Create a new server connection.
    pub fn new<C>(connection: C, info: I, request_decoder: RequestDecoder) -> Self
    where
        C: AsyncRead + AsyncWrite + Send + 'static,
    {
        let message_codec = ServerCodec::from(request_decoder);
        let interleaved_codec = InterleavedCodec::new(message_codec);
        let stream = Framed::new(connection, interleaved_codec);

        Self {
            inner: BaseRtspConnection::new(stream),
            info: Arc::new(info),
        }
    }

    /// Get the connection handle.
    pub fn handle(&self) -> ConnectionHandle<I> {
        ConnectionHandle {
            inner: self.inner.handle(),
            info: self.info.clone(),
        }
    }
}

impl<I> Stream for InternalConnection<I> {
    type Item = Result<IncomingRequest<I>, Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let ready = ready!(self.inner.poll_next_unpin(cx));

        if let Some(request) = ready.transpose()? {
            let connection = self.handle();

            let request = IncomingRequest::new(request, connection)?;

            Poll::Ready(Some(Ok(request)))
        } else {
            Poll::Ready(None)
        }
    }
}

impl<I> Sink<OutgoingResponse> for InternalConnection<I> {
    type Error = Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready_unpin(cx)
    }

    fn start_send(mut self: Pin<&mut Self>, response: OutgoingResponse) -> Result<(), Self::Error> {
        self.inner.start_send_unpin(response)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_flush_unpin(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_close_unpin(cx)
    }
}

/// Connection handle.
#[derive(Clone)]
pub struct ConnectionHandle<I = DefaultConnectionInfo> {
    inner: BaseRtspConnectionHandle<Request, Error>,
    info: Arc<I>,
}

impl<I> ConnectionHandle<I> {
    /// Get the connection info.
    #[inline]
    pub fn info(&self) -> &I {
        &self.info
    }
}

impl<I> ConnectionHandle<I>
where
    I: ConnectionInfo,
{
    /// Get the local address.
    #[inline]
    pub fn local_addr(&self) -> SocketAddr {
        self.info.local_addr()
    }

    /// Get the remote address.
    #[inline]
    pub fn remote_addr(&self) -> SocketAddr {
        self.info.remote_addr()
    }
}

impl<I> ConnectionHandle<I>
where
    I: ConnectionInfo,
{
    /// Get an interleaved channel.
    pub fn get_interleaved_channel(
        &self,
        channel: Option<u8>,
    ) -> Result<InterleavedChannel, Error> {
        self.inner.get_interleaved_channel(channel)
    }

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
        let peer = self.info.remote_addr();

        let remote_host = remote_host.unwrap_or(peer.ip());

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

/// RTP sink that also handles the related RTCP communication automatically.
///
/// Note that the sink also implements the `Stream` trait. The user should poll
/// the stream even if no incoming RTP packets are expected in order to avoid
/// clogging the incoming RTP channel. Decoding errors of the incoming RTP
/// packets are always ignored.
pub struct RtpTransport {
    inner: Pin<Box<dyn StreamSink<OrderedRtpPacket, RtpPacket, Error> + Send>>,
}

impl RtpTransport {
    /// Create a new RTP sink.
    pub fn new<S, T, E>(
        ssrc: u32,
        rtp_clock_rate: u32,
        rtp_channel: S,
        rtcp_channel: T,
        ignore_decoding_errors: bool,
    ) -> Self
    where
        S: Send + 'static,
        T: Send + 'static,
        E: Send + 'static,
        S: Stream<Item = Result<Bytes, E>>,
        S: Sink<Bytes>,
        T: Stream<Item = Result<Bytes, E>>,
        T: Sink<Bytes>,
        Error: From<E>,
        Error: From<S::Error>,
        Error: From<T::Error>,
    {
        let rtp_channel = rtp_channel.map_err(RtpStreamError::Other);
        let rtcp_channel = rtcp_channel.map_err(RtcpStreamError::Other);

        let rtp = RtpChannel::new(rtp_channel, true);

        let options = RtpTransceiverOptions::new()
            .with_primary_sender_ssrc(ssrc)
            .with_default_clock_rate(rtp_clock_rate)
            .with_output_ssrcs([(ssrc, rtp_clock_rate)]);

        let rtp = DefaultRtpTransceiver::new(rtp, options);

        let rtcp = RtcpChannel::new(rtcp_channel, ignore_decoding_errors);

        // NOTE: We expect only one-to-one RTP sessions, so setting the RTCP
        //   report interval to 5 seconds should be OK.
        let options = RtcpHandlerOptions::new()
            .with_ignore_decoding_errors(true)
            .with_rtcp_report_interval(Duration::from_secs(5));

        let handler = RtcpHandler::new(rtp, rtcp, options)
            .map_err(Error::from)
            .sink_map_err(Error::from);

        Self {
            inner: Box::pin(handler),
        }
    }
}

impl Stream for RtpTransport {
    type Item = Result<OrderedRtpPacket, Error>;

    #[inline]
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.inner.poll_next_unpin(cx)
    }
}

impl Sink<RtpPacket> for RtpTransport {
    type Error = Error;

    #[inline]
    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready_unpin(cx)
    }

    #[inline]
    fn start_send(mut self: Pin<&mut Self>, item: RtpPacket) -> Result<(), Self::Error> {
        self.inner.start_send_unpin(item)
    }

    #[inline]
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_flush_unpin(cx)
    }

    #[inline]
    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_close_unpin(cx)
    }
}

/// Server message stream codec.
struct ServerCodec {
    request_decoder: RequestDecoder,
    response_header_encoder: ResponseHeaderEncoder,
    output_buffer: BytesMut,
}

impl From<RequestDecoder> for ServerCodec {
    fn from(decoder: RequestDecoder) -> Self {
        Self {
            request_decoder: decoder,
            response_header_encoder: ResponseHeaderEncoder::new(),
            output_buffer: BytesMut::new(),
        }
    }
}

impl Decoder for ServerCodec {
    type Item = Request;
    type Error = Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        self.request_decoder.decode(src)
    }

    fn decode_eof(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        self.request_decoder.decode_eof(src)
    }
}

impl Encoder<OutgoingResponse> for ServerCodec {
    type Error = Error;

    fn encode(
        &mut self,
        response: OutgoingResponse,
        dst: &mut BytesMut,
    ) -> Result<(), Self::Error> {
        let (header, body) = response.deconstruct();

        self.response_header_encoder
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

/// Helper enum.
enum RtpStreamError<E> {
    InvalidInput,
    Other(E),
}

impl<E> From<InvalidInput> for RtpStreamError<E> {
    fn from(_: InvalidInput) -> Self {
        Self::InvalidInput
    }
}

impl<E> From<RtpStreamError<E>> for Error
where
    Error: From<E>,
{
    fn from(err: RtpStreamError<E>) -> Self {
        match err {
            RtpStreamError::InvalidInput => Error::from_static_msg("invalid RTP packet"),
            RtpStreamError::Other(err) => Error::from(err),
        }
    }
}

/// Helper enum.
enum RtcpStreamError<E> {
    InvalidInput,
    Other(E),
}

impl<E> From<InvalidInput> for RtcpStreamError<E> {
    fn from(_: InvalidInput) -> Self {
        Self::InvalidInput
    }
}

impl<E> From<RtcpStreamError<E>> for Error
where
    Error: From<E>,
{
    fn from(err: RtcpStreamError<E>) -> Self {
        match err {
            RtcpStreamError::InvalidInput => Error::from_static_msg("invalid RTCP packet"),
            RtcpStreamError::Other(err) => Error::from(err),
        }
    }
}

/// Helper trait.
trait StreamSink<I, O, E>: Stream<Item = Result<I, E>> + Sink<O, Error = E> {}

impl<T, I, O, E> StreamSink<I, O, E> for T
where
    T: Stream<Item = Result<I, E>>,
    T: Sink<O, Error = E>,
{
}
