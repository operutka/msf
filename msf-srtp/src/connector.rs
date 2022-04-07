use std::{
    future::Future,
    io::{self, Read, Write},
    pin::Pin,
    ptr,
    task::{Context, Poll},
};

use bytes::{Bytes, BytesMut};
use futures::{ready, Sink, SinkExt, Stream, StreamExt};
use msf_rtp::{CompoundRtcpPacket, PacketMux, RtcpPacketType, RtpPacket};
use openssl::ssl::{HandshakeError, Ssl, SslStream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{
    session::{DecodingError, SrtpSession},
    Error, InternalError,
};

/// Helper struct.
pub struct Connector {
    inner: Ssl,
}

impl Connector {
    /// Create a new SRTP connector.
    pub fn new(ssl: Ssl) -> Self {
        Self { inner: ssl }
    }

    /// Perform a "connect" DTLS handshake.
    pub async fn connect_srtp<S>(self, mut stream: S) -> Result<SrtpStream<S>, Error>
    where
        S: Stream<Item = io::Result<Bytes>> + Sink<Bytes, Error = io::Error> + Unpin,
    {
        let session = self.connect(&mut stream).await?;

        Ok(SrtpStream::new(session, stream))
    }

    /// Perform a "connect" DTLS handshake.
    pub async fn connect_srtcp<S>(self, mut stream: S) -> Result<SrtcpStream<S>, Error>
    where
        S: Stream<Item = io::Result<Bytes>> + Sink<Bytes, Error = io::Error> + Unpin,
    {
        let session = self.connect(&mut stream).await?;

        Ok(SrtcpStream::new(session, stream))
    }

    /// Perform a "connect" DTLS handshake.
    pub async fn connect_muxed<S>(self, mut stream: S) -> Result<MuxedSrtpStream<S>, Error>
    where
        S: Stream<Item = io::Result<Bytes>> + Sink<Bytes, Error = io::Error> + Unpin,
    {
        let session = self.connect(&mut stream).await?;

        Ok(MuxedSrtpStream::new(session, stream))
    }

    /// Perform an "accept" DTLS handshake.
    pub async fn accept_srtp<S>(self, mut stream: S) -> Result<SrtpStream<S>, Error>
    where
        S: Stream<Item = io::Result<Bytes>> + Sink<Bytes, Error = io::Error> + Unpin,
    {
        let session = self.accept(&mut stream).await?;

        Ok(SrtpStream::new(session, stream))
    }

    /// Perform an "accept" DTLS handshake.
    pub async fn accept_srtcp<S>(self, mut stream: S) -> Result<SrtcpStream<S>, Error>
    where
        S: Stream<Item = io::Result<Bytes>> + Sink<Bytes, Error = io::Error> + Unpin,
    {
        let session = self.accept(&mut stream).await?;

        Ok(SrtcpStream::new(session, stream))
    }

    /// Perform an "accept" DTLS handshake.
    pub async fn accept_muxed<S>(self, mut stream: S) -> Result<MuxedSrtpStream<S>, Error>
    where
        S: Stream<Item = io::Result<Bytes>> + Sink<Bytes, Error = io::Error> + Unpin,
    {
        let session = self.accept(&mut stream).await?;

        Ok(MuxedSrtpStream::new(session, stream))
    }

    /// Perform a "connect" DTLS handshake.
    async fn connect<S>(self, stream: &mut S) -> Result<SrtpSession, Error>
    where
        S: Stream<Item = io::Result<Bytes>> + Sink<Bytes, Error = io::Error> + Unpin,
    {
        let mut ssl_stream = InnerSslStream::new(stream);

        let connect = futures::future::lazy(move |cx| {
            ssl_stream.set_async_context(Some(cx));

            let mut res = HandshakeState::from(self.inner.connect(ssl_stream));

            res.set_async_context(None);
            res
        });

        let handshake = Handshake::from(connect.await);

        let ssl_stream = handshake.await?;

        SrtpSession::client(ssl_stream.ssl())
    }

    /// Perform an "accept" DTLS handshake.
    async fn accept<S>(self, stream: &mut S) -> Result<SrtpSession, Error>
    where
        S: Stream<Item = io::Result<Bytes>> + Sink<Bytes, Error = io::Error> + Unpin,
    {
        let mut ssl_stream = InnerSslStream::new(stream);

        let accept = futures::future::lazy(move |cx| {
            ssl_stream.set_async_context(Some(cx));

            let mut res = HandshakeState::from(self.inner.accept(ssl_stream));

            res.set_async_context(None);
            res
        });

        let handshake = Handshake::from(accept.await);

        let ssl_stream = handshake.await?;

        SrtpSession::server(ssl_stream.ssl())
    }
}

/// SRTP stream.
pub struct SrtpStream<S> {
    inner: MuxedSrtpStream<S>,
}

impl<S> SrtpStream<S> {
    /// Create a new SRTP stream.
    fn new(session: SrtpSession, stream: S) -> Self {
        Self {
            inner: MuxedSrtpStream::new(session, stream),
        }
    }
}

impl<S> Stream for SrtpStream<S>
where
    S: Stream<Item = io::Result<Bytes>> + Unpin,
{
    type Item = Result<RtpPacket, Error>;

    #[inline]
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        while let Poll::Ready(ready) = self.inner.poll_next_unpin(cx) {
            match ready.transpose()? {
                Some(PacketMux::Rtp(packet)) => return Poll::Ready(Some(Ok(packet))),
                Some(PacketMux::Rtcp(_)) => (),
                None => return Poll::Ready(None),
            }
        }

        Poll::Pending
    }
}

impl<S> Sink<RtpPacket> for SrtpStream<S>
where
    S: Sink<Bytes, Error = io::Error> + Unpin,
{
    type Error = Error;

    #[inline]
    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready_unpin(cx)
    }

    #[inline]
    fn start_send(mut self: Pin<&mut Self>, packet: RtpPacket) -> Result<(), Self::Error> {
        self.inner.start_send_unpin(packet.into())
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

/// SRTCP stream.
pub struct SrtcpStream<S> {
    inner: MuxedSrtpStream<S>,
}

impl<S> SrtcpStream<S> {
    /// Create a new SRTCP stream.
    fn new(session: SrtpSession, stream: S) -> Self {
        Self {
            inner: MuxedSrtpStream::new(session, stream),
        }
    }
}

impl<S> Stream for SrtcpStream<S>
where
    S: Stream<Item = io::Result<Bytes>> + Unpin,
{
    type Item = Result<CompoundRtcpPacket, Error>;

    #[inline]
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        while let Poll::Ready(ready) = self.inner.poll_next_unpin(cx) {
            match ready.transpose()? {
                Some(PacketMux::Rtp(_)) => (),
                Some(PacketMux::Rtcp(packet)) => return Poll::Ready(Some(Ok(packet))),
                None => return Poll::Ready(None),
            }
        }

        Poll::Pending
    }
}

impl<S> Sink<CompoundRtcpPacket> for SrtcpStream<S>
where
    S: Sink<Bytes, Error = io::Error> + Unpin,
{
    type Error = Error;

    #[inline]
    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready_unpin(cx)
    }

    #[inline]
    fn start_send(mut self: Pin<&mut Self>, packet: CompoundRtcpPacket) -> Result<(), Self::Error> {
        self.inner.start_send_unpin(packet.into())
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

/// Muxed SRTP-SRTCP stream.
pub struct MuxedSrtpStream<S> {
    session: SrtpSession,
    inner: S,
}

impl<S> MuxedSrtpStream<S> {
    /// Create a new muxed SRTP-SRTCP stream.
    fn new(session: SrtpSession, stream: S) -> Self {
        Self {
            session,
            inner: stream,
        }
    }
}

impl<S> Stream for MuxedSrtpStream<S>
where
    S: Stream<Item = io::Result<Bytes>> + Unpin,
{
    type Item = Result<PacketMux, Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            if let Some(packet) = self.session.next() {
                return Poll::Ready(Some(Ok(packet)));
            } else if let Poll::Ready(ready) = self.inner.poll_next_unpin(cx) {
                if let Some(frame) = ready.transpose()? {
                    if let Err(DecodingError::Other(err)) = self.session.decode(frame) {
                        return Poll::Ready(Some(Err(err)));
                    }
                } else {
                    return Poll::Ready(None);
                }
            } else {
                return Poll::Pending;
            }
        }
    }
}

impl<S> Sink<PacketMux> for MuxedSrtpStream<S>
where
    S: Sink<Bytes, Error = io::Error> + Unpin,
{
    type Error = Error;

    #[inline]
    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        ready!(self.inner.poll_ready_unpin(cx))?;

        Poll::Ready(Ok(()))
    }

    fn start_send(mut self: Pin<&mut Self>, packet: PacketMux) -> Result<(), Self::Error> {
        let frame = match packet {
            PacketMux::Rtp(packet) => self.session.encode_rtp_packet(packet)?,
            PacketMux::Rtcp(packet) => {
                if let Some(first) = packet.first() {
                    match first.packet_type() {
                        RtcpPacketType::SR | RtcpPacketType::RR => {
                            self.session.encode_rtcp_packet(packet)?
                        }
                        _ => return Err(Error::from(InternalError::InvalidPacketType)),
                    }
                } else {
                    return Ok(());
                }
            }
        };

        self.inner.start_send_unpin(frame)?;

        Ok(())
    }

    #[inline]
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        ready!(self.inner.poll_flush_unpin(cx))?;

        Poll::Ready(Ok(()))
    }

    #[inline]
    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        ready!(self.inner.poll_close_unpin(cx))?;

        Poll::Ready(Ok(()))
    }
}

/// Pending SRTP handshake.
struct Handshake<'a, S> {
    inner: Option<HandshakeState<'a, S>>,
}

impl<'a, S> From<HandshakeState<'a, S>> for Handshake<'a, S> {
    fn from(state: HandshakeState<'a, S>) -> Self {
        Self { inner: Some(state) }
    }
}

impl<'a, S> Future for Handshake<'a, S>
where
    S: Stream<Item = io::Result<Bytes>> + Sink<Bytes, Error = io::Error> + Unpin,
{
    type Output = Result<SslStream<InnerSslStream<'a, S>>, InternalError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let mut state = self
            .inner
            .take()
            .expect("the future has been already resolved");

        state.set_async_context(Some(cx));

        match state.inner {
            Ok(stream) => Poll::Ready(Ok(stream)),
            Err(HandshakeError::SetupFailure(err)) => Poll::Ready(Err(err.into())),
            Err(HandshakeError::Failure(m)) => {
                Poll::Ready(Err(InternalError::from(m.into_error())))
            }
            Err(HandshakeError::WouldBlock(m)) => match m.handshake() {
                Ok(stream) => Poll::Ready(Ok(stream)),
                Err(HandshakeError::SetupFailure(err)) => Poll::Ready(Err(err.into())),
                Err(HandshakeError::Failure(m)) => {
                    Poll::Ready(Err(InternalError::from(m.into_error())))
                }
                Err(HandshakeError::WouldBlock(m)) => {
                    let mut state = HandshakeState::from(HandshakeError::WouldBlock(m));

                    state.set_async_context(None);

                    self.inner = Some(state);

                    Poll::Pending
                }
            },
        }
    }
}

/// Type alias.
type HandshakeResult<'a, S> =
    Result<SslStream<InnerSslStream<'a, S>>, HandshakeError<InnerSslStream<'a, S>>>;

/// Helper struct.
struct HandshakeState<'a, S> {
    inner: HandshakeResult<'a, S>,
}

impl<'a, S> HandshakeState<'a, S> {
    /// Use a given asynchronous context on the next IO operation.
    fn set_async_context(&mut self, cx: Option<&mut Context<'_>>) {
        let ssl_stream = match &mut self.inner {
            Ok(ssl_stream) => Some(ssl_stream.get_mut()),
            Err(HandshakeError::Failure(m)) => Some(m.get_mut()),
            Err(HandshakeError::WouldBlock(m)) => Some(m.get_mut()),
            _ => None,
        };

        if let Some(s) = ssl_stream {
            s.set_async_context(cx);
        }
    }
}

impl<'a, S> From<HandshakeResult<'a, S>> for HandshakeState<'a, S> {
    fn from(res: HandshakeResult<'a, S>) -> Self {
        Self { inner: res }
    }
}

impl<'a, S> From<HandshakeError<InnerSslStream<'a, S>>> for HandshakeState<'a, S> {
    fn from(err: HandshakeError<InnerSslStream<'a, S>>) -> Self {
        Self::from(Err(err))
    }
}

/// Helper struct.
struct InnerSslStream<'a, S> {
    inner: RWStreamRef<'a, S>,
    context: *mut (),
}

impl<'a, S> InnerSslStream<'a, S> {
    /// Create a new inner SSL stream.
    fn new(stream: &'a mut S) -> Self {
        Self {
            inner: RWStreamRef::new(stream),
            context: ptr::null_mut(),
        }
    }

    /// Use a given asynchronous context on the next IO operation.
    fn set_async_context(&mut self, cx: Option<&mut Context<'_>>) {
        if let Some(cx) = cx {
            self.context = cx as *mut _ as *mut ();
        } else {
            self.context = ptr::null_mut();
        }
    }
}

unsafe impl<'a, S> Send for InnerSslStream<'a, S> where S: Send {}
unsafe impl<'a, S> Sync for InnerSslStream<'a, S> where S: Sync {}

impl<'a, S> Read for InnerSslStream<'a, S>
where
    S: Stream<Item = io::Result<Bytes>> + Unpin,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        debug_assert!(!self.context.is_null());

        let cx = unsafe { &mut *(self.context as *mut Context<'_>) };

        let pinned = Pin::new(&mut self.inner);

        let mut buf = ReadBuf::new(buf);

        let data = match pinned.poll_read(cx, &mut buf) {
            Poll::Ready(Ok(())) => buf.filled(),
            Poll::Ready(Err(err)) => return Err(err),
            Poll::Pending => return Err(io::Error::from(io::ErrorKind::WouldBlock)),
        };

        Ok(data.len())
    }
}

impl<'a, S> Write for InnerSslStream<'a, S>
where
    S: Sink<Bytes, Error = io::Error> + Unpin,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        debug_assert!(!self.context.is_null());

        let cx = unsafe { &mut *(self.context as *mut Context<'_>) };

        let pinned = Pin::new(&mut self.inner);

        if let Poll::Ready(res) = pinned.poll_write(cx, buf) {
            res
        } else {
            Err(io::Error::from(io::ErrorKind::WouldBlock))
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        debug_assert!(!self.context.is_null());

        let cx = unsafe { &mut *(self.context as *mut Context<'_>) };

        let pinned = Pin::new(&mut self.inner);

        if let Poll::Ready(res) = AsyncWrite::poll_flush(pinned, cx) {
            res
        } else {
            Err(io::Error::from(io::ErrorKind::WouldBlock))
        }
    }
}

/// Stream/sink wrapper making it an asynchronous reader/writer.
struct RWStreamRef<'a, S> {
    stream: &'a mut S,
    input: Bytes,
    output: BytesMut,
}

impl<'a, S> RWStreamRef<'a, S> {
    /// Create a new wrapper.
    fn new(stream: &'a mut S) -> Self {
        Self {
            stream,
            input: Bytes::new(),
            output: BytesMut::new(),
        }
    }
}

impl<'a, S> AsyncRead for RWStreamRef<'a, S>
where
    S: Stream<Item = io::Result<Bytes>> + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if !self.input.is_empty() {
                let remaining = buf.remaining();
                let take = remaining.min(self.input.len());
                let data = self.input.split_to(take);

                buf.put_slice(&data);

                return Poll::Ready(Ok(()));
            } else if let Poll::Ready(ready) = self.stream.poll_next_unpin(cx) {
                if let Some(chunk) = ready.transpose()? {
                    self.input = chunk;
                } else {
                    return Poll::Ready(Ok(()));
                }
            } else {
                return Poll::Pending;
            }
        }
    }
}

impl<'a, S> AsyncWrite for RWStreamRef<'a, S>
where
    S: Sink<Bytes, Error = io::Error> + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;

        ready!(this.stream.poll_ready_unpin(cx))?;

        this.output.extend_from_slice(buf);

        let data = this.output.split_to(this.output.len()).freeze();

        this.stream.start_send_unpin(data)?;

        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        self.stream.poll_flush_unpin(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        self.stream.poll_close_unpin(cx)
    }
}
