//! UDP utils.

use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Bytes, BytesMut};
use futures::{Sink, SinkExt, Stream, StreamExt, ready};
use tokio::net::UdpSocket;
use tokio_util::{
    codec::{BytesCodec, Decoder, Encoder},
    udp::UdpFramed,
};

/// UDP channel.
pub struct UdpChannel {
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    framed: UdpFramed<UdpCodec>,
}

impl UdpChannel {
    /// Create a new UDP channel connecting given two addresses.
    pub async fn new(local_addr: SocketAddr, remote_addr: SocketAddr) -> io::Result<Self> {
        let socket = UdpSocket::bind(local_addr).await?;

        let local_addr = socket.local_addr()?;

        socket.connect(remote_addr).await?;

        let codec = UdpCodec::new();
        let framed = UdpFramed::new(socket, codec);

        let channel = Self {
            local_addr,
            remote_addr,
            framed,
        };

        Ok(channel)
    }

    /// Get local address that this channel is bound to.
    #[inline]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Get the local port that this channel is bound to.
    #[inline]
    pub fn local_port(&self) -> u16 {
        self.local_addr.port()
    }

    /// Get the remote address where the outgoing packets go.
    #[inline]
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    /// Get the remote port where the outgoing packets go.
    #[inline]
    pub fn remote_port(&self) -> u16 {
        self.remote_addr.port()
    }
}

impl Stream for UdpChannel {
    type Item = io::Result<Bytes>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if let Some(item) = ready!(self.framed.poll_next_unpin(cx)) {
            Poll::Ready(Some(item.map(|(data, _)| data)))
        } else {
            Poll::Ready(None)
        }
    }
}

impl Sink<Bytes> for UdpChannel {
    type Error = io::Error;

    #[inline]
    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        self.framed.poll_ready_unpin(cx)
    }

    #[inline]
    fn start_send(mut self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
        let remote_addr = self.remote_addr;

        self.framed.start_send_unpin((item, remote_addr))
    }

    #[inline]
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        self.framed.poll_flush_unpin(cx)
    }

    #[inline]
    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        self.framed.poll_close_unpin(cx)
    }
}

/// Helper struct to deal with type annotations.
struct UdpCodec {
    inner: BytesCodec,
}

impl UdpCodec {
    /// Create a new UDP bytes codec.
    fn new() -> Self {
        Self {
            inner: BytesCodec::new(),
        }
    }
}

impl Decoder for UdpCodec {
    type Item = Bytes;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match self.inner.decode(src) {
            Ok(Some(data)) => Ok(Some(data.freeze())),
            Ok(None) => Ok(None),
            Err(err) => Err(err),
        }
    }

    fn decode_eof(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match self.inner.decode_eof(buf) {
            Ok(Some(data)) => Ok(Some(data.freeze())),
            Ok(None) => Ok(None),
            Err(err) => Err(err),
        }
    }
}

impl Encoder<Bytes> for UdpCodec {
    type Error = io::Error;

    fn encode(&mut self, item: Bytes, dst: &mut BytesMut) -> Result<(), Self::Error> {
        self.inner.encode(item, dst)
    }
}
