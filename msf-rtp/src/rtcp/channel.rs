use std::{
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Bytes, BytesMut};
use futures::{ready, Sink, Stream};

use crate::{rtcp::CompoundRtcpPacket, InvalidInput};

pin_project_lite::pin_project! {
    /// RTCP channel decoding/encoding RTCP packets from/to byte frames.
    pub struct RtcpChannel<T> {
        #[pin]
        inner: T,
        output_buffer: BytesMut,
        ignore_decoding_errors: bool,
    }
}

impl<T> RtcpChannel<T> {
    /// Create a new RTCP channel from a given byte frame channel.
    ///
    /// # Arguments
    /// * `inner` - the underlying byte frame channel
    /// * `ignore_decoding_errors` - if true, decoding errors will be ignored
    ///   and the invalid packets will be silently dropped (the underlying
    ///   stream errors will still be propagated)
    #[inline]
    pub fn new(inner: T, ignore_decoding_errors: bool) -> Self {
        Self {
            inner,
            output_buffer: BytesMut::new(),
            ignore_decoding_errors,
        }
    }
}

impl<T, E> Stream for RtcpChannel<T>
where
    T: Stream<Item = Result<Bytes, E>>,
    E: From<InvalidInput>,
{
    type Item = Result<CompoundRtcpPacket, E>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();

        loop {
            let inner = this.inner.as_mut();

            let res = match ready!(inner.poll_next(cx)) {
                Some(Ok(frame)) => match CompoundRtcpPacket::decode(frame) {
                    Ok(packet) => Some(Ok(packet)),
                    Err(_) if *this.ignore_decoding_errors => continue,
                    Err(err) => Some(Err(err.into())),
                },
                Some(Err(err)) => Some(Err(err)),
                None => None,
            };

            return Poll::Ready(res);
        }
    }
}

impl<T> Sink<CompoundRtcpPacket> for RtcpChannel<T>
where
    T: Sink<Bytes>,
{
    type Error = T::Error;

    #[inline]
    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.project();

        this.inner.poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: CompoundRtcpPacket) -> Result<(), Self::Error> {
        let this = self.project();

        item.encode(this.output_buffer);

        let frame = this.output_buffer.split();

        this.inner.start_send(frame.freeze())?;

        Ok(())
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.project();

        this.inner.poll_flush(cx)
    }

    #[inline]
    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.project();

        this.inner.poll_close(cx)
    }
}
