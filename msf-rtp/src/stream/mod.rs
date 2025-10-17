//! RTP streaming utilities.

pub mod receiver;
pub mod sender;

use std::{
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use bytes::{Bytes, BytesMut};
use futures::{ready, Sink, Stream};

use crate::{
    rtp::RtpPacket,
    InvalidInput,
};

pin_project_lite::pin_project! {
    /// RTP channel decoding/encoding RTP packets from/to byte frames.
    ///
    /// The channel does not perform any reordering or additional validation of
    /// the incoming RTP packets.
    pub struct RtpChannel<T> {
        #[pin]
        inner: T,
        output_buffer: BytesMut,
        ignore_decoding_errors: bool,
    }
}

impl<T> RtpChannel<T> {
    /// Create a new RTP channel from a given byte frame channel.
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

impl<T, E> Stream for RtpChannel<T>
where
    T: Stream<Item = Result<Bytes, E>>,
    E: From<InvalidInput>,
{
    type Item = Result<RtpPacket, E>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();

        loop {
            let inner = this.inner.as_mut();

            let res = match ready!(inner.poll_next(cx)) {
                Some(Ok(frame)) => match RtpPacket::decode(frame) {
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

impl<T> Sink<RtpPacket> for RtpChannel<T>
where
    T: Sink<Bytes>,
{
    type Error = T::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.project();

        ready!(this.inner.poll_ready(cx))?;

        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: RtpPacket) -> Result<(), Self::Error> {
        let this = self.project();

        item.encode(this.output_buffer);

        let frame = this.output_buffer.split();

        this.inner.start_send(frame.freeze())?;

        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.project();

        ready!(this.inner.poll_flush(cx))?;

        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.project();

        ready!(this.inner.poll_close(cx))?;

        Poll::Ready(Ok(()))
    }
}

/// Helper trait.
trait DurationExt {
    /// Convert duration to RTP time with given clock rate.
    fn to_rtp_time(&self, clock_rate: u32) -> u32;
}

impl DurationExt for Duration {
    fn to_rtp_time(&self, clock_rate: u32) -> u32 {
        let secs = self.as_secs();
        let subs = self.subsec_nanos();

        let rtp_secs = secs.wrapping_mul(clock_rate as u64);

        let rtp_subs = (subs as u64) * (clock_rate as u64) / 1_000_000_000u64;

        (rtp_secs.wrapping_add(rtp_subs)) as u32
    }
}
