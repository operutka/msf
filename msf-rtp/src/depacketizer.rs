//! Common types for RTP to media framing.

use std::{
    pin::Pin,
    task::{Context, Poll},
};

use futures::{Stream, StreamExt};

use crate::RtpPacket;

/// Common trait for de-packetizers.
///
/// Depacketizers are responsible for converting RTP packets into media frames.
///
/// # Usage
/// 1. Push an RTP packet into the depacketizer.
/// 2. Take all media frames from the depacketizer.
/// 3. Repeat from (1) if needed.
/// 4. Flush the depacketizer.
/// 5. Take all media frames from the depacketizer.
pub trait Depacketizer {
    type Frame;
    type Error;

    /// Process a given RTP packet.
    ///
    /// # Panics
    /// The method may panic if calling the `take` method would not return
    /// `None`.
    fn push(&mut self, packet: RtpPacket) -> Result<(), Self::Error>;

    /// Flush the depacketizer.
    ///
    /// # Panics
    /// The method may panic if calling the `take` method would not return
    /// `None`.
    fn flush(&mut self) -> Result<(), Self::Error>;

    /// Take the next available media frame.
    ///
    /// Note that only after this method returns `None`, it is allowed to call
    /// the `push` method or the `flush` method again.
    fn take(&mut self) -> Result<Option<Self::Frame>, Self::Error>;

    /// Map the media frame into a different type.
    #[inline]
    fn map_frame<F, T>(self, f: F) -> MapFrame<Self, F>
    where
        F: FnMut(Self::Frame) -> T,
        Self: Sized,
    {
        MapFrame {
            depacketizer: self,
            closure: f,
        }
    }

    /// Map the depacketizer error into a different one.
    #[inline]
    fn map_err<F, E>(self, f: F) -> MapErr<Self, F>
    where
        F: FnMut(Self::Error) -> E,
        Self: Sized,
    {
        MapErr {
            depacketizer: self,
            closure: f,
        }
    }
}

/// Depacketizer with mapped error type.
pub struct MapErr<D, F> {
    depacketizer: D,
    closure: F,
}

impl<D, F, E> Depacketizer for MapErr<D, F>
where
    D: Depacketizer,
    F: FnMut(D::Error) -> E,
{
    type Frame = D::Frame;
    type Error = E;

    #[inline]
    fn push(&mut self, packet: RtpPacket) -> Result<(), Self::Error> {
        self.depacketizer.push(packet).map_err(&mut self.closure)
    }

    #[inline]
    fn flush(&mut self) -> Result<(), Self::Error> {
        self.depacketizer.flush().map_err(&mut self.closure)
    }

    #[inline]
    fn take(&mut self) -> Result<Option<Self::Frame>, Self::Error> {
        self.depacketizer.take().map_err(&mut self.closure)
    }
}

/// Depacketizer with mapped media frame type.
pub struct MapFrame<D, F> {
    depacketizer: D,
    closure: F,
}

impl<D, F, T> Depacketizer for MapFrame<D, F>
where
    D: Depacketizer,
    F: FnMut(D::Frame) -> T,
{
    type Frame = T;
    type Error = D::Error;

    #[inline]
    fn push(&mut self, packet: RtpPacket) -> Result<(), Self::Error> {
        self.depacketizer.push(packet)
    }

    #[inline]
    fn flush(&mut self) -> Result<(), Self::Error> {
        self.depacketizer.flush()
    }

    #[inline]
    fn take(&mut self) -> Result<Option<Self::Frame>, Self::Error> {
        if let Some(frame) = self.depacketizer.take()? {
            Ok(Some((self.closure)(frame)))
        } else {
            Ok(None)
        }
    }
}

impl<T> Depacketizer for Box<T>
where
    T: Depacketizer + ?Sized,
{
    type Frame = T::Frame;
    type Error = T::Error;

    #[inline]
    fn push(&mut self, packet: RtpPacket) -> Result<(), Self::Error> {
        <T as Depacketizer>::push(self, packet)
    }

    #[inline]
    fn flush(&mut self) -> Result<(), Self::Error> {
        <T as Depacketizer>::flush(self)
    }

    #[inline]
    fn take(&mut self) -> Result<Option<Self::Frame>, Self::Error> {
        <T as Depacketizer>::take(self)
    }
}

/// Media stream that uses an underlying depacketizer to convert RTP packets
/// from the underlying RTP stream into media frames.
pub struct MediaStream<S, D> {
    rtp_stream: Option<S>,
    depacketizer: D,
}

impl<S, D> MediaStream<S, D> {
    /// Create a new media stream.
    #[inline]
    pub const fn new(rtp_stream: S, depacketizer: D) -> Self {
        Self {
            rtp_stream: Some(rtp_stream),
            depacketizer,
        }
    }
}

impl<S, D, E> Stream for MediaStream<S, D>
where
    S: Stream<Item = Result<RtpPacket, E>> + Unpin,
    D: Depacketizer + Unpin,
    E: From<D::Error>,
{
    type Item = Result<D::Frame, E>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            if let Some(frame) = self.depacketizer.take()? {
                return Poll::Ready(Some(Ok(frame)));
            } else if let Some(stream) = self.rtp_stream.as_mut() {
                if let Poll::Ready(ready) = stream.poll_next_unpin(cx) {
                    if let Some(packet) = ready.transpose()? {
                        self.depacketizer.push(packet)?;
                    } else {
                        self.depacketizer.flush()?;
                        self.rtp_stream = None;
                    }
                } else {
                    return Poll::Pending;
                }
            } else {
                return Poll::Ready(None);
            }
        }
    }
}
