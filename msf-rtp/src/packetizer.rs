//! Common types for media to RTP framing.

use std::{
    marker::PhantomData,
    pin::Pin,
    task::{Context, Poll},
};

use futures::{ready, Sink, SinkExt};

use crate::RtpPacket;

/// Common trait for packetizers.
///
/// Packetizers are responsible for converting media frames into RTP packets.
///
/// # Usage
/// 1. Push a media frame into the packetizer.
/// 2. Take all RTP packets from the packetizer.
/// 3. Repeat from (1) if needed.
/// 4. Flush the packetizer.
/// 5. Take all RTP packets from the packetizer.
pub trait Packetizer {
    type Frame;
    type Error;

    /// Process a given media frame.
    ///
    /// # Panics
    /// The method may panic if calling the `take` method would not return
    /// `None`.
    fn push(&mut self, frame: Self::Frame) -> Result<(), Self::Error>;

    /// Flush the packetizer.
    ///
    /// # Panics
    /// The method may panic if calling the `take` method would not return
    /// `None`.
    fn flush(&mut self) -> Result<(), Self::Error>;

    /// Take the next available RTP packet.
    ///
    /// Note that only after this method returns `None`, it is allowed to call
    /// the `push` method or the `flush` method again.
    fn take(&mut self) -> Result<Option<RtpPacket>, Self::Error>;

    /// Convert this packetizer into a new one accepting media frames of a
    /// given type.
    #[inline]
    fn with_frame<F, T>(self, f: F) -> WithFrame<Self, F, T>
    where
        F: FnMut(T) -> Self::Frame,
        Self: Sized,
    {
        WithFrame {
            packetizer: self,
            closure: f,
            _frame: PhantomData,
        }
    }

    /// Map the packetizer error into a different one.
    #[inline]
    fn map_err<F, E>(self, f: F) -> MapErr<Self, F>
    where
        F: FnMut(Self::Error) -> E,
        Self: Sized,
    {
        MapErr {
            packetizer: self,
            closure: f,
        }
    }
}

/// Packetizer with mapped error type.
pub struct MapErr<P, F> {
    packetizer: P,
    closure: F,
}

impl<P, F, E> Packetizer for MapErr<P, F>
where
    P: Packetizer,
    F: FnMut(P::Error) -> E,
{
    type Frame = P::Frame;
    type Error = E;

    #[inline]
    fn push(&mut self, frame: Self::Frame) -> Result<(), Self::Error> {
        self.packetizer.push(frame).map_err(&mut self.closure)
    }

    #[inline]
    fn flush(&mut self) -> Result<(), Self::Error> {
        self.packetizer.flush().map_err(&mut self.closure)
    }

    #[inline]
    fn take(&mut self) -> Result<Option<RtpPacket>, Self::Error> {
        self.packetizer.take().map_err(&mut self.closure)
    }
}

/// Packetizer with mapped media frame type.
pub struct WithFrame<P, F, T> {
    packetizer: P,
    closure: F,
    _frame: PhantomData<T>,
}

impl<P, F, T> Packetizer for WithFrame<P, F, T>
where
    P: Packetizer,
    F: FnMut(T) -> P::Frame,
{
    type Frame = T;
    type Error = P::Error;

    #[inline]
    fn push(&mut self, frame: Self::Frame) -> Result<(), Self::Error> {
        self.packetizer.push((self.closure)(frame))
    }

    #[inline]
    fn flush(&mut self) -> Result<(), Self::Error> {
        self.packetizer.flush()
    }

    #[inline]
    fn take(&mut self) -> Result<Option<RtpPacket>, Self::Error> {
        self.packetizer.take()
    }
}

impl<T> Packetizer for Box<T>
where
    T: Packetizer + ?Sized,
{
    type Frame = T::Frame;
    type Error = T::Error;

    #[inline]
    fn push(&mut self, frame: Self::Frame) -> Result<(), Self::Error> {
        <T as Packetizer>::push(self, frame)
    }

    #[inline]
    fn flush(&mut self) -> Result<(), Self::Error> {
        <T as Packetizer>::flush(self)
    }

    #[inline]
    fn take(&mut self) -> Result<Option<RtpPacket>, Self::Error> {
        <T as Packetizer>::take(self)
    }
}

/// Media sink that uses an underlying packetizer to convert media frames into
/// RTP packets and forwards the RTP packets into an underlying RTP sink.
pub struct MediaSink<S, P> {
    rtp_sink: S,
    packetizer: P,
    pending: Option<RtpPacket>,
}

impl<S, P> MediaSink<S, P> {
    /// Create a new media sink.
    #[inline]
    pub const fn new(rtp_sink: S, packetizer: P) -> Self {
        Self {
            rtp_sink,
            packetizer,
            pending: None,
        }
    }
}

impl<S, P> MediaSink<S, P>
where
    S: Sink<RtpPacket> + Unpin,
    P: Packetizer,
    S::Error: From<P::Error>,
{
    /// Get the next packet to be sent.
    fn next_packet(&mut self) -> Result<Option<RtpPacket>, P::Error> {
        if let Some(packet) = self.pending.take() {
            Ok(Some(packet))
        } else {
            self.packetizer.take()
        }
    }

    /// Flush the underlying packetizer.
    fn poll_flush_packetizer(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), S::Error>> {
        while let Some(packet) = self.next_packet()? {
            match self.rtp_sink.poll_ready_unpin(cx) {
                Poll::Ready(Ok(())) => self.rtp_sink.start_send_unpin(packet)?,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => {
                    // we'll have to try it next time
                    self.pending = Some(packet);

                    return Poll::Pending;
                }
            }
        }

        Poll::Ready(Ok(()))
    }
}

impl<S, P> Sink<P::Frame> for MediaSink<S, P>
where
    S: Sink<RtpPacket> + Unpin,
    P: Packetizer + Unpin,
    S::Error: From<P::Error>,
{
    type Error = S::Error;

    #[inline]
    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.poll_flush_packetizer(cx)
    }

    #[inline]
    fn start_send(mut self: Pin<&mut Self>, frame: P::Frame) -> Result<(), Self::Error> {
        self.packetizer.push(frame)?;

        Ok(())
    }

    #[inline]
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        ready!(self.poll_flush_packetizer(cx))?;

        self.rtp_sink.poll_flush_unpin(cx)
    }

    #[inline]
    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        ready!(self.poll_flush_packetizer(cx))?;

        self.rtp_sink.poll_close_unpin(cx)
    }
}
