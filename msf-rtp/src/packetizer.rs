//! Common types for media to RTP framing.

use std::{
    marker::PhantomData,
    pin::Pin,
    task::{Context, Poll},
};

use futures::{ready, Sink};

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

pin_project_lite::pin_project! {
    /// Media sink that uses an underlying packetizer to convert media frames
    /// into RTP packets and forwards the RTP packets into an underlying RTP
    /// sink.
    pub struct MediaSink<S, P> {
        #[pin]
        rtp_sink: S,
        context: MediaSinkContext<P>,
    }
}

impl<S, P> MediaSink<S, P> {
    /// Create a new media sink.
    #[inline]
    pub const fn new(rtp_sink: S, packetizer: P) -> Self {
        Self {
            rtp_sink,
            context: MediaSinkContext::new(packetizer),
        }
    }
}

impl<S, P> MediaSink<S, P>
where
    S: Sink<RtpPacket>,
    P: Packetizer,
    S::Error: From<P::Error>,
{
    /// Flush the underlying packetizer.
    fn poll_flush_packetizer(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), S::Error>> {
        let mut this = self.project();

        while let Some(packet) = this.context.next_packet()? {
            match this.rtp_sink.as_mut().poll_ready(cx) {
                Poll::Ready(Ok(())) => this.rtp_sink.as_mut().start_send(packet)?,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => {
                    // we'll have to try it next time
                    this.context.push_back_packet(packet);

                    return Poll::Pending;
                }
            }
        }

        Poll::Ready(Ok(()))
    }
}

impl<S, P> Sink<P::Frame> for MediaSink<S, P>
where
    S: Sink<RtpPacket>,
    P: Packetizer,
    S::Error: From<P::Error>,
{
    type Error = S::Error;

    #[inline]
    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.poll_flush_packetizer(cx)
    }

    #[inline]
    fn start_send(self: Pin<&mut Self>, frame: P::Frame) -> Result<(), Self::Error> {
        let this = self.project();

        this.context.push_frame(frame)?;

        Ok(())
    }

    #[inline]
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.as_mut();

        ready!(this.poll_flush_packetizer(cx))?;

        let this = self.project();

        this.rtp_sink.poll_flush(cx)
    }

    #[inline]
    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.as_mut();

        ready!(this.poll_flush_packetizer(cx))?;

        let this = self.project();

        this.rtp_sink.poll_close(cx)
    }
}

/// Media sink context.
struct MediaSinkContext<P> {
    packetizer: P,
    pending: Option<RtpPacket>,
}

impl<P> MediaSinkContext<P> {
    /// Create a new media sink context.
    #[inline]
    const fn new(packetizer: P) -> Self {
        Self {
            packetizer,
            pending: None,
        }
    }

    /// Push back a given packet that was not sent.
    ///
    /// The packet will be returned next time the `next_packet` method is
    /// called.
    fn push_back_packet(&mut self, packet: RtpPacket) {
        self.pending = Some(packet);
    }
}

impl<P> MediaSinkContext<P>
where
    P: Packetizer,
{
    /// Push a given media frame into the underlying packetizer.
    fn push_frame(&mut self, frame: P::Frame) -> Result<(), P::Error> {
        self.packetizer.push(frame)
    }

    /// Get the next packet to be sent.
    fn next_packet(&mut self) -> Result<Option<RtpPacket>, P::Error> {
        if let Some(packet) = self.pending.take() {
            Ok(Some(packet))
        } else {
            self.packetizer.take()
        }
    }
}
