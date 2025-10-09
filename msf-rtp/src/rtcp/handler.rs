use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use futures::{
    channel::{mpsc, oneshot},
    ready, FutureExt, Sink, SinkExt, Stream, StreamExt,
};
use tokio::task::JoinHandle;

use crate::{CompoundRtcpPacket, PacketMux, RtpPacket};

pin_project_lite::pin_project! {
    /// RTCP protocol handler.
    ///
    /// The handler consumes a given RTP-RTCP stream pair and handles all the
    /// necessary RTCP communication. The resulting object can be used as an RTP
    /// stream/sink while the corresponding RTCP communication is handled
    /// automatically by a background task.
    pub struct RtcpHandler<T> {
        #[pin]
        stream: T,
        context: RtcpHandlerContext,
    }
}

impl<T> RtcpHandler<T> {
    /// Create a new RTCP handler.
    pub fn new<U, E>(rtp: T, rtcp: U) -> Self
    where
        U: Send + 'static,
        U: Stream<Item = Result<CompoundRtcpPacket, E>>,
        U: Sink<CompoundRtcpPacket>,
    {
        let context = RtcpContext::new();

        let (rtcp_tx, rtcp_rx) = rtcp.split();

        let (close_tx, close_rx) = oneshot::channel();

        let sender = RtcpSender {
            sink: rtcp_tx,
            context: RtcpSenderContext {
                context: context.clone(),
                close_rx: Some(close_rx),
                pending: None,
            },
        };

        let receiver = RtcpReceiver {
            context: context.clone(),
            stream: rtcp_rx,
        };

        tokio::spawn(async move { sender.await.unwrap_or_default() });

        let receiver = tokio::spawn(async move { receiver.await.unwrap_or_default() });

        Self {
            stream: rtp,
            context: RtcpHandlerContext {
                context,
                receiver,
                sender: Some(close_tx),
            },
        }
    }
}

impl<T, E> Stream for RtcpHandler<T>
where
    T: Stream<Item = Result<RtpPacket, E>>,
{
    type Item = Result<RtpPacket, E>;

    #[inline]
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();

        if let Poll::Ready(ready) = this.stream.poll_next(cx) {
            if let Some(packet) = ready.transpose()? {
                this.context.process_incoming_rtp_packet(&packet);

                Poll::Ready(Some(Ok(packet)))
            } else {
                Poll::Ready(None)
            }
        } else {
            Poll::Pending
        }
    }
}

impl<T, E> Sink<RtpPacket> for RtcpHandler<T>
where
    T: Sink<RtpPacket, Error = E>,
{
    type Error = E;

    #[inline]
    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.project();

        this.stream.poll_ready(cx)
    }

    #[inline]
    fn start_send(self: Pin<&mut Self>, packet: RtpPacket) -> Result<(), Self::Error> {
        let this = self.project();

        this.context.process_outgoing_rtp_packet(&packet);

        this.stream.start_send(packet)
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.project();

        this.stream.poll_flush(cx)
    }

    #[inline]
    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.project();

        this.stream.poll_close(cx)
    }
}

/// RTCP handler context.
struct RtcpHandlerContext {
    context: RtcpContext,
    receiver: JoinHandle<()>,
    sender: Option<oneshot::Sender<()>>,
}

impl RtcpHandlerContext {
    /// Process a given incoming RTP packet.
    fn process_incoming_rtp_packet(&mut self, packet: &RtpPacket) {
        self.context.process_incoming_rtp_packet(packet);
    }

    /// Process a given outgoing RTP packet.
    fn process_outgoing_rtp_packet(&mut self, packet: &RtpPacket) {
        self.context.process_outgoing_rtp_packet(packet);
    }
}

impl Drop for RtcpHandlerContext {
    fn drop(&mut self) {
        // stop the RTCP receiver
        self.receiver.abort();

        // shutdown the RTCP sender
        if let Some(close_tx) = self.sender.take() {
            let _ = close_tx.send(());
        }
    }
}

/// Type alias.
type DemuxingRtpStream<E> = mpsc::Receiver<Result<RtpPacket, E>>;

/// Type alias.
type MuxingRtpSink = PacketMuxer<mpsc::Sender<PacketMux>>;

/// Type alias.
type RtpComponent<E> = StreamSink<DemuxingRtpStream<E>, MuxingRtpSink>;

/// RTCP protocol handler for muxed RTP-RTCP streams.
///
/// The handler consumes a given muxed RTP-RTCP stream and handles all the
/// necessary RTCP communication. The resulting object can be used as an RTP
/// stream/sink while the corresponding RTCP communication is handled
/// automatically by a background task.
pub struct MuxedRtcpHandler<E> {
    inner: RtcpHandler<RtpComponent<E>>,
    reader: JoinHandle<()>,
    writer: JoinHandle<Result<(), E>>,
    sink_error: bool,
}

impl<E> MuxedRtcpHandler<E> {
    /// Create a new RTCP handler.
    pub fn new<T>(stream: T) -> Self
    where
        T: Send + 'static,
        T: Stream<Item = Result<PacketMux, E>>,
        T: Sink<PacketMux, Error = E>,
        E: Send + 'static,
    {
        let (mut muxed_tx, mut muxed_rx) = stream.split();

        let (mut input_rtp_tx, input_rtp_rx) = mpsc::channel(4);
        let (output_rtp_tx, output_rtp_rx) = mpsc::channel(4);
        let (mut input_rtcp_tx, input_rtcp_rx) = mpsc::channel(4);
        let (output_rtcp_tx, output_rtcp_rx) = mpsc::channel(4);

        let output_rtp_tx = PacketMuxer::new(output_rtp_tx);
        let output_rtcp_tx = PacketMuxer::new(output_rtcp_tx);

        let rtp = StreamSink::new(input_rtp_rx, output_rtp_tx);
        let rtcp = StreamSink::new(input_rtcp_rx, output_rtcp_tx);

        let reader = tokio::spawn(async move {
            while let Some(item) = muxed_rx.next().await {
                match item {
                    Ok(PacketMux::Rtp(packet)) => {
                        input_rtp_tx.send(Ok(packet)).await.unwrap_or_default();
                    }
                    Ok(PacketMux::Rtcp(packet)) => {
                        input_rtcp_tx
                            .send(Ok(packet) as Result<_, E>)
                            .await
                            .unwrap_or_default();
                    }
                    Err(err) => {
                        // forward the error into the RTP channel
                        input_rtp_tx.send(Err(err)).await.unwrap_or_default();

                        // ... and stop the reader
                        break;
                    }
                }
            }
        });

        let writer = tokio::spawn(async move {
            let mut stream = futures::stream::select(output_rtp_rx, output_rtcp_rx);

            while let Some(item) = stream.next().await {
                muxed_tx.send(item).await?;
            }

            Ok(()) as Result<(), T::Error>
        });

        Self {
            inner: RtcpHandler::new(rtp, rtcp),
            reader,
            writer,
            sink_error: false,
        }
    }

    /// Poll the writer result.
    fn poll_writer_result(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), E>> {
        match ready!(self.writer.poll_unpin(cx)) {
            Ok(Ok(_)) => Poll::Ready(Ok(())),
            Ok(Err(err)) => Poll::Ready(Err(err)),
            Err(_) => Poll::Ready(Ok(())),
        }
    }
}

impl<E> Drop for MuxedRtcpHandler<E> {
    #[inline]
    fn drop(&mut self) {
        self.reader.abort();
    }
}

impl<E> Stream for MuxedRtcpHandler<E> {
    type Item = Result<RtpPacket, E>;

    #[inline]
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.inner.poll_next_unpin(cx)
    }
}

impl<E> Sink<RtpPacket> for MuxedRtcpHandler<E> {
    type Error = E;

    #[inline]
    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        loop {
            if self.sink_error {
                return self.poll_writer_result(cx);
            }

            let res = ready!(self.inner.poll_ready_unpin(cx));

            if res.is_ok() {
                return Poll::Ready(Ok(()));
            } else {
                self.sink_error = true;
            }
        }
    }

    #[inline]
    fn start_send(mut self: Pin<&mut Self>, item: RtpPacket) -> Result<(), Self::Error> {
        let res = self.inner.start_send_unpin(item);

        // we cannot get the actual error here, it needs to be polled out from
        // the writer
        if res.is_err() {
            self.sink_error = true;
        }

        Ok(())
    }

    #[inline]
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        loop {
            if self.sink_error {
                return self.poll_writer_result(cx);
            }

            let res = ready!(self.inner.poll_flush_unpin(cx));

            if res.is_ok() {
                return Poll::Ready(Ok(()));
            } else {
                self.sink_error = true;
            }
        }
    }

    #[inline]
    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        loop {
            if self.sink_error {
                return self.poll_writer_result(cx);
            }

            let res = ready!(self.inner.poll_close_unpin(cx));

            if res.is_ok() {
                return Poll::Ready(Ok(()));
            } else {
                self.sink_error = true;
            }
        }
    }
}

pin_project_lite::pin_project! {
    /// Helper struct.
    struct StreamSink<T, U> {
        #[pin]
        stream: T,
        #[pin]
        sink: U,
    }
}

impl<T, U> StreamSink<T, U> {
    /// Create a new stream-sink.
    fn new(stream: T, sink: U) -> Self {
        Self { stream, sink }
    }
}

impl<T, U> Stream for StreamSink<T, U>
where
    T: Stream,
{
    type Item = T::Item;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();

        this.stream.poll_next(cx)
    }
}

impl<T, U, I> Sink<I> for StreamSink<T, U>
where
    U: Sink<I>,
{
    type Error = U::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.project();

        this.sink.poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: I) -> Result<(), Self::Error> {
        let this = self.project();

        this.sink.start_send(item)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.project();

        this.sink.poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.project();

        this.sink.poll_close(cx)
    }
}

pin_project_lite::pin_project! {
    /// Helper struct.
    struct PacketMuxer<T> {
        #[pin]
        inner: T,
    }
}

impl<T> PacketMuxer<T> {
    /// Create a new packet muxer.
    fn new(sink: T) -> Self {
        Self { inner: sink }
    }
}

impl<T, I> Sink<I> for PacketMuxer<T>
where
    T: Sink<PacketMux>,
    I: Into<PacketMux>,
{
    type Error = T::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.project();

        this.inner.poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: I) -> Result<(), Self::Error> {
        let this = self.project();

        this.inner.start_send(item.into())
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.project();

        this.inner.poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.project();

        this.inner.poll_close(cx)
    }
}

pin_project_lite::pin_project! {
    /// Future that will read and process all incoming RTCP packets.
    struct RtcpReceiver<T> {
        #[pin]
        stream: T,
        context: RtcpContext,
    }
}

impl<T, E> Future for RtcpReceiver<T>
where
    T: Stream<Item = Result<CompoundRtcpPacket, E>>,
{
    type Output = Result<(), E>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();

        while let Poll::Ready(ready) = this.stream.as_mut().poll_next(cx) {
            if let Some(packet) = ready.transpose()? {
                this.context.process_incoming_rtcp_packet(&packet);
            } else {
                return Poll::Ready(Ok(()));
            }
        }

        Poll::Pending
    }
}

pin_project_lite::pin_project! {
    /// Future responsible for generating and sending RTCP packets.
    struct RtcpSender<T> {
        #[pin]
        sink: T,
        context: RtcpSenderContext,
    }
}

impl<T> Future for RtcpSender<T>
where
    T: Sink<CompoundRtcpPacket>,
{
    type Output = Result<(), T::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();

        while let Poll::Ready(ready) = this.context.poll_next_packet(cx) {
            if let Some(packet) = ready {
                let poll = this.sink.as_mut().poll_ready(cx)?;

                if poll.is_ready() {
                    this.context.process_outgoing_rtcp_packet(&packet);
                    this.sink.as_mut().start_send(packet)?;
                } else {
                    // save the packet for later
                    this.context.push_back_packet(packet);

                    // ... and return immediately
                    return Poll::Pending;
                }
            } else {
                return this.sink.poll_close(cx);
            }
        }

        // make sure that we drive the sink forward
        let _ = this.sink.poll_flush(cx);

        Poll::Pending
    }
}

/// RTCP sender context.
struct RtcpSenderContext {
    context: RtcpContext,
    close_rx: Option<oneshot::Receiver<()>>,
    pending: Option<CompoundRtcpPacket>,
}

impl RtcpSenderContext {
    /// Process a given outgoing RTCP packet.
    fn process_outgoing_rtcp_packet(&mut self, packet: &CompoundRtcpPacket) {
        self.context.process_outgoing_rtcp_packet(packet);
    }

    /// Poll the next RTCP packet.
    fn poll_next_packet(&mut self, cx: &mut Context) -> Poll<Option<CompoundRtcpPacket>> {
        if let Some(close_rx) = self.close_rx.as_mut() {
            if close_rx.poll_unpin(cx).is_ready() {
                // TODO
                // self.pending = Some(BYE);
                self.close_rx = None;
            }
        }

        if let Some(packet) = self.pending.take() {
            Poll::Ready(Some(packet))
        } else if self.close_rx.is_none() {
            Poll::Ready(None)
        } else {
            // TODO

            Poll::Pending
        }
    }

    /// Push back a given packet that was not sent.
    ///
    /// The packet will be returned next time the `poll_next_packet` method is
    /// called.
    fn push_back_packet(&mut self, packet: CompoundRtcpPacket) {
        self.pending = Some(packet);
    }
}

/// RTCP context.
#[derive(Clone)]
struct RtcpContext {
    inner: Arc<Mutex<InnerRtcpContext>>,
}

impl RtcpContext {
    /// Create a new RTCP context.
    fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(InnerRtcpContext::new())),
        }
    }

    /// Process a given incoming RTP packet.
    fn process_incoming_rtp_packet(&mut self, packet: &RtpPacket) {
        self.inner
            .lock()
            .unwrap()
            .process_incoming_rtp_packet(packet);
    }

    /// Process a given incoming RTCP packet.
    fn process_incoming_rtcp_packet(&mut self, packet: &CompoundRtcpPacket) {
        self.inner
            .lock()
            .unwrap()
            .process_incoming_rtcp_packet(packet);
    }

    /// Process a given outgoing RTP packet.
    fn process_outgoing_rtp_packet(&mut self, packet: &RtpPacket) {
        self.inner
            .lock()
            .unwrap()
            .process_outgoing_rtp_packet(packet);
    }

    /// Process a given outgoing RTCP packet.
    fn process_outgoing_rtcp_packet(&mut self, packet: &CompoundRtcpPacket) {
        self.inner
            .lock()
            .unwrap()
            .process_outgoing_rtcp_packet(packet);
    }
}

/// Inner context.
struct InnerRtcpContext {}

impl InnerRtcpContext {
    /// Create a new context.
    fn new() -> Self {
        Self {}
    }

    /// Process a given incoming RTP packet.
    fn process_incoming_rtp_packet(&mut self, _: &RtpPacket) {
        // TODO
    }

    /// Process a given incoming RTCP packet.
    fn process_incoming_rtcp_packet(&mut self, _: &CompoundRtcpPacket) {
        // TODO
    }

    /// Process a given outgoing RTP packet.
    fn process_outgoing_rtp_packet(&mut self, _: &RtpPacket) {
        // TODO
    }

    /// Process a given outgoing RTCP packet.
    fn process_outgoing_rtcp_packet(&mut self, _: &CompoundRtcpPacket) {
        // TODO
    }
}
