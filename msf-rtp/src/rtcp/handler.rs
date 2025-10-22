use std::{
    collections::VecDeque,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::{Duration, Instant},
};

use futures::{channel::mpsc, ready, FutureExt, Sink, SinkExt, Stream, StreamExt};
use tokio::{
    task::JoinHandle,
    time::{Interval, MissedTickBehavior},
};

use crate::{
    rtcp::{ByePacket, ReceiverReport, RtcpContextHandle, RtcpPacketType, SenderReport},
    transceiver::RtpTransceiver,
    CompoundRtcpPacket, InvalidInput, PacketMux, RtpPacket,
};

/// RTCP handler options.
#[derive(Copy, Clone)]
pub struct RtcpHandlerOptions {
    rtcp_report_interval: Duration,
    ignore_decoding_errors: bool,
}

impl RtcpHandlerOptions {
    /// Create new RTCP handler options with default values.
    #[inline]
    pub const fn new() -> Self {
        Self {
            rtcp_report_interval: Duration::from_secs(5),
            ignore_decoding_errors: true,
        }
    }

    /// Get the RTCP report interval.
    #[inline]
    pub const fn rtcp_report_interval(&self) -> Duration {
        self.rtcp_report_interval
    }

    /// Set the RTCP report interval.
    ///
    /// RTCP reports will be generated every `interval` seconds. The default
    /// value is 5 seconds.
    #[inline]
    pub const fn with_rtcp_report_interval(mut self, interval: Duration) -> Self {
        self.rtcp_report_interval = interval;
        self
    }

    /// Check if RTCP decoding errors should be ignored.
    #[inline]
    pub const fn ignore_decoding_errors(&self) -> bool {
        self.ignore_decoding_errors
    }

    /// Set whether RTCP decoding errors should be ignored.
    ///
    /// If true, decoding errors will be ignored and the invalid packets
    /// will be silently dropped. If false, the RTCP handler will stop
    /// processing incoming RTCP packets on the first decoding error. The
    /// default value is true.
    #[inline]
    pub const fn with_ignore_decoding_errors(mut self, ignore: bool) -> Self {
        self.ignore_decoding_errors = ignore;
        self
    }
}

impl Default for RtcpHandlerOptions {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

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
    ///
    /// The handler will use the RTCP context provided by the RTP transceiver.
    pub fn new<U, E>(rtp: T, rtcp: U, options: RtcpHandlerOptions) -> Self
    where
        T: RtpTransceiver,
        U: Send + 'static,
        U: Stream<Item = Result<CompoundRtcpPacket, E>>,
        U: Sink<CompoundRtcpPacket>,
    {
        let rtcp_context = rtp.rtcp_context();

        Self::new_with_rtcp_context(rtp, rtcp, rtcp_context, options)
    }

    /// Create a new RTCP handler with a given RTCP context.
    pub fn new_with_rtcp_context<U, E>(
        rtp: T,
        rtcp: U,
        rtcp_context: RtcpContextHandle,
        options: RtcpHandlerOptions,
    ) -> Self
    where
        U: Send + 'static,
        U: Stream<Item = Result<CompoundRtcpPacket, E>>,
        U: Sink<CompoundRtcpPacket>,
    {
        let (rtcp_tx, rtcp_rx) = rtcp.split();

        let sender = send_rtcp_reports(
            rtcp_tx,
            rtcp_context.clone(),
            options.rtcp_report_interval(),
        );

        // NOTE: This task will run as long as the RtcpContext is generating
        //   RTCP reports. It stops when the context is closed. Therefore, we
        //   close the context when the handler is dropped.
        tokio::spawn(async move {
            let _ = sender.await;
        });

        let receiver = RtcpReceiver::new(
            rtcp_rx,
            rtcp_context.clone(),
            options.ignore_decoding_errors(),
        );

        // NOTE: This task will be terminated when the handler is dropped.
        let receiver = tokio::spawn(async move {
            let _ = receiver.await;
        });

        Self {
            stream: rtp,
            context: RtcpHandlerContext {
                context: rtcp_context,
                receiver,
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

        this.stream.poll_next(cx)
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
    context: RtcpContextHandle,
    receiver: JoinHandle<()>,
}

impl Drop for RtcpHandlerContext {
    fn drop(&mut self) {
        // generate final RTCP reports including BYE packets
        self.context.close();

        // stop the RTCP receiver
        self.receiver.abort();
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
    pub fn new<T>(stream: T, options: RtcpHandlerOptions) -> Self
    where
        T: Send + 'static,
        T: Stream<Item = Result<PacketMux, E>>,
        T: Sink<PacketMux, Error = E>,
        T: RtpTransceiver,
        E: Send + 'static,
    {
        let rtcp_context = stream.rtcp_context();

        let (muxed_tx, mut muxed_rx) = stream.split();

        let (mut input_rtp_tx, input_rtp_rx) = mpsc::channel::<Result<_, E>>(4);
        let (output_rtp_tx, output_rtp_rx) = mpsc::channel(4);
        let (mut input_rtcp_tx, input_rtcp_rx) = mpsc::channel::<Result<_, E>>(4);
        let (output_rtcp_tx, output_rtcp_rx) = mpsc::channel(4);

        let output_rtp_tx = PacketMuxer::new(output_rtp_tx);
        let output_rtcp_tx = PacketMuxer::new(output_rtcp_tx);

        let rtp = StreamSink::new(input_rtp_rx, output_rtp_tx);
        let rtcp = StreamSink::new(input_rtcp_rx, output_rtcp_tx);

        // NOTE: This task will be terminated when the handler is dropped.
        let reader = tokio::spawn(async move {
            let mut run = true;

            while run {
                let next = muxed_rx.next().await;

                run = matches!(next, Some(Ok(_)));

                let _ = match next {
                    Some(Ok(PacketMux::Rtp(packet))) => input_rtp_tx.send(Ok(packet)).await,
                    Some(Ok(PacketMux::Rtcp(packet))) => input_rtcp_tx.send(Ok(packet)).await,
                    Some(Err(err)) => input_rtp_tx.send(Err(err)).await,
                    _ => Ok(()),
                };
            }
        });

        // NOTE: This task will run as long as the `output_rtp_rx` and
        //   `output_rtcp_rx` are open. These channels will be closed when the
        //   inner handler is dropped.
        let writer = tokio::spawn(async move {
            futures::stream::select(output_rtp_rx, output_rtcp_rx)
                .map(Ok)
                .forward(muxed_tx)
                .await
        });

        Self {
            inner: RtcpHandler::new_with_rtcp_context(rtp, rtcp, rtcp_context, options),
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

    fn start_send(mut self: Pin<&mut Self>, item: RtpPacket) -> Result<(), Self::Error> {
        let res = self.inner.start_send_unpin(item);

        // we cannot get the actual error here, it needs to be polled out from
        // the writer
        if res.is_err() {
            self.sink_error = true;
        }

        Ok(())
    }

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
        context: RtcpReceiverContext,
        ignore_decoding_errors: bool,
    }
}

impl<T> RtcpReceiver<T> {
    /// Create a new RTCP receiver.
    fn new(stream: T, context: RtcpContextHandle, ignore_decoding_errors: bool) -> Self {
        Self {
            stream,
            context: RtcpReceiverContext::new(context),
            ignore_decoding_errors,
        }
    }
}

impl<T, E> Future for RtcpReceiver<T>
where
    T: Stream<Item = Result<CompoundRtcpPacket, E>>,
{
    type Output = Result<(), RtcpReceiverError<E>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();

        loop {
            let stream = this.stream.as_mut();

            match ready!(stream.poll_next(cx)) {
                Some(Ok(packet)) => {
                    if let Err(err) = this.context.process_incoming_rtcp_packet(&packet) {
                        if !*this.ignore_decoding_errors {
                            return Poll::Ready(Err(err.into()));
                        }
                    }
                }
                Some(Err(err)) => return Poll::Ready(Err(RtcpReceiverError::Other(err))),
                None => return Poll::Ready(Ok(())),
            }
        }
    }
}

/// RTCP receiver context.
struct RtcpReceiverContext {
    context: RtcpContextHandle,
}

impl RtcpReceiverContext {
    /// Create a new RTCP receiver context.
    fn new(context: RtcpContextHandle) -> Self {
        Self { context }
    }

    /// Process a given incoming RTCP packet.
    fn process_incoming_rtcp_packet(
        &mut self,
        packet: &CompoundRtcpPacket,
    ) -> Result<(), InvalidInput> {
        for packet in packet.iter() {
            match packet.packet_type() {
                RtcpPacketType::SR => {
                    self.context
                        .process_incoming_sender_report(&SenderReport::decode(packet)?);
                }
                RtcpPacketType::RR => {
                    self.context
                        .process_incoming_receiver_report(&ReceiverReport::decode(packet)?);
                }
                RtcpPacketType::BYE => {
                    self.context
                        .process_incoming_bye_packet(&ByePacket::decode(packet)?);
                }
                _ => (),
            }
        }

        Ok(())
    }
}

/// Internal RTCP receiver error.
enum RtcpReceiverError<E> {
    InvalidInput,
    Other(E),
}

impl<E> From<InvalidInput> for RtcpReceiverError<E> {
    fn from(_: InvalidInput) -> Self {
        Self::InvalidInput
    }
}

/// Generate and send RTCP reports at regular intervals.
///
/// The returned future completes once there are no more RTCP reports to send
/// and the sink has been flushed and closed.
async fn send_rtcp_reports<T>(
    sink: T,
    context: RtcpContextHandle,
    rtcp_report_interval: Duration,
) -> Result<(), T::Error>
where
    T: Sink<CompoundRtcpPacket>,
{
    RtcpOutputStream::new(context, rtcp_report_interval)
        .map(Ok)
        .forward(sink)
        .await
}

/// Stream of outgoing RTCP packets.
struct RtcpOutputStream {
    interval: Interval,
    context: RtcpContextHandle,
    output: VecDeque<CompoundRtcpPacket>,
}

impl RtcpOutputStream {
    /// Create a new stream that will generate RTCP reports at regular
    /// intervals.
    fn new(context: RtcpContextHandle, rtcp_report_interval: Duration) -> Self {
        let start = Instant::now() + (rtcp_report_interval / 2);

        let mut interval = tokio::time::interval_at(start.into(), rtcp_report_interval);

        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        Self {
            interval,
            context,
            output: VecDeque::new(),
        }
    }
}

impl Stream for RtcpOutputStream {
    type Item = CompoundRtcpPacket;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            if let Some(packet) = self.output.pop_front() {
                return Poll::Ready(Some(packet));
            }

            ready!(self.interval.poll_tick(cx));

            let packets = self.context.create_rtcp_reports();

            if packets.is_empty() {
                return Poll::Ready(None);
            }

            self.output.extend(packets);
        }
    }
}
