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

impl<T, P, E> Stream for RtcpHandler<T>
where
    T: Stream<Item = Result<P, E>>,
{
    type Item = Result<P, E>;

    #[inline]
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();

        this.stream.poll_next(cx)
    }
}

impl<T, P, E> Sink<P> for RtcpHandler<T>
where
    T: Sink<P, Error = E>,
{
    type Error = E;

    #[inline]
    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.project();

        this.stream.poll_ready(cx)
    }

    #[inline]
    fn start_send(self: Pin<&mut Self>, packet: P) -> Result<(), Self::Error> {
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

            let res = ready!(SinkExt::<RtpPacket>::poll_ready_unpin(&mut self.inner, cx));

            if res.is_ok() {
                return Poll::Ready(Ok(()));
            } else {
                self.sink_error = true;
            }
        }
    }

    fn start_send(mut self: Pin<&mut Self>, item: RtpPacket) -> Result<(), Self::Error> {
        let res = SinkExt::<RtpPacket>::start_send_unpin(&mut self.inner, item);

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

            let res = ready!(SinkExt::<RtpPacket>::poll_flush_unpin(&mut self.inner, cx));

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

            let res = ready!(SinkExt::<RtpPacket>::poll_close_unpin(&mut self.inner, cx));

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

            let closed = self.context.poll_closed(cx);

            if closed.is_pending() {
                ready!(self.interval.poll_tick(cx));
            }

            let packets = self.context.create_rtcp_reports();

            if packets.is_empty() {
                return Poll::Ready(None);
            }

            self.output.extend(packets);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        convert::Infallible,
        pin::Pin,
        sync::{Arc, Mutex},
        task::{Context, Poll},
        time::{Duration, Instant},
    };

    use futures::{channel::mpsc, Sink, SinkExt, Stream, StreamExt};

    use super::{MuxedRtcpHandler, RtcpHandler, RtcpHandlerOptions, StreamSink};

    use crate::{
        rtcp::{RtcpContext, RtcpPacketType},
        rtp::{IncomingRtpPacket, RtpPacket},
        transceiver::{DefaultRtpTransceiver, RtpTransceiver, RtpTransceiverOptions, SSRCMode},
        utils::OrderedRtpPacket,
        PacketMux,
    };

    fn make_rtp_packet(ssrc: u32, seq: u16, timestamp: u32) -> RtpPacket {
        RtpPacket::new()
            .with_ssrc(ssrc)
            .with_sequence_number(seq)
            .with_timestamp(timestamp)
    }

    /// Helper stream-sink for testing.
    #[derive(Clone)]
    struct RtcpTestChannel<I, O> {
        inner: Arc<Mutex<InnerRtcpTestChannel<I, O>>>,
    }

    impl<I, O> RtcpTestChannel<I, O> {
        /// Create a new RTCP test channel.
        fn new<T>(input: T) -> Self
        where
            T: IntoIterator<Item = I>,
        {
            Self {
                inner: Arc::new(Mutex::new(InnerRtcpTestChannel::new(input))),
            }
        }
    }

    impl<I, O> Stream for RtcpTestChannel<I, O> {
        type Item = Result<I, Infallible>;

        fn poll_next(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            let mut inner = self.inner.lock().unwrap();

            if let Some(packet) = inner.input.pop_front() {
                Poll::Ready(Some(Ok(packet)))
            } else {
                Poll::Pending
            }
        }
    }

    impl<I, O> Sink<O> for RtcpTestChannel<I, O> {
        type Error = Infallible;

        fn poll_ready(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn start_send(self: Pin<&mut Self>, packet: O) -> Result<(), Self::Error> {
            let mut inner = self.inner.lock().unwrap();
            inner.output.push(packet);

            Ok(())
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            self.inner.lock().unwrap().closed = true;

            Poll::Ready(Ok(()))
        }
    }

    /// Inner RTCP test channel.
    struct InnerRtcpTestChannel<I, O> {
        input: VecDeque<I>,
        output: Vec<O>,
        closed: bool,
    }

    impl<I, O> InnerRtcpTestChannel<I, O> {
        /// Create a new inner RTCP test channel.
        fn new<T>(input: T) -> Self
        where
            T: IntoIterator<Item = I>,
        {
            Self {
                input: VecDeque::from_iter(input),
                output: Vec::new(),
                closed: false,
            }
        }
    }

    /// Test transceiver for muxed RTP-RTCP streams.
    #[derive(Clone)]
    struct MuxedTestTransceiver {
        inner: Arc<Mutex<InnerMuxedTestTransceiver>>,
    }

    impl MuxedTestTransceiver {
        /// Create a new muxed RTP-RTCP test transceiver.
        fn new<T>(input: T, options: RtpTransceiverOptions) -> Self
        where
            T: IntoIterator<Item = PacketMux>,
        {
            let inner = InnerMuxedTestTransceiver::new(input, options);

            Self {
                inner: Arc::new(Mutex::new(inner)),
            }
        }
    }

    impl Stream for MuxedTestTransceiver {
        type Item = Result<PacketMux, Infallible>;

        fn poll_next(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            let mut inner = self.inner.lock().unwrap();

            if let Some(packet) = inner.inner.input.pop_front() {
                let packet = if let PacketMux::Rtp(packet) = packet {
                    let index = packet.sequence_number() as u64;

                    let now = Instant::now();
                    let incoming = IncomingRtpPacket::new(packet, now);
                    let ordered = OrderedRtpPacket::new(incoming, index);

                    inner.context.process_incoming_rtp_packet(&ordered);
                    inner.context.process_ordered_rtp_packet(&ordered);

                    PacketMux::Rtp(ordered.into())
                } else {
                    packet
                };

                Poll::Ready(Some(Ok(packet)))
            } else {
                Poll::Ready(None)
            }
        }
    }

    impl Sink<PacketMux> for MuxedTestTransceiver {
        type Error = Infallible;

        fn poll_ready(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn start_send(self: Pin<&mut Self>, packet: PacketMux) -> Result<(), Self::Error> {
            let mut inner = self.inner.lock().unwrap();

            if let PacketMux::Rtp(packet) = &packet {
                inner.context.process_outgoing_rtp_packet(packet);
            }

            inner.inner.output.push(packet);

            Ok(())
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            let mut inner = self.inner.lock().unwrap();

            inner.inner.closed = true;

            Poll::Ready(Ok(()))
        }
    }

    impl RtpTransceiver for MuxedTestTransceiver {
        fn rtcp_context(&self) -> crate::rtcp::RtcpContextHandle {
            let inner = self.inner.lock().unwrap();

            inner.context.handle()
        }
    }

    /// Inner muxed RTP-RTCP test transceiver.
    struct InnerMuxedTestTransceiver {
        inner: InnerRtcpTestChannel<PacketMux, PacketMux>,
        context: RtcpContext,
    }

    impl InnerMuxedTestTransceiver {
        /// Create a new inner muxed RTP-RTCP test transceiver.
        fn new<T>(input: T, options: RtpTransceiverOptions) -> Self
        where
            T: IntoIterator<Item = PacketMux>,
        {
            Self {
                inner: InnerRtcpTestChannel::new(input),
                context: RtcpContext::new(options),
            }
        }
    }

    #[tokio::test]
    async fn test_handler_task_termination() {
        let (mut incoming_rtp_tx, incoming_rtp_rx) =
            mpsc::unbounded::<Result<RtpPacket, Infallible>>();
        let (outgoing_rtp_tx, outgoing_rtp_rx) = mpsc::unbounded::<RtpPacket>();

        let rtp = StreamSink::new(incoming_rtp_rx, outgoing_rtp_tx);

        let options = RtpTransceiverOptions::new()
            .with_default_clock_rate(1000)
            .with_primary_sender_ssrc(0)
            .with_input_ssrc_mode(SSRCMode::Any);

        let rtp = DefaultRtpTransceiver::<_, Infallible>::new(rtp, options);

        let rtcp = RtcpTestChannel::new([]);

        let options = RtcpHandlerOptions::new()
            .with_ignore_decoding_errors(true)
            .with_rtcp_report_interval(Duration::from_millis(100));

        let handler = RtcpHandler::new(rtp, rtcp.clone(), options);

        let handler = tokio::spawn(async move { handler.collect::<Vec<_>>().await });

        incoming_rtp_tx
            .send(Ok(make_rtp_packet(1, 1, 100)))
            .await
            .unwrap();
        incoming_rtp_tx.close().await.unwrap();

        let incoming_rtp_packets = handler.await.unwrap();

        std::mem::drop(outgoing_rtp_rx);

        assert_eq!(incoming_rtp_packets.len(), 1);

        let packet = incoming_rtp_packets.into_iter().next().unwrap().unwrap();

        assert_eq!(packet.ssrc(), 1);
        assert_eq!(packet.sequence_number(), 1);
        assert_eq!(packet.timestamp(), 100);

        let wait_for_close = async {
            while Arc::strong_count(&rtcp.inner) > 1 {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        };

        tokio::time::timeout(Duration::from_secs(1), wait_for_close)
            .await
            .expect("RTCP handler tasks have not terminated");

        // once we reach here, both RTCP handler tasks are already terminated
        let rtcp = Arc::try_unwrap(rtcp.inner)
            .ok()
            .unwrap()
            .into_inner()
            .ok()
            .unwrap();

        assert!(rtcp.closed);

        assert_eq!(rtcp.output.len(), 1);

        let report = &rtcp.output[0];

        assert_eq!(report.len(), 3);

        let rr = &report[0];
        let sdes = &report[1];
        let bye = &report[2];

        assert_eq!(rr.packet_type(), RtcpPacketType::RR);
        assert_eq!(sdes.packet_type(), RtcpPacketType::SDES);
        assert_eq!(bye.packet_type(), RtcpPacketType::BYE);
    }

    #[tokio::test]
    async fn test_muxed_handler_task_termination() {
        let options = RtpTransceiverOptions::new()
            .with_default_clock_rate(1000)
            .with_primary_sender_ssrc(0)
            .with_input_ssrc_mode(SSRCMode::Any);

        let packet = PacketMux::Rtp(make_rtp_packet(1, 1, 100));

        let muxed = MuxedTestTransceiver::new([packet], options);

        let options = RtcpHandlerOptions::new()
            .with_ignore_decoding_errors(true)
            .with_rtcp_report_interval(Duration::from_millis(100));

        let handler = MuxedRtcpHandler::new(muxed.clone(), options);

        let handler = tokio::spawn(async move { handler.collect::<Vec<_>>().await });

        let incoming_rtp_packets = handler.await.unwrap();

        assert_eq!(incoming_rtp_packets.len(), 1);

        let packet = incoming_rtp_packets.into_iter().next().unwrap().unwrap();

        assert_eq!(packet.ssrc(), 1);
        assert_eq!(packet.sequence_number(), 1);
        assert_eq!(packet.timestamp(), 100);

        let wait_for_close = async {
            while Arc::strong_count(&muxed.inner) > 1 {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        };

        tokio::time::timeout(Duration::from_secs(1), wait_for_close)
            .await
            .expect("RTCP handler tasks have not terminated");

        // once we reach here, all RTCP handler tasks are already terminated
        let muxed = Arc::try_unwrap(muxed.inner)
            .ok()
            .unwrap()
            .into_inner()
            .ok()
            .unwrap();

        assert!(muxed.inner.closed);

        assert_eq!(muxed.inner.output.len(), 1);

        let PacketMux::Rtcp(report) = &muxed.inner.output[0] else {
            panic!("expected RTCP packet");
        };

        assert_eq!(report.len(), 3);

        let rr = &report[0];
        let sdes = &report[1];
        let bye = &report[2];

        assert_eq!(rr.packet_type(), RtcpPacketType::RR);
        assert_eq!(sdes.packet_type(), RtcpPacketType::SDES);
        assert_eq!(bye.packet_type(), RtcpPacketType::BYE);
    }
}
