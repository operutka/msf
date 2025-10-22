//! RTP transceiver.

use std::{
    collections::{HashMap, VecDeque},
    convert::Infallible,
    ops::{Deref, DerefMut},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Instant,
};

use futures::{ready, Sink, Stream};

use crate::{
    rtcp::{RtcpContext, RtcpContextHandle},
    rtp::{IncomingRtpPacket, RtpPacket},
    utils::{OrderedRtpPacket, ReorderingError, ReorderingMultiBuffer},
};

/// RTP packet transceiver.
pub trait RtpTransceiver {
    /// Get the transceiver's RTCP context.
    ///
    /// The transceiver is responsible for feeding the RTCP context with
    /// incoming and outgoing RTP packets. This happens internally. The RTCP
    /// context can be used then to generate RTCP reports and process incoming
    /// RTCP packets.
    fn rtcp_context(&self) -> RtcpContextHandle;
}

/// SSRC handling mode.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum SSRCMode {
    /// Ignore incoming SSRCs and treat all packets as belonging to a single
    /// SSRC.
    ///
    /// This mode is useful when dealing with buggy peers that change SSRCs
    /// unexpectedly. The receiver reports will use the last seen SSRC.
    Ignore,

    /// Accept packets with any SSRC.
    Any,

    /// Accept packets only from specific SSRCs.
    Specific,
}

/// SSRC to clock rate mapping.
#[derive(Clone)]
pub struct SSRC2ClockRate {
    inner: HashMap<u32, u32>,
}

impl SSRC2ClockRate {
    /// Create an empty mapping.
    fn new() -> Self {
        Self {
            inner: HashMap::new(),
        }
    }

    /// Create a mapping from a given iterator of `(ssrc, clock_rate)` tuples.
    fn from_iter<T>(items: T) -> Self
    where
        T: IntoIterator<Item = (u32, u32)>,
    {
        Self {
            inner: HashMap::from_iter(items),
        }
    }

    /// Get the number of SSRCs in the mapping.
    #[inline]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Get the clock rate for a given SSRC.
    #[inline]
    pub fn clock_rate(&self, ssrc: u32) -> Option<u32> {
        self.inner.get(&ssrc).copied()
    }

    /// Check if the mapping contains a given SSRC.
    #[inline]
    pub fn contains(&self, ssrc: u32) -> bool {
        self.inner.contains_key(&ssrc)
    }

    /// Get an iterator over all `(ssrc, clock_rate)` pairs within the mapping.
    pub fn iter(&self) -> impl Iterator<Item = (u32, u32)> + use<'_> {
        self.inner
            .iter()
            .map(|(&ssrc, &clock_rate)| (ssrc, clock_rate))
    }
}

/// RTP transceiver options.
#[derive(Clone)]
pub struct RtpTransceiverOptions {
    inner: ArcInnerTransceiverOptions,
}

impl RtpTransceiverOptions {
    /// Create new options.
    pub fn new() -> Self {
        Self {
            inner: ArcInnerTransceiverOptions::new(InnerTransceiverOptions::new()),
        }
    }

    /// Get the primary sender SSRC.
    #[inline]
    pub fn primary_sender_ssrc(&self) -> u32 {
        self.inner.primary_sender_ssrc
    }

    /// Set the primary sender SSRC.
    ///
    /// This SSRC will be used as the sender SSRC for RTCP reception reports.
    /// The default value is random.
    pub fn with_primary_sender_ssrc(mut self, ssrc: u32) -> Self {
        self.inner.primary_sender_ssrc = ssrc;
        self
    }

    /// Get depth of the reordering buffer for incoming RTP packets.
    #[inline]
    pub fn reordering_buffer_depth(&self) -> usize {
        self.inner.reordering_buffer_depth
    }

    /// Set depth of the reordering buffer for incoming RTP packets.
    ///
    /// The default value is 64.
    pub fn with_reordering_buffer_depth(mut self, depth: usize) -> Self {
        self.inner.reordering_buffer_depth = depth;
        self
    }

    /// Get the default clock rate for SSRCs without an explicit clock rate.
    #[inline]
    pub fn default_clock_rate(&self) -> u32 {
        self.inner.default_clock_rate
    }

    /// Set the default clock rate for SSRCs without an explicit clock rate.
    ///
    /// This clock rate will be used when creating sender and receiver reports
    /// for SSRCs where the clock rate is not known. The default value is
    /// 90000.
    pub fn with_default_clock_rate(mut self, clock_rate: u32) -> Self {
        self.inner.default_clock_rate = clock_rate;
        self
    }

    /// Get the input SSRC handling mode.
    #[inline]
    pub fn input_ssrc_mode(&self) -> SSRCMode {
        self.inner.input_ssrc_mode
    }

    /// Set the input SSRC handling mode.
    ///
    /// The default mode is `SSRCMode::Any`.
    pub fn with_input_ssrc_mode(mut self, mode: SSRCMode) -> Self {
        self.inner.input_ssrc_mode = mode;
        self
    }

    /// Get the maximum number of input SSRCs to track.
    #[inline]
    pub fn max_input_ssrcs(&self) -> Option<usize> {
        self.inner.max_input_ssrcs
    }

    /// Set the maximum number of input SSRCs to track.
    ///
    /// This option is valid only when `input_ssrc_mode` is set to
    /// `SSRCMode::Any`. Setting this option to `None` will allow unlimited
    /// number of SSRCs. This should be used with caution as it may lead to
    /// excessive memory usage. The default limit is 64 SSRCs.
    ///
    /// If there are more SSRCs than the limit, the least recently used SSRCs
    /// will be dropped first.
    pub fn with_max_input_ssrcs(mut self, max: Option<usize>) -> Self {
        self.inner.max_input_ssrcs = max;
        self
    }

    /// Get the input SSRC to clock rate mapping.
    #[inline]
    pub fn input_ssrcs(&self) -> &SSRC2ClockRate {
        &self.inner.input_ssrcs
    }

    /// Set the expected input SSRCs along with their clock rates.
    ///
    /// The clock rate is used for generating RTCP receiver reports. The method
    /// accepts an iterator of `(ssrc, clock_rate)` tuples.
    ///
    /// Note that if the clock rate for a given SSRC is not specified here, the
    /// default clock rate will be used instead when generating receiver
    /// reports. This may lead to incorrect reports if the actual clock rate
    /// differs from the default one.
    pub fn with_input_ssrcs<T>(mut self, ssrcs: T) -> Self
    where
        T: IntoIterator<Item = (u32, u32)>,
    {
        self.inner.input_ssrcs = SSRC2ClockRate::from_iter(ssrcs);
        self
    }

    /// Get the output SSRC to clock rate mapping.
    #[inline]
    pub fn output_ssrcs(&self) -> &SSRC2ClockRate {
        &self.inner.output_ssrcs
    }

    /// Set the output SSRCs along with their clock rates.
    ///
    /// The clock rate is used for generating RTCP sender reports. The method
    /// accepts an iterator of `(ssrc, clock_rate)` tuples.
    ///
    /// Note that if the clock rate for a given SSRC is not specified here, the
    /// default clock rate will be used instead when generating sender reports.
    /// This may lead to incorrect reports if the actual clock rate differs
    /// from the default one.
    pub fn with_output_ssrcs<T>(mut self, ssrcs: T) -> Self
    where
        T: IntoIterator<Item = (u32, u32)>,
    {
        self.inner.output_ssrcs = SSRC2ClockRate::from_iter(ssrcs);
        self
    }

    /// Get the maximum RTCP packet size.
    #[inline]
    pub fn max_rtcp_packet_size(&self) -> usize {
        self.inner.max_rtcp_packet_size
    }

    /// Set the maximum RTCP packet size.
    ///
    /// Limiting the maximum RTCP packet size helps avoid IP packet
    /// fragmentation. The default limit is 1200 bytes. This should be safe for
    /// UDP transport in IPv4/IPv6 networks with typical MTU sizes in the
    /// Internet environment.
    pub fn with_max_rtcp_packet_size(mut self, size: usize) -> Self {
        self.inner.max_rtcp_packet_size = size;
        self
    }
}

impl Default for RtpTransceiverOptions {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

/// Helper type for shared transceiver options.
///
/// It implements copy-on-write semantics.
#[derive(Clone)]
struct ArcInnerTransceiverOptions {
    inner: Arc<InnerTransceiverOptions>,
}

impl ArcInnerTransceiverOptions {
    /// Create shared transceiver options.
    fn new(inner: InnerTransceiverOptions) -> Self {
        Self {
            inner: Arc::new(inner),
        }
    }
}

impl Deref for ArcInnerTransceiverOptions {
    type Target = InnerTransceiverOptions;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for ArcInnerTransceiverOptions {
    fn deref_mut(&mut self) -> &mut Self::Target {
        Arc::make_mut(&mut self.inner)
    }
}

/// Inner transceiver options.
#[derive(Clone)]
struct InnerTransceiverOptions {
    primary_sender_ssrc: u32,
    reordering_buffer_depth: usize,
    default_clock_rate: u32,
    input_ssrc_mode: SSRCMode,
    max_input_ssrcs: Option<usize>,
    input_ssrcs: SSRC2ClockRate,
    output_ssrcs: SSRC2ClockRate,
    max_rtcp_packet_size: usize,
}

impl InnerTransceiverOptions {
    /// Create new inner options.
    fn new() -> Self {
        Self {
            primary_sender_ssrc: rand::random(),
            reordering_buffer_depth: 64,
            default_clock_rate: 90000,
            input_ssrc_mode: SSRCMode::Any,
            max_input_ssrcs: Some(64),
            input_ssrcs: SSRC2ClockRate::new(),
            output_ssrcs: SSRC2ClockRate::new(),
            max_rtcp_packet_size: 1200,
        }
    }
}

pin_project_lite::pin_project! {
    /// Default RTP transceiver implementation.
    pub struct DefaultRtpTransceiver<T, E = Infallible> {
        #[pin]
        inner: T,
        context: TransceiverContext,
        error: Option<E>,
        eof: bool,
    }
}

impl<T, E> DefaultRtpTransceiver<T, E> {
    /// Create a new RTP packet receiver.
    pub fn new(stream: T, options: RtpTransceiverOptions) -> Self {
        Self {
            inner: stream,
            context: TransceiverContext::new(options),
            error: None,
            eof: false,
        }
    }
}

impl<T, E> Stream for DefaultRtpTransceiver<T, E>
where
    T: Stream<Item = Result<RtpPacket, E>>,
{
    type Item = Result<OrderedRtpPacket, E>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();

        loop {
            if let Some(packet) = this.context.poll_next_ordered_packet() {
                return Poll::Ready(Some(Ok(packet)));
            }

            let inner = this.inner.as_mut();

            if !*this.eof {
                let ready = if this.context.end_of_stream() {
                    None
                } else {
                    ready!(inner.poll_next(cx))
                };

                match ready {
                    Some(Ok(packet)) => this.context.process_incoming_packet(packet),
                    other => {
                        if let Some(Err(err)) = other {
                            *this.error = Some(err);
                        }

                        *this.eof = true;
                    }
                }
            } else if let Some(packet) = this.context.take_next_ordered_packet() {
                return Poll::Ready(Some(Ok(packet)));
            } else if let Some(err) = this.error.take() {
                return Poll::Ready(Some(Err(err)));
            } else {
                return Poll::Ready(None);
            }
        }
    }
}

impl<T, E> Sink<RtpPacket> for DefaultRtpTransceiver<T, E>
where
    T: Sink<RtpPacket>,
{
    type Error = T::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.project();

        ready!(this.inner.poll_ready(cx))?;

        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, packet: RtpPacket) -> Result<(), Self::Error> {
        let this = self.project();

        this.context.process_outgoing_packet(&packet);

        this.inner.start_send(packet)?;

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

        this.context.close();

        Poll::Ready(Ok(()))
    }
}

impl<T, E> RtpTransceiver for DefaultRtpTransceiver<T, E> {
    fn rtcp_context(&self) -> RtcpContextHandle {
        self.context.rtcp_context()
    }
}

/// RTP transceiver context.
struct TransceiverContext {
    options: RtpTransceiverOptions,
    rtcp: RtcpContext,
    buffer: ReorderingMultiBuffer,
    output: VecDeque<OrderedRtpPacket>,
}

impl TransceiverContext {
    /// Create a new RTP receiver context.
    fn new(options: RtpTransceiverOptions) -> Self {
        let input_ssrcs = options.input_ssrcs();
        let expected_ssrcs = input_ssrcs.len();

        let max_input_ssrcs = options.max_input_ssrcs().map(|max| max.max(expected_ssrcs));

        let max_ssrc_buffers = match options.input_ssrc_mode() {
            SSRCMode::Ignore => Some(1),
            SSRCMode::Any => max_input_ssrcs,
            SSRCMode::Specific => Some(expected_ssrcs),
        };

        let reordering_buffer_depth = options.reordering_buffer_depth();

        Self {
            options: options.clone(),
            rtcp: RtcpContext::new(options),
            buffer: ReorderingMultiBuffer::new(reordering_buffer_depth, max_ssrc_buffers),
            output: VecDeque::new(),
        }
    }

    /// Process a given outgoing RTP packet.
    fn process_outgoing_packet(&mut self, packet: &RtpPacket) {
        self.rtcp.process_outgoing_rtp_packet(packet);
    }

    /// Process a given incoming RTP packet.
    fn process_incoming_packet(&mut self, packet: RtpPacket) {
        let ssrc = packet.ssrc();

        let input_ssrcs = self.options.input_ssrcs();
        let input_ssrc_mode = self.options.input_ssrc_mode();

        if input_ssrc_mode == SSRCMode::Specific && !input_ssrcs.contains(ssrc) {
            return;
        }

        let now = Instant::now();

        let packet = IncomingRtpPacket::new(packet, now);

        // update the statistics (we need to do this before modifying the SSRC)
        self.rtcp.process_incoming_rtp_packet(&packet);

        let mut packet = RtpPacket::from(packet);

        // set SSRC to 0 if we are ignoring SSRCs
        if input_ssrc_mode == SSRCMode::Ignore {
            packet = packet.with_ssrc(0);
        }

        let mut packet = IncomingRtpPacket::new(packet, now);

        // put the packet into the reordering buffer, skipping missing packets
        // if necessary
        while let Err(ReorderingError::BufferFull(tmp)) = self.buffer.push(packet) {
            if let Some(p) = self.buffer.take() {
                self.process_ordered_packet(p);
            }

            packet = tmp;
        }

        // take all in-order packets from the reordering buffer
        while let Some(p) = self.buffer.next() {
            self.process_ordered_packet(p);
        }
    }

    /// Process a given incoming RTP packet after reordering.
    fn process_ordered_packet(&mut self, packet: OrderedRtpPacket) {
        self.rtcp.process_ordered_rtp_packet(&packet);
        self.output.push_back(packet);
    }

    /// Take the next incoming packet RTP without skipping missing packets.
    fn poll_next_ordered_packet(&mut self) -> Option<OrderedRtpPacket> {
        self.output.pop_front()
    }

    /// Take the next incoming RTP packet from the reordering buffer.
    ///
    /// This method will skip missing packets if necessary.
    fn take_next_ordered_packet(&mut self) -> Option<OrderedRtpPacket> {
        while self.output.is_empty() {
            if self.buffer.is_empty() {
                break;
            } else if let Some(packet) = self.buffer.take() {
                self.process_ordered_packet(packet);
            }
        }

        self.output.pop_front()
    }

    /// Check if the end of stream has been signaled by the other peer via the
    /// RTCP channel.
    fn end_of_stream(&self) -> bool {
        self.rtcp.end_of_stream()
    }

    /// Signal the end of stream to the other peer via the RTCP channel.
    fn close(&mut self) {
        self.rtcp.close();
    }

    /// Get the transceiver's RTCP context handle.
    fn rtcp_context(&self) -> RtcpContextHandle {
        self.rtcp.handle()
    }
}
