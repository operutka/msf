use std::{
    collections::HashMap,
    num::NonZeroUsize,
    sync::{Arc, Mutex},
    time::Duration,
};

use lru::LruCache;

use crate::{
    rtcp::{
        stats::{SSRCRxStats, SSRCTxStats},
        ByePacket, CompoundRtcpPacket, ReceiverReport, ReportBlock, RtcpHeader, RtcpPacket,
        SenderReport, SourceDescription, SourceDescriptionPacket,
    },
    rtp::{IncomingRtpPacket, RtpPacket},
    transceiver::{RtpTransceiverOptions, SSRCMode},
    utils::OrderedRtpPacket,
};

/// RTCP context.
///
/// This struct manages RTCP state, including sender and receiver statistics,
/// source descriptions, and RTCP report generation. It is used for interaction
/// between RTP channels and their corresponding RTCP channels.
///
/// The RTCP context is designed to be owned by an RTP channel/transceiver,
/// while a handle to the context can be shared with the RTCP channel for
/// processing incoming RTCP packets and generating RTCP reports.
///
/// The context will be closed automatically when dropped.
pub struct RtcpContext {
    inner: Arc<Mutex<InternalContext>>,
}

impl RtcpContext {
    /// Create a new RTCP context.
    pub fn new(options: RtpTransceiverOptions) -> Self {
        Self {
            inner: Arc::new(Mutex::new(InternalContext::new(options))),
        }
    }

    /// Process a given outgoing RTP packet.
    pub fn process_outgoing_rtp_packet(&self, packet: &RtpPacket) {
        self.inner
            .lock()
            .unwrap()
            .process_outgoing_rtp_packet(packet);
    }

    /// Process a given incoming RTP packet.
    pub fn process_incoming_rtp_packet(&self, packet: &IncomingRtpPacket) {
        self.inner
            .lock()
            .unwrap()
            .process_incoming_rtp_packet(packet);
    }

    /// Process a given incoming RTP packet after reordering.
    ///
    /// Note that if the underlying RTP transport is ordered and no packet
    /// reordering is needed, the method `process_incoming_rtp_packet` still
    /// needs to be called for each packet before calling this method.
    pub fn process_ordered_rtp_packet(&self, packet: &OrderedRtpPacket) {
        self.inner
            .lock()
            .unwrap()
            .process_ordered_rtp_packet(packet);
    }

    /// Close the RTCP context.
    ///
    /// This will generate BYE packets for all active sender SSRCs and stop
    /// generating further RTCP reports. A sender SSRC is considered active if
    /// we have sent at least one RTP packet with the SSRC.
    pub fn close(&self) {
        self.inner.lock().unwrap().close();
    }

    /// Check if end of stream has been reached.
    ///
    /// The method checks the end-of-stream condition based on the configured
    /// SSRC mode and the reception of BYE packets for the relevant SSRCs.
    ///
    /// * If the input SSRC mode is `Specific`, the method returns true if BYE
    ///   packets have been received for all configured input SSRCs.
    /// * If the input SSRC mode is `Ignore`, the method returns true if at
    ///   least one BYE packet has been received.
    /// * If the input SSRC mode is `Any`, the method returns true if BYE
    ///   packets have been received for all currently tracked SSRCs on the
    ///   receiver side and there is at least one such SSRC.
    pub fn end_of_stream(&self) -> bool {
        self.inner.lock().unwrap().end_of_stream()
    }

    /// Create a context handle that can be shared with the companion RTCP
    /// channel.
    pub fn handle(&self) -> RtcpContextHandle {
        RtcpContextHandle {
            inner: self.inner.clone(),
        }
    }
}

impl Drop for RtcpContext {
    fn drop(&mut self) {
        self.close();
    }
}

/// RTCP context handle.
///
/// This handle can be shared with an RTCP channel for processing incoming
/// RTCP packets and generating RTCP reports.
#[derive(Clone)]
pub struct RtcpContextHandle {
    inner: Arc<Mutex<InternalContext>>,
}

impl RtcpContextHandle {
    /// Process a given receiver report.
    pub fn process_incoming_receiver_report(&self, report: &ReceiverReport) {
        self.inner
            .lock()
            .unwrap()
            .process_incoming_receiver_report(report);
    }

    /// Process a given sender report.
    pub fn process_incoming_sender_report(&self, report: &SenderReport) {
        self.inner
            .lock()
            .unwrap()
            .process_incoming_sender_report(report);
    }

    /// Process a given BYE packet.
    pub fn process_incoming_bye_packet(&self, packet: &ByePacket) {
        self.inner
            .lock()
            .unwrap()
            .process_incoming_bye_packet(packet);
    }

    /// Create RTCP reports.
    ///
    /// This method generates receiver and/or sender reports for all SSRCs that
    /// appeared since the last call to this method. If no RTP packets have
    /// been sent or received since the last call, empty receiver reports for
    /// all active sender SSRCs will be generated. A sender SSRC is considered
    /// active if we have sent at least one RTP packet with the SSRC.
    ///
    /// The method also generates BYE packets for all active sender SSRCs if
    /// the context has been closed. The method will return an empty vector if
    /// the context has already been closed and all corresponding BYE packets
    /// have been generated.
    pub fn create_rtcp_reports(&mut self) -> Vec<CompoundRtcpPacket> {
        self.inner.lock().unwrap().create_rtcp_reports()
    }

    /// Close the RTCP context.
    ///
    /// This will generate BYE packets for all active sender SSRCs and stop
    /// generating further RTCP reports. A sender SSRC is considered active if
    /// we have sent at least one RTP packet with the SSRC.
    pub fn close(&self) {
        self.inner.lock().unwrap().close();
    }
}

/// Internal RTCP context state.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum ContextState {
    Open,
    Closing,
    Closed,
}

/// Internal RTCP context.
struct InternalContext {
    options: RtpTransceiverOptions,
    source_descriptions: SourceDescriptionCache,
    rx_stats: LruCache<u32, SSRCRxStats>,
    tx_stats: HashMap<u32, SSRCTxStats>,
    last_ssrc: Option<u32>,
    state: ContextState,
}

impl InternalContext {
    /// Create a new internal RTCP context.
    fn new(options: RtpTransceiverOptions) -> Self {
        let input_ssrc_mode = options.input_ssrc_mode();
        let max_input_ssrcs = options.max_input_ssrcs();

        let rx_stats = if let (SSRCMode::Any, Some(max)) = (input_ssrc_mode, max_input_ssrcs) {
            let input_ssrcs = options.input_ssrcs();

            let max = NonZeroUsize::new(max.max(input_ssrcs.len())).unwrap_or(NonZeroUsize::MIN);

            LruCache::new(max)
        } else {
            LruCache::unbounded()
        };

        Self {
            options,
            source_descriptions: SourceDescriptionCache::new(),
            rx_stats,
            tx_stats: HashMap::new(),
            last_ssrc: None,
            state: ContextState::Open,
        }
    }

    /// Process a given outgoing RTP packet.
    fn process_outgoing_rtp_packet(&mut self, packet: &RtpPacket) {
        self.get_tx_stats_mut(packet.ssrc())
            .process_outgoing_packet(packet);
    }

    /// Process a given incoming RTP packet.
    fn process_incoming_rtp_packet(&mut self, packet: &IncomingRtpPacket) {
        let mut ssrc = packet.ssrc();

        self.last_ssrc = Some(ssrc);

        if self.options.input_ssrc_mode() == SSRCMode::Ignore {
            ssrc = 0;
        }

        self.get_rx_stats_mut(ssrc)
            .process_incoming_rtp_packet(packet);
    }

    /// Process a given incoming RTP packet after reordering.
    fn process_ordered_rtp_packet(&mut self, packet: &OrderedRtpPacket) {
        let mut ssrc = packet.ssrc();

        if self.options.input_ssrc_mode() == SSRCMode::Ignore {
            ssrc = 0;
        }

        self.get_rx_stats_mut(ssrc)
            .process_ordered_rtp_packet(packet);
    }

    /// Process a given sender report.
    fn process_incoming_sender_report(&mut self, report: &SenderReport) {
        if let Some(stats) = self.rx_stats.peek_mut(&report.sender_ssrc()) {
            stats.process_incoming_sender_report(report);
        }

        self.process_incoming_reception_report_blocks(report.report_blocks());
    }

    /// Process a given receiver report.
    fn process_incoming_receiver_report(&mut self, report: &ReceiverReport) {
        self.process_incoming_reception_report_blocks(report.report_blocks());
    }

    /// Process given reception report blocks.
    fn process_incoming_reception_report_blocks(&mut self, _: &[ReportBlock]) {
        // we have no use for reception reports at the moment
    }

    /// Process a given BYE packet.
    fn process_incoming_bye_packet(&mut self, packet: &ByePacket) {
        let sources = if self.options.input_ssrc_mode() == SSRCMode::Ignore {
            &[0]
        } else {
            packet.sources()
        };

        for &ssrc in sources {
            self.get_rx_stats_mut(ssrc)
                .process_incoming_bye_packet(packet);
        }
    }

    /// Check if end of stream has been reached.
    ///
    /// The method checks the end-of-stream condition based on the configured
    /// SSRC mode and the reception of BYE packets for the relevant SSRCs.
    ///
    /// * If the input SSRC mode is `Specific`, the method returns true if BYE
    ///   packets have been received for all configured input SSRCs.
    /// * If the input SSRC mode is `Ignore`, the method returns true if we
    ///   have received at least one BYE packet.
    /// * If the input SSRC mode is `Any`, the method returns true if BYE
    ///   packets have been received for all currently tracked SSRCs on the
    ///   receiver side and there is at least one such SSRC.
    fn end_of_stream(&self) -> bool {
        if self.options.input_ssrc_mode() == SSRCMode::Specific {
            self.options.input_ssrcs().iter().all(|(ssrc, _)| {
                self.rx_stats
                    .peek(&ssrc)
                    .map(|stats| stats.bye_received())
                    .unwrap_or(false)
            })
        } else {
            !self.rx_stats.is_empty() && self.rx_stats.iter().all(|(_, stats)| stats.bye_received())
        }
    }

    /// Close the RTCP context.
    ///
    /// This will generate BYE packets for all active sender SSRCs and stop
    /// generating further RTCP reports. A sender SSRC is considered active if
    /// we have sent at least one RTP packet with the SSRC.
    fn close(&mut self) {
        if self.state == ContextState::Open {
            self.state = ContextState::Closing;
        }
    }

    /// Get transmission statistics for a given SSRC.
    fn get_tx_stats_mut(&mut self, ssrc: u32) -> &mut SSRCTxStats {
        // helper function
        fn create_tx_stats(ssrc: u32, options: &RtpTransceiverOptions) -> SSRCTxStats {
            let clock_rate = options
                .output_ssrcs()
                .clock_rate(ssrc)
                .unwrap_or(options.default_clock_rate());

            SSRCTxStats::new(ssrc, clock_rate)
        }

        self.tx_stats
            .entry(ssrc)
            .or_insert_with(|| create_tx_stats(ssrc, &self.options))
    }

    /// Get reception statistics for a given SSRC.
    fn get_rx_stats_mut(&mut self, ssrc: u32) -> &mut SSRCRxStats {
        // helper function
        fn create_rx_stats(ssrc: u32, options: &RtpTransceiverOptions) -> SSRCRxStats {
            let clock_rate = options
                .input_ssrcs()
                .clock_rate(ssrc)
                .unwrap_or(options.default_clock_rate());

            SSRCRxStats::new(ssrc, clock_rate)
        }

        self.rx_stats
            .get_or_insert_mut(ssrc, || create_rx_stats(ssrc, &self.options))
    }

    /// Generate reception report blocks.
    ///
    /// The method returns an iterator over reception report blocks for all
    /// tracked SSRCs ordered by the time since the last report was generated.
    /// Only SSRCs with packets received since the last report will be included
    /// in the output.
    ///
    /// Consumer of the iterator should not call the `next` method if the
    /// resulting report block would be dropped (e.g. due to size limits) as
    /// that would update the last report generation instant for the
    /// corresponding SSRC and thus affect the ordering of subsequent calls.
    fn generate_reception_report_blocks(&mut self) -> impl Iterator<Item = ReportBlock> + use<'_> {
        let mut report_order = self
            .rx_stats
            .iter()
            .map(|(&ssrc, stats)| {
                let duration_since_last_report = stats
                    .last_reception_report_at()
                    .map(|t| t.elapsed())
                    .unwrap_or(Duration::MAX);

                (ssrc, duration_since_last_report)
            })
            .collect::<Vec<_>>();

        report_order.sort_unstable_by_key(|&(_, d)| d);

        report_order
            .into_iter()
            .filter_map(|(ssrc, _)| self.rx_stats.peek_mut(&ssrc)?.create_reception_report())
            .map(|block| {
                if self.options.input_ssrc_mode() == SSRCMode::Ignore {
                    if let Some(ssrc) = self.last_ssrc {
                        return block.with_ssrc(ssrc);
                    }
                }

                block
            })
    }

    /// Create the primary RTCP report.
    ///
    /// This report is created for the primary sender SSRC and may include
    /// reception report blocks for the peer SSRCs.
    fn create_primary_rtcp_report(&mut self) -> CompoundRtcpPacket {
        let sender_ssrc = self.options.primary_sender_ssrc();

        let report = self
            .tx_stats
            .get_mut(&sender_ssrc)
            .and_then(|stats| stats.create_sender_report())
            .map(RtcpReport::Sender)
            .unwrap_or_else(|| RtcpReport::Receiver(ReceiverReport::new(sender_ssrc)));

        let mut builder = RtcpReportBuilder::new(report);

        let sdes = self.source_descriptions.get(sender_ssrc);

        let mut min_packets = 2;
        let mut encoded_size = sdes.raw_size();

        let bye = if self.state != ContextState::Open {
            let pkt = ByePacket::new([sender_ssrc]);

            let encoded = pkt.encode();

            encoded_size += encoded.raw_size();
            min_packets += 1;

            Some(encoded)
        } else {
            None
        };

        let mut packets = Vec::with_capacity(min_packets);

        let max_encoded_size = self.options.max_rtcp_packet_size();

        let mut report_blocks = self.generate_reception_report_blocks();

        while (encoded_size + builder.size() + ReportBlock::RAW_SIZE) <= max_encoded_size {
            if let Some(block) = report_blocks.next() {
                if let Some(packet) = builder.add(block) {
                    encoded_size += packet.raw_size();

                    packets.push(packet);
                }
            } else {
                break;
            }
        }

        if !builder.is_empty() || packets.is_empty() {
            packets.push(builder.build_and_encode());
        }

        packets.push(sdes);

        if let Some(bye) = bye {
            packets.push(bye);
        }

        CompoundRtcpPacket::new(packets)
    }

    /// Create RTCP reports.
    ///
    /// This method generates receiver and/or sender reports for all SSRCs that
    /// appeared since the last call to this method. If no RTP packets have
    /// been sent or received since the last call, empty receiver reports for
    /// all active sender SSRCs will be generated. A sender SSRC is considered
    /// active if we have sent at least one RTP packet with the SSRC.
    ///
    /// The method also generates BYE packets for all active sender SSRCs if
    /// the context has been closed. The method will return an empty vector if
    /// the context has already been closed and all corresponding BYE packets
    /// have been generated.
    fn create_rtcp_reports(&mut self) -> Vec<CompoundRtcpPacket> {
        match self.state {
            ContextState::Open => (),
            ContextState::Closing => self.state = ContextState::Closed,
            ContextState::Closed => return Vec::new(),
        }

        let mut reports = vec![self.create_primary_rtcp_report()];

        let secondary_report_packets = if self.state == ContextState::Open {
            2
        } else {
            3
        };

        // We consider each sender SSRC as an independent RTP participant, so
        // we create separate sender reports for them.
        let secondary = self
            .tx_stats
            .iter_mut()
            .filter(|(&ssrc, _)| ssrc != self.options.primary_sender_ssrc())
            .map(|(&ssrc, stats)| {
                let mut packets = Vec::with_capacity(secondary_report_packets);

                // if there are no sender stats to report, create an empty
                // receiver report instead
                let report = stats
                    .create_sender_report()
                    .map(RtcpReport::Sender)
                    .unwrap_or_else(|| RtcpReport::Receiver(ReceiverReport::new(ssrc)));

                packets.push(report.encode());
                packets.push(self.source_descriptions.get(ssrc));

                if self.state != ContextState::Open {
                    let bye = ByePacket::new([ssrc]);

                    packets.push(bye.encode());
                }

                CompoundRtcpPacket::new(packets)
            });

        reports.extend(secondary);
        reports
    }
}

/// Cache for source description packets.
struct SourceDescriptionCache {
    descriptions: HashMap<u32, RtcpPacket>,
}

impl SourceDescriptionCache {
    /// Create a new source description packet cache.
    fn new() -> Self {
        Self {
            descriptions: HashMap::new(),
        }
    }

    /// Get a source description packet for a given SSRC.
    fn get(&mut self, ssrc: u32) -> RtcpPacket {
        self.descriptions
            .entry(ssrc)
            .or_insert_with(|| {
                let cname = format!("{:016x}", rand::random::<u64>());

                let desc = SourceDescription::new(ssrc, cname);

                SourceDescriptionPacket::new()
                    .with_source_descriptions([desc])
                    .encode()
            })
            .clone()
    }
}

/// RTCP report builder.
struct RtcpReportBuilder {
    report: RtcpReport,
    blocks: Vec<ReportBlock>,
    size: usize,
}

impl RtcpReportBuilder {
    /// Create a new RTCP report builder.
    ///
    /// # Arguments
    /// * `report` - the initial RTCP report (sender or receiver)
    fn new<T>(report: T) -> Self
    where
        T: Into<RtcpReport>,
    {
        let report = report.into();

        let size = RtcpHeader::RAW_SIZE + report.raw_size();

        Self {
            report,
            blocks: Vec::new(),
            size,
        }
    }

    /// Get the current size of the report in bytes.
    fn size(&self) -> usize {
        self.size
    }

    /// Check if the report is empty (i.e. there are no report blocks).
    fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    /// Check if the report is full (i.e. contains the maximum allowed number
    /// of report blocks).
    fn is_full(&self) -> bool {
        self.blocks.len() >= 31
    }

    /// Add a given report block to the report.
    ///
    /// The method will finalize the report and encode it into an RTCP packet
    /// if the report becomes full after adding the block. In such case, the
    /// method will return the encoded RTCP packet and a new empty receiver
    /// report will be started.
    ///
    /// This keeps the invariant that the currently open report is never full
    /// making the packet size limit calculations simpler.
    fn add(&mut self, block: ReportBlock) -> Option<RtcpPacket> {
        self.size += block.raw_size();

        self.blocks.push(block);

        if !self.is_full() {
            return None;
        }

        let empty = ReceiverReport::new(self.report.sender_ssrc());

        let full = std::mem::replace(self, Self::new(empty));

        Some(full.build_and_encode())
    }

    /// Finalize the sender/receiver report and encode it into an RTCP packet.
    fn build_and_encode(self) -> RtcpPacket {
        self.report.with_report_blocks(self.blocks).encode()
    }
}

/// RTCP report.
enum RtcpReport {
    Sender(SenderReport),
    Receiver(ReceiverReport),
}

impl RtcpReport {
    /// Get the sender SSRC.
    fn sender_ssrc(&self) -> u32 {
        match self {
            Self::Sender(sr) => sr.sender_ssrc(),
            Self::Receiver(rr) => rr.sender_ssrc(),
        }
    }

    /// Get size of the encoded report.
    fn raw_size(&self) -> usize {
        match self {
            Self::Sender(sr) => sr.raw_size(),
            Self::Receiver(rr) => rr.raw_size(),
        }
    }

    /// Set the reception report blocks.
    fn with_report_blocks(self, blocks: Vec<ReportBlock>) -> Self {
        match self {
            Self::Sender(sr) => Self::Sender(sr.with_report_blocks(blocks)),
            Self::Receiver(rr) => Self::Receiver(rr.with_report_blocks(blocks)),
        }
    }

    /// Encode the report into an RTCP packet.
    fn encode(&self) -> RtcpPacket {
        match self {
            Self::Sender(sr) => sr.encode(),
            Self::Receiver(rr) => rr.encode(),
        }
    }
}

impl From<SenderReport> for RtcpReport {
    fn from(sr: SenderReport) -> Self {
        Self::Sender(sr)
    }
}

impl From<ReceiverReport> for RtcpReport {
    fn from(rr: ReceiverReport) -> Self {
        Self::Receiver(rr)
    }
}
