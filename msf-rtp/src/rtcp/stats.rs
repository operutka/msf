use std::time::{Duration, Instant};

use crate::{
    rtcp::{ByePacket, ReportBlock, SenderReport},
    rtp::{IncomingRtpPacket, RtpPacket},
    utils::OrderedRtpPacket,
};

/// RTP receiver statistics for a single SSRC.
#[derive(Clone)]
pub struct SSRCRxStats {
    ssrc: u32,
    clock_rate: u32,
    received_packets: u64,
    first_rtp_packet_at: Option<Instant>,
    first_rtp_timestamp: Option<u32>,
    last_transit_time: i32,
    jitter_estimate: u32,
    first_esn: Option<u64>,
    last_esn: Option<u64>,
    last_rr_at: Option<Instant>,
    last_sr_at: Option<Instant>,
    last_sr_ntp_timestamp: u64,
    create_report: bool,
    bye_received: bool,
}

impl SSRCRxStats {
    /// Create new RTP receiver statistics.
    pub fn new(ssrc: u32, clock_rate: u32) -> Self {
        Self {
            ssrc,
            clock_rate,
            received_packets: 0,
            first_rtp_packet_at: None,
            first_rtp_timestamp: None,
            last_transit_time: 0,
            jitter_estimate: 0,
            first_esn: None,
            last_esn: None,
            last_rr_at: None,
            last_sr_at: None,
            last_sr_ntp_timestamp: 0,
            create_report: false,
            bye_received: false,
        }
    }

    /// Process a given incoming RTP packet.
    pub fn process_incoming_rtp_packet(&mut self, packet: &IncomingRtpPacket) {
        self.received_packets = self.received_packets.wrapping_add(1);

        let received_at = packet.received_at();

        if self.first_rtp_packet_at.is_none() {
            self.first_rtp_packet_at = Some(received_at);
        }

        let packet_ts = packet.timestamp();

        if self.first_rtp_timestamp.is_none() {
            self.first_rtp_timestamp = Some(packet_ts);
        }

        let arrival_ts = self.get_rtp_time(received_at);

        let transit_time = arrival_ts.wrapping_sub(packet_ts) as i32;

        self.jitter_estimate = self
            .jitter_estimate
            .wrapping_add(i32::unsigned_abs(transit_time - self.last_transit_time))
            .wrapping_sub((self.jitter_estimate + 8) >> 4);

        self.last_transit_time = transit_time;
    }

    /// Process a given incoming RTP packet after reordering.
    ///
    /// Note that if the underlying RTP transport is ordered and no packet
    /// reordering is needed, the method `process_incoming_rtp_packet` still
    /// needs to be called for each packet before calling this method.
    pub fn process_ordered_rtp_packet(&mut self, packet: &OrderedRtpPacket) {
        let index = packet.index();

        if self.first_esn.is_none() {
            self.first_esn = Some(index);
        }

        self.last_esn = Some(index);

        self.create_report = true;
    }

    /// Process a given sender report.
    pub fn process_incoming_sender_report(&mut self, report: &SenderReport) {
        self.last_sr_at = Some(Instant::now());
        self.last_sr_ntp_timestamp = report.ntp_timestamp();
    }

    /// Process a given BYE packet.
    pub fn process_incoming_bye_packet(&mut self, _: &ByePacket) {
        self.bye_received = true;
    }

    /// Create an RTCP reception report block.
    ///
    /// The method will generate a reception report block only if there were
    /// any packets received since the last report.
    pub fn create_reception_report(&mut self) -> Option<ReportBlock> {
        let expected_packets = self.expected_packets();
        let highest_esn = self.highest_esn()?;

        if !self.create_report {
            return None;
        }

        self.create_report = false;

        self.last_rr_at = Some(Instant::now());

        let jitter = self.jitter_estimate >> 4;

        let delay_since_last_sr = self
            .last_sr_at
            .map(|t| t.elapsed())
            .unwrap_or(Duration::ZERO);

        let res = ReportBlock::new(self.ssrc)
            .with_loss(expected_packets, self.received_packets)
            .with_extended_sequence_number(highest_esn)
            .with_jitter(jitter)
            .with_last_sr_timestamp(self.last_sr_ntp_timestamp)
            .with_delay_since_last_sr(delay_since_last_sr);

        Some(res)
    }

    /// Get the instant when the last reception report was generated.
    pub fn last_reception_report_at(&self) -> Option<Instant> {
        self.last_rr_at
    }

    /// Check if a BYE packet was received.
    pub fn bye_received(&self) -> bool {
        self.bye_received
    }

    /// Get the number of packets expected by the receiver.
    fn expected_packets(&self) -> u64 {
        if let Some(last) = self.last_esn {
            last - self.first_esn.unwrap_or(last) + 1
        } else {
            0
        }
    }

    /// Get the highest extended sequence number received.
    fn highest_esn(&self) -> Option<u32> {
        self.last_esn.map(|val| val as u32)
    }

    /// Get RTP timestamp corresponding to a given instant.
    ///
    /// The returned value corresponds to the time elapsed since the first RTP
    /// packet was received until the given timestamp and it is in the SSRC
    /// clock rate units.
    fn get_rtp_time(&self, instant: Instant) -> u32 {
        let elapsed = self
            .first_rtp_packet_at
            .map(|first| instant.saturating_duration_since(first))
            .unwrap_or(Duration::ZERO);

        self.first_rtp_timestamp
            .unwrap_or(0)
            .wrapping_add(elapsed.to_rtp_time(self.clock_rate))
    }
}

/// RTP sender statistics for a single SSRC.
#[derive(Clone)]
pub struct SSRCTxStats {
    ssrc: u32,
    clock_rate: u32,
    first_rtp_packet_at: Option<Instant>,
    first_rtp_timestamp: Option<u32>,
    sent_packets: u64,
    sent_bytes: u64,
    create_report: bool,
}

impl SSRCTxStats {
    /// Create new RTP sender statistics.
    #[inline]
    pub const fn new(ssrc: u32, clock_rate: u32) -> Self {
        Self {
            ssrc,
            clock_rate,
            first_rtp_packet_at: None,
            first_rtp_timestamp: None,
            sent_packets: 0,
            sent_bytes: 0,
            create_report: false,
        }
    }

    /// Process a given outgoing RTP packet.
    pub fn process_outgoing_packet(&mut self, packet: &RtpPacket) {
        if self.first_rtp_packet_at.is_none() {
            self.first_rtp_packet_at = Some(Instant::now());
        }

        if self.first_rtp_timestamp.is_none() {
            self.first_rtp_timestamp = Some(packet.timestamp());
        }

        let payload = packet.payload();
        let length = payload.len();

        self.sent_packets = self.sent_packets.wrapping_add(1);
        self.sent_bytes = self.sent_bytes.wrapping_add(length as u64);

        self.create_report = true;
    }

    /// Create an RTCP sender report if there is anything to report.
    ///
    /// If there is nothing to report (i.e., no packets were sent since
    /// the last report), `None` is returned. The caller is expected to
    /// send an empty receiver report in such case.
    ///
    /// Note that the returned sender report does not contain any reception
    /// report blocks. It is the caller's responsibility to add them if needed.
    pub fn create_sender_report(&mut self) -> Option<SenderReport> {
        if !self.create_report {
            return None;
        }

        self.create_report = false;

        let res = SenderReport::new(self.ssrc)
            .with_ntp_timestamp(crate::utils::ntp_timestamp())
            .with_rtp_timestamp(self.current_rtp_time())
            .with_packet_count(self.sent_packets as u32)
            .with_octet_count(self.sent_bytes as u32);

        Some(res)
    }

    /// Get the current RTP timestamp.
    ///
    /// The timestamp corresponds to the time elapsed since the first RTP
    /// packet was sent and it is in the SSRC clock rate units.
    fn current_rtp_time(&self) -> u32 {
        let elapsed = self
            .first_rtp_packet_at
            .map(|instant| instant.elapsed())
            .unwrap_or(Duration::ZERO);

        self.first_rtp_timestamp
            .unwrap_or(0)
            .wrapping_add(elapsed.to_rtp_time(self.clock_rate))
    }
}

/// Helper trait.
trait DurationExt {
    /// Convert duration to RTP time with a given clock rate.
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
