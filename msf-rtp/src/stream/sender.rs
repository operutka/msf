//! RTP sender and related statistics.

use std::{
    collections::HashMap,
    pin::Pin,
    task::{Context, Poll},
    time::{Duration, Instant},
};

use futures::{ready, Sink};

use crate::{
    rtcp::{ReceiverReport, ReportBlock, RtcpPacket, SenderReport},
    rtp::RtpPacket,
    stream::DurationExt,
};

/// RTP packet sender.
pub trait RtpSender: Sink<RtpPacket> {
    /// Create sender reports.
    ///
    /// This method should generate sender reports for all SSRCs that appeared
    /// since the last call to this method.
    fn create_sender_reports(&mut self) -> Vec<RtcpPacket>;

    /// Process given reception report blocks.
    ///
    /// Note that reception report blocks may be received also as a part of a
    /// sender report (in cases where the peer is both sending and receiving
    /// RTP packets).
    fn process_reception_reports(&mut self, reports: &[ReportBlock]);
}

/// RTP sender options.
#[derive(Clone)]
pub struct RtpSenderOptions {
    default_clock_rate: u32,
    output_ssrcs: Vec<(u32, u32)>,
}

impl RtpSenderOptions {
    /// Create new options.
    #[inline]
    pub const fn new() -> Self {
        Self {
            default_clock_rate: 90000,
            output_ssrcs: Vec::new(),
        }
    }

    /// Set the default clock rate for SSRCs without an explicit clock rate.
    ///
    /// This clock rate will be used when creating sender and receiver reports
    /// for SSRCs where the clock rate is not known. The default value is
    /// 90000.
    #[inline]
    pub const fn default_clock_rate(mut self, clock_rate: u32) -> Self {
        self.default_clock_rate = clock_rate;
        self
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
    pub fn output_ssrcs<T>(mut self, ssrcs: T) -> Self
    where
        T: IntoIterator<Item = (u32, u32)>,
    {
        self.output_ssrcs = Vec::from_iter(ssrcs);
        self
    }
}

impl Default for RtpSenderOptions {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

pin_project_lite::pin_project! {
    /// Default RTP sender implementation.
    pub struct DefaultRtpSender<T> {
        #[pin]
        inner: T,
        options: RtpSenderOptions,
        stats: HashMap<u32, SSRCTxStats>,
    }
}

impl<T> DefaultRtpSender<T> {
    /// Create a new RTP packet sender.
    pub fn new(inner: T, options: RtpSenderOptions) -> Self {
        let stats = options
            .output_ssrcs
            .iter()
            .copied()
            .map(|(ssrc, clock_rate)| (ssrc, SSRCTxStats::new(ssrc, clock_rate)))
            .collect();

        Self {
            inner,
            options,
            stats,
        }
    }
}

impl<T> Sink<RtpPacket> for DefaultRtpSender<T>
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

        let ssrc = packet.ssrc();

        this.stats
            .entry(ssrc)
            .or_insert_with(|| SSRCTxStats::new(ssrc, this.options.default_clock_rate))
            .process_outgoing_packet(&packet);

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

        Poll::Ready(Ok(()))
    }
}

impl<T> RtpSender for DefaultRtpSender<T>
where
    T: Sink<RtpPacket>,
{
    fn create_sender_reports(&mut self) -> Vec<RtcpPacket> {
        self.stats
            .iter_mut()
            .map(|(&ssrc, stats)| {
                if let Some(sr) = stats.create_rtcp_report() {
                    sr.encode()
                } else {
                    // if there are no sender stats to report, create an empty
                    // receiver report instead
                    let rr = ReceiverReport::new(ssrc);

                    rr.encode()
                }
            })
            .collect()
    }

    fn process_reception_reports(&mut self, _: &[ReportBlock]) {
        // we have no use for reception reports at the moment
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
    pub fn create_rtcp_report(&mut self) -> Option<SenderReport> {
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
    /// packet was sent and it is in the SSRC clock rate.
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
