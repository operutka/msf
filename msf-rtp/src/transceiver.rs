//! RTP transceiver.

use std::{
    collections::HashMap,
    ops::{Deref, DerefMut},
    sync::Arc,
};

use crate::rtcp::RtcpContextHandle;

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
