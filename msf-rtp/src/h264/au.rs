use std::collections::VecDeque;

use bytes::{Bytes, BytesMut};

/// H.264 access unit.
///
/// # Note
/// The decoding timestamp sequence should have the same timing properties as
/// the presentation timestamp sequence. That is, the DTS values should be
/// monotonically increasing and the difference between consecutive DTS values
/// should correspond to the frame durations. This is important audio and
/// video frames need to be interleaved into a container.
#[derive(Clone)]
pub struct AccessUnit {
    pts: u64,
    dts: u64,
    data: Bytes,
}

impl AccessUnit {
    /// Create a new access unit with given extended RTP timestamps.
    #[inline]
    pub const fn new(pts: u64, dts: u64, data: Bytes) -> Self {
        Self { pts, dts, data }
    }

    /// Get the extended RTP presentation timestamp.
    #[inline]
    pub const fn presentation_timestamp(&self) -> u64 {
        self.pts
    }

    /// Set the extended RTP presentation timestamp.
    #[inline]
    pub const fn with_presentation_timestamp(mut self, dts: u64) -> Self {
        self.dts = dts;
        self
    }

    /// Get the extended RTP decoding timestamp.
    #[inline]
    pub const fn decoding_timestamp(&self) -> u64 {
        self.dts
    }

    /// Set the extended RTP decoding timestamp.
    #[inline]
    pub const fn with_decoding_timestamp(mut self, dts: u64) -> Self {
        self.dts = dts;
        self
    }

    /// Get the access unit data.
    #[inline]
    pub const fn data(&self) -> &Bytes {
        &self.data
    }

    /// Take the access unit data.
    #[inline]
    pub fn into_data(self) -> Bytes {
        self.data
    }
}

/// H.264 access unit builder.
pub struct AccessUnitBuilder {
    available_aus: VecDeque<AccessUnit>,
    rtp_timestamp: Option<u64>,
    data: BytesMut,
}

impl AccessUnitBuilder {
    /// Create a new access unit builder.
    pub fn new() -> Self {
        Self {
            available_aus: VecDeque::new(),
            rtp_timestamp: None,
            data: BytesMut::new(),
        }
    }

    /// Push a given NAL unit with the corresponding RTP timestamp.
    pub fn push(&mut self, timestamp: u64, nal_unit: &[u8]) {
        if let Some(ts) = self.rtp_timestamp {
            if ts != timestamp {
                self.commit();
            }
        }

        self.rtp_timestamp = Some(timestamp);

        self.data.reserve(3 + nal_unit.len());
        self.data.extend_from_slice(&[0, 0, 1]);
        self.data.extend_from_slice(nal_unit);
    }

    /// Flush the builder and commit any pending access unit.
    pub fn flush(&mut self) {
        self.commit();
    }

    /// Take the next available access unit.
    pub fn take(&mut self) -> Option<AccessUnit> {
        self.available_aus.pop_front()
    }

    /// Get the number of available access units.
    pub fn available(&self) -> usize {
        self.available_aus.len()
    }

    /// Commit the current access unit.
    fn commit(&mut self) {
        let Some(timestamp) = self.rtp_timestamp.take() else {
            return;
        };

        let data = self.data.split();

        let au = AccessUnit::new(timestamp, 0, data.freeze());

        self.available_aus.push_back(au);
    }
}
