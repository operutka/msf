use std::collections::VecDeque;

/// Helper structure for constructing decoding timestamp sequence.
///
/// We store only distinct RTP presentation timestamps in a queue and they get
/// assigned to every access unit after reordering the NAL units and
/// constructing the AUs. This way we can construct a decoding timestamp
/// sequence that matches the original stream timing and can be used for
/// example when interleaving audio and video frames into a container.
pub struct DTSSequenceBuilder {
    rtp_timestamps: VecDeque<u64>,
    last_rtp_timestamp: Option<u64>,
}

impl DTSSequenceBuilder {
    /// Create a new decoding timestamp sequence builder.
    pub fn new() -> Self {
        Self {
            rtp_timestamps: VecDeque::new(),
            last_rtp_timestamp: None,
        }
    }

    /// Push a given RTP presentation timestamp to the sequence builder.
    pub fn push_rtp_timestamp(&mut self, rtp_timestamp: u64) {
        if Some(rtp_timestamp) == self.last_rtp_timestamp {
            return;
        }

        self.last_rtp_timestamp = Some(rtp_timestamp);

        self.rtp_timestamps.push_back(rtp_timestamp);
    }

    /// Get the next decoding timestamp in the RTP clock rate units.
    pub fn next_decoding_timestamp(&mut self) -> u64 {
        self.rtp_timestamps
            .pop_front()
            .or(self.last_rtp_timestamp)
            .unwrap_or(0)
    }

    /// Get the number of available RTP timestamps in the sequence.
    pub fn available(&self) -> usize {
        self.rtp_timestamps.len()
    }
}
