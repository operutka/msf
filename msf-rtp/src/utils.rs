//! Helpers.

use std::collections::VecDeque;

use crate::rtp::RtpPacket;

/// Reordering error.
pub enum ReorderingError {
    BufferFull(RtpPacket),
    DuplicatePacket(RtpPacket),
}

impl ReorderingError {
    /// Check if the reordering buffer rejected the packet because it would
    /// exceed its capacity.
    #[inline]
    pub fn is_full(&self) -> bool {
        matches!(self, Self::BufferFull(_))
    }

    /// Check if the packet was rejected because of being a duplicate.
    #[inline]
    pub fn is_duplicate(&self) -> bool {
        matches!(self, Self::DuplicatePacket(_))
    }
}

/// Reordering buffer for RTP packets.
///
/// The reordering buffer internally uses `u64` packet indices. These indices
/// are estimated from packet sequence numbers according to the algorithm
/// presented in RFC 3711, section 3.3.1.
///
/// This simplifies the original algorithm presented in RFC 3550.
///
/// Note: RFC 3711 uses 32-bit ROC. This implementation uses 64-bit indices, so
/// the actual bit width of the ROC is 48 bits here (48-bit ROC + 16-bit
/// sequence number gives 64-bit packet index). The 32-bit ROC value can be
/// extracted from packet indices simply by cutting off the upper 16 bits, e.g.
/// `(index >> 16) as u32`.
pub struct ReorderingBuffer {
    start: Option<u64>,
    window: VecDeque<Option<RtpPacket>>,
    capacity: usize,
}

impl ReorderingBuffer {
    /// Create a new reordering buffer with a given depth.
    #[inline]
    pub fn new(depth: usize) -> Self {
        Self {
            start: None,
            window: VecDeque::with_capacity(depth.min(32)),
            capacity: depth,
        }
    }

    /// Estimate packet index from a given sequence number.
    pub fn estimate_index(&self, sequence_nr: u16) -> u64 {
        let start_index = self.start.unwrap_or(sequence_nr as u64);
        let last_index = start_index + (self.window.len() as u64);
        let last_seq_nr = (last_index & 0xffff) as u16;
        let last_roc = last_index >> 16;

        let new_seq_nr = sequence_nr;

        let new_roc = if new_seq_nr > last_seq_nr {
            if (new_seq_nr - last_seq_nr) < 0x8000 {
                last_roc
            } else {
                last_roc.wrapping_sub(1)
            }
        } else if (last_seq_nr - new_seq_nr) < 0x8000 {
            last_roc
        } else {
            last_roc.wrapping_add(1)
        };

        (new_roc << 16) | (new_seq_nr as u64)
    }

    /// Check if a packet with a given index would be a duplicate.
    pub fn is_duplicate(&self, index: u64) -> bool {
        let start = self.start.unwrap_or(index);

        if index < start {
            return true;
        }

        let offset = index - start;

        if offset > (usize::MAX as u64) {
            return false;
        }

        let offset = offset as usize;

        self.window
            .get(offset)
            .map(|entry| entry.is_some())
            .unwrap_or(false)
    }

    /// Push a given packet into the buffer and return index of the inserted
    /// packet.
    ///
    /// The method returns an error if the packet cannot be inserted into the
    /// buffer because it is either a duplicate or the buffer would exceed its
    /// capacity.
    pub fn push(&mut self, packet: RtpPacket) -> Result<u64, ReorderingError> {
        let index = self.estimate_index(packet.sequence_number());

        if self.start.is_none() {
            self.start = Some(index);
        }

        let start = self.start.unwrap();

        if index < start {
            return Err(ReorderingError::DuplicatePacket(packet));
        }

        let offset = index - start;

        if offset > (usize::MAX as u64) {
            return Err(ReorderingError::BufferFull(packet));
        }

        let offset = offset as usize;

        if offset < self.capacity {
            while offset >= self.window.len() {
                self.window.push_back(None);
            }

            let entry = &mut self.window[offset];

            if entry.is_some() {
                return Err(ReorderingError::DuplicatePacket(packet));
            }

            *entry = Some(packet);

            Ok(index)
        } else {
            Err(ReorderingError::BufferFull(packet))
        }
    }

    /// Take the next packet from the buffer.
    ///
    /// This method will return a packet only if there is a packet in the front
    /// slot of the buffer. In other words, the index of the returned packet
    /// will always be equal to the start index.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Option<RtpPacket> {
        if let Some(entry) = self.window.front() {
            if entry.is_some() {
                return self.take();
            }
        }

        None
    }

    /// Remove the front packet in the buffer and advance the window start
    /// position by one.
    ///
    /// The method will always advance the window start position even if the
    /// front slot is empty or if the underlying buffer itself is empty.
    pub fn take(&mut self) -> Option<RtpPacket> {
        if let Some(start) = self.start.as_mut() {
            *start += 1;
        }

        self.window.pop_front()?
    }

    /// Check if the underlying buffer is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.window.is_empty()
    }
}
