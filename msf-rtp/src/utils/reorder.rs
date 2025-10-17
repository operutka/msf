//! Helpers.

use std::{borrow::Borrow, collections::VecDeque, ops::Deref};

use lru::LruCache;

use crate::rtp::{IncomingRtpPacket, RtpPacket};

/// Reordering error.
pub enum ReorderingError {
    BufferFull(IncomingRtpPacket),
    DuplicatePacket(IncomingRtpPacket),
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

/// Ordered RTP packet.
#[derive(Clone)]
pub struct OrderedRtpPacket {
    inner: IncomingRtpPacket,
    index: u64,
}

impl OrderedRtpPacket {
    /// Create a new ordered RTP packet.
    #[inline]
    pub const fn new(inner: IncomingRtpPacket, index: u64) -> Self {
        Self { inner, index }
    }

    /// Get the estimated packet index (a.k.a. extended sequence number).
    #[inline]
    pub fn index(&self) -> u64 {
        self.index
    }
}

impl AsRef<IncomingRtpPacket> for OrderedRtpPacket {
    #[inline]
    fn as_ref(&self) -> &IncomingRtpPacket {
        &self.inner
    }
}

impl AsRef<RtpPacket> for OrderedRtpPacket {
    #[inline]
    fn as_ref(&self) -> &RtpPacket {
        &self.inner
    }
}

impl Borrow<IncomingRtpPacket> for OrderedRtpPacket {
    #[inline]
    fn borrow(&self) -> &IncomingRtpPacket {
        &self.inner
    }
}

impl Borrow<RtpPacket> for OrderedRtpPacket {
    #[inline]
    fn borrow(&self) -> &RtpPacket {
        &self.inner
    }
}

impl Deref for OrderedRtpPacket {
    type Target = IncomingRtpPacket;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl From<OrderedRtpPacket> for IncomingRtpPacket {
    #[inline]
    fn from(packet: OrderedRtpPacket) -> Self {
        packet.inner
    }
}

impl From<OrderedRtpPacket> for RtpPacket {
    #[inline]
    fn from(packet: OrderedRtpPacket) -> Self {
        packet.inner.into()
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
    inner: InternalBuffer,
}

impl ReorderingBuffer {
    /// Create a new reordering buffer with a given depth.
    #[inline]
    pub fn new(depth: usize) -> Self {
        Self {
            inner: InternalBuffer::new(depth),
        }
    }

    /// Estimate packet index from a given sequence number.
    pub fn estimate_index(&self, sequence_nr: u16) -> u64 {
        self.inner.estimate_index(sequence_nr)
    }

    /// Check if a packet with a given index would be a duplicate.
    pub fn is_duplicate(&self, index: u64) -> bool {
        self.inner.is_duplicate(index)
    }

    /// Push a given packet into the buffer and return index of the inserted
    /// packet.
    ///
    /// The method returns an error if the packet cannot be inserted into the
    /// buffer because it is either a duplicate or the buffer would exceed its
    /// capacity.
    pub fn push(&mut self, packet: IncomingRtpPacket) -> Result<u64, ReorderingError> {
        self.inner
            .push(InputPacket::new(packet, 0))
            .map_err(ReorderingError::from)
    }

    /// Take the next packet from the buffer.
    ///
    /// This method will return a packet only if there is a packet in the front
    /// slot of the buffer. In other words, a packet will be returned only if
    /// it is an in-order packet and returning it would not skip any packets.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Option<OrderedRtpPacket> {
        self.inner
            .next()
            .map(OrderedRtpPacket::from)
    }

    /// Remove the front slot from the buffer and return the contained packet
    /// (if any).
    ///
    /// The method will always advance start position of the reordering window
    /// by one even if the front slot is empty or if the underlying buffer
    /// itself is empty.
    pub fn take(&mut self) -> Option<OrderedRtpPacket> {
        self.inner
            .take()
            .map(OrderedRtpPacket::from)
    }

    /// Check if the buffer is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

/// Reordering buffer for RTP packets from multiple synchronization sources.
///
/// The buffer can be used the same way as `ReorderingBuffer` in cases where
/// RTP packets with multiple SSRCs are expected. The buffer reorder packets
/// from each SSRC independently but the global reordering depth will be
/// still limited to make sure that no packet is delayed for too long.
pub struct ReorderingMultiBuffer {
    input_index_to_ssrc: VecDeque<Option<u32>>,
    first_input_index: usize,
    sources: LruCache<u32, InternalBuffer>,
    output: VecDeque<OutputPacket>,
    capacity: usize,
    max_ssrcs: Option<usize>,
}

impl ReorderingMultiBuffer {
    /// Create a new reordering buffer.
    ///
    /// # Arguments
    /// * `depth`: maximum number of buffered packets across all SSRCs and also
    ///   the maximum distance between sequence numbers of any pair of packets
    ///   within a single SSRC
    /// * `max_ssrcs`: maximum number of SSRCs to track; if the number of SSRCs
    ///   exceeds this limit, the least recently used SSRCs will be dropped
    ///
    /// Using unlimited number of SSRCs (i.e. `max_ssrcs == None`) is not
    /// recommended as the memory usage would not be limited in this case.
    pub fn new(depth: usize, max_ssrcs: Option<usize>) -> Self {
        Self {
            input_index_to_ssrc: VecDeque::new(),
            first_input_index: 0,
            sources: LruCache::unbounded(),
            output: VecDeque::with_capacity(depth.min(8)),
            capacity: depth,
            max_ssrcs,
        }
    }

    /// Estimate packet index from a given sequence number.
    pub fn estimate_index(&self, ssrc: u32, sequence_nr: u16) -> u64 {
        self.sources
            .peek(&ssrc)
            .map(|source| source.estimate_index(sequence_nr))
            .unwrap_or(sequence_nr as u64)
    }

    /// Check if a packet with a given index would be a duplicate.
    pub fn is_duplicate(&self, ssrc: u32, index: u64) -> bool {
        self.sources
            .peek(&ssrc)
            .map(|source| source.is_duplicate(index))
            .unwrap_or(false)
    }

    /// Push a given packet into the buffer and return index of the inserted
    /// packet.
    ///
    /// The method returns an error if the packet cannot be inserted into the
    /// buffer because it is either a duplicate or the buffer would exceed its
    /// capacity.
    pub fn push(&mut self, packet: IncomingRtpPacket) -> Result<u64, ReorderingError> {
        // check if the oldest packet in the buffer is more than `capacity`
        // packets behind
        if self.input_index_to_ssrc.len() >= self.capacity {
            return Err(ReorderingError::BufferFull(packet));
        }

        let ssrc = packet.ssrc();

        let source = self
            .sources
            .get_or_insert_mut(ssrc, || InternalBuffer::new(self.capacity));

        let input_index = self.first_input_index.wrapping_add(self.input_index_to_ssrc.len());

        let output_index = source.push(InputPacket::new(packet, input_index))?;

        self.input_index_to_ssrc.push_back(Some(ssrc));

        while let Some(packet) = source.next() {
            self.output.push_back(packet);
        }

        // drop the least recently used SSRCs if we exceed the maximum allowed
        // number of SSRCs
        if let Some(max_ssrcs) = self.max_ssrcs {
            while self.sources.len() > max_ssrcs {
                if let Some((_, mut source)) = self.sources.pop_lru() {
                    while !source.is_empty() {
                        if let Some(packet) = source.take() {
                            self.output.push_back(packet);
                        }
                    }
                }
            }
        }

        Ok(output_index)
    }

    /// Take the next packet from the buffer.
    ///
    /// This method will return a packet only if it is in-order (i.e. no
    /// packets would be skipped for the corresponding SSRC) or if the
    /// corresponding SSRC has been dropped from the buffer.
    pub fn next(&mut self) -> Option<OrderedRtpPacket> {
        let packet = self.output.pop_front()?;

        self.remove_input_index(packet.input_index);

        Some(packet.into())
    }

    /// Take the next packet from the buffer.
    ///
    /// This method will either return the next in-order packet or contents
    /// of the first slot of a SSRC sub-buffer containing the oldest packet.
    /// The method will always advance the buffer state. Calling this method
    /// repeatedly will eventually drain the buffer.
    ///
    /// Note that this method may return `None` even if the buffer is not
    /// empty. It only indicates a missing packet.
    pub fn take(&mut self) -> Option<OrderedRtpPacket> {
        let packet = if let Some(p) = self.output.pop_front() {
            p
        } else {
            self.poll_oldest_source()?
        };

        self.remove_input_index(packet.input_index);

        Some(packet.into())
    }

    /// Check if the underlying buffer is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.input_index_to_ssrc.is_empty()
    }

    /// Remove a given input index from the `input_index_to_ssrc` map.
    ///
    /// The method will also remove all tombstones from the front of the map in
    /// order to keep the invariant that the front element of the map is not
    /// `None` and it will also adjust `first_input_index` accordingly.
    ///
    /// Note that the time complexity of this method is still O(1) on average
    /// because there are only two operations for each input index:
    ///
    /// * replacing the index with `None`
    /// * and removing the element from the map.
    fn remove_input_index(&mut self, input_index: usize) {
        let offset = input_index.wrapping_sub(self.first_input_index);

        self.input_index_to_ssrc[offset] = None;

        // remove all tombstones from the front of the map
        while let Some(None) = self.input_index_to_ssrc.front() {
            self.input_index_to_ssrc.pop_front();

            // ... and increment the first input index accordingly
            self.first_input_index = self.first_input_index.wrapping_add(1);
        }
    }

    /// Advance the SSRC buffer containing the oldest packet.
    ///
    /// The method will return contents of the front slot of that buffer.
    /// Returning `None` does not indicate that the buffer is empty.
    fn poll_oldest_source(&mut self) -> Option<OutputPacket> {
        if let Some(ssrc) = self.input_index_to_ssrc.front()? {
            if let Some(source) = self.sources.peek_mut(ssrc) {
                if !source.is_empty() {
                    let res = source.take();

                    // in-order packets may follow after removing the first
                    // slot; we need to move them to the output queue
                    while let Some(packet) = source.next() {
                        self.output.push_back(packet);
                    }

                    return res;
                }
            }
        }

        // NOTE: This should never happen. The invariant is that if
        //   `input_index_to_ssrc` is not empty, its front element is not
        //   `None` and the corresponding source exists and is not empty
        //   (because it must contain the oldest packet).

        panic!("inconsistent state")
    }
}

/// Reordering buffer for RTP packets from a single synchronization source.
struct InternalBuffer {
    start: Option<u64>,
    window: VecDeque<Option<OutputPacket>>,
    capacity: usize,
}

impl InternalBuffer {
    /// Create a new reordering buffer with a given depth.
    #[inline]
    fn new(depth: usize) -> Self {
        Self {
            start: None,
            window: VecDeque::with_capacity(depth.min(8)),
            capacity: depth,
        }
    }

    /// Estimate packet index from a given sequence number.
    fn estimate_index(&self, sequence_nr: u16) -> u64 {
        let start_index = self.start.unwrap_or(sequence_nr as u64);
        let last_index = start_index.wrapping_add(self.window.len() as u64);
        let last_seq_nr = last_index as u16;
        let last_roc = last_index & !0xffff;

        let new_seq_nr = sequence_nr;

        let new_roc = if last_seq_nr < 0x8000 {
            if new_seq_nr > (last_seq_nr + 0x8000) {
                last_roc.wrapping_sub(0x10000)
            } else {
                last_roc
            }
        } else if (last_seq_nr - 0x8000) > new_seq_nr {
            last_roc.wrapping_add(0x10000)
        } else {
            last_roc
        };

        new_roc | (new_seq_nr as u64)
    }

    /// Check if a packet with a given index would be a duplicate.
    fn is_duplicate(&self, index: u64) -> bool {
        let start = self.start.unwrap_or(index);

        let offset = index.wrapping_sub(start);

        // this is `index < start` in wrapping arithmetic
        if offset > (u64::MAX >> 1) {
            return true;
        }

        let Ok(offset) = usize::try_from(offset) else {
            return false;
        };

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
    fn push(&mut self, packet: InputPacket) -> Result<u64, InternalError> {
        let index = self.estimate_index(packet.sequence_number());

        if self.start.is_none() {
            self.start = Some(index);
        }

        let start = self.start.unwrap_or(index);

        let offset = index.wrapping_sub(start);

        // this is `index < start` in wrapping arithmetic
        if offset > (u64::MAX >> 1) {
            return Err(InternalError::DuplicatePacket(packet));
        }

        let Ok(offset) = usize::try_from(offset) else {
            return Err(InternalError::BufferFull(packet));
        };

        if offset < self.capacity {
            while offset >= self.window.len() {
                self.window.push_back(None);
            }

            let entry = &mut self.window[offset];

            if entry.is_some() {
                return Err(InternalError::DuplicatePacket(packet));
            }

            *entry = Some(OutputPacket::new(packet, index));

            Ok(index)
        } else {
            Err(InternalError::BufferFull(packet))
        }
    }

    /// Take the next packet from the buffer.
    ///
    /// This method will return a packet only if there is a packet in the front
    /// slot of the buffer. In other words, a packet will be returned only if
    /// it is an in-order packet and returning it would not skip any packets.
    fn next(&mut self) -> Option<OutputPacket> {
        if let Some(entry) = self.window.front() {
            if entry.is_some() {
                return self.take();
            }
        }

        None
    }

    /// Remove the front slot from the buffer and return the contained packet
    /// (if any).
    ///
    /// The method will always advance start position of the reordering window
    /// by one even if the front slot is empty or if the underlying buffer
    /// itself is empty.
    fn take(&mut self) -> Option<OutputPacket> {
        if let Some(start) = self.start.as_mut() {
            *start = start.wrapping_add(1);
        }

        self.window.pop_front()?
    }

    /// Check if the buffer is empty.
    #[inline]
    fn is_empty(&self) -> bool {
        self.window.is_empty()
    }
}

/// Helper struct.
///
/// It associates an input index with an incoming RTP packet.
struct InputPacket {
    input_index: usize,
    packet: IncomingRtpPacket,
}

impl InputPacket {
    /// Create a new input packet.
    fn new(packet: IncomingRtpPacket, input_index: usize) -> Self {
        Self { input_index, packet }
    }
}

impl Deref for InputPacket {
    type Target = IncomingRtpPacket;

    fn deref(&self) -> &Self::Target {
        &self.packet
    }
}

/// Helper struct.
///
/// It associates an input index and an output index with an incoming RTP
/// packet.
struct OutputPacket {
    input_index: usize,
    output_index: u64,
    packet: IncomingRtpPacket,
}

impl OutputPacket {
    /// Create a new output packet.
    fn new(packet: InputPacket, output_index: u64) -> Self {
        Self {
            input_index: packet.input_index,
            output_index,
            packet: packet.packet,
        }
    }
}

impl From<OutputPacket> for OrderedRtpPacket {
    fn from(packet: OutputPacket) -> Self {
        OrderedRtpPacket::new(packet.packet, packet.output_index)
    }
}

/// Helper enum.
///
/// It has the same variants as `ReorderingError` but it carries `InputPacket`
/// instead of `IncomingRtpPacket`.
enum InternalError {
    BufferFull(InputPacket),
    DuplicatePacket(InputPacket),
}

impl From<InternalError> for ReorderingError {
    fn from(err: InternalError) -> Self {
        match err {
            InternalError::BufferFull(packet) => Self::BufferFull(packet.packet),
            InternalError::DuplicatePacket(packet) => Self::DuplicatePacket(packet.packet),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::{ReorderingBuffer, ReorderingError, ReorderingMultiBuffer};

    use crate::rtp::{IncomingRtpPacket, RtpPacket};

    fn make_packet(seq: u16, ssrc: u32) -> IncomingRtpPacket {
        let packet = RtpPacket::new()
            .with_sequence_number(seq)
            .with_ssrc(ssrc);

        IncomingRtpPacket::new(packet, Instant::now())
    }

    #[test]
    fn test_wrapping_index_arithmetic() {
        let mut buffer = ReorderingBuffer::new(4);

        assert!(matches!(buffer.push(make_packet(0x1000, 1)), Ok(0x1000)));

        assert_eq!(buffer.estimate_index(0x0000), 0x0000_0000_0000_0000);
        assert_eq!(buffer.estimate_index(0x2000), 0x0000_0000_0000_2000);
        assert_eq!(buffer.estimate_index(0xf000), 0xffff_ffff_ffff_f000);

        assert!(matches!(buffer.push(make_packet(0xf000, 1)), Err(ReorderingError::DuplicatePacket(_))));
        assert!(matches!(buffer.push(make_packet(0x2000, 1)), Err(ReorderingError::BufferFull(_))));

        buffer = ReorderingBuffer::new(4);

        assert!(matches!(buffer.push(make_packet(0xe000, 1)), Ok(0xe000)));

        assert_eq!(buffer.estimate_index(0xd000), 0x0000_0000_0000_d000);
        assert_eq!(buffer.estimate_index(0xf000), 0x0000_0000_0000_f000);
        assert_eq!(buffer.estimate_index(0x1000), 0x0000_0000_0001_1000);

        assert!(matches!(buffer.push(make_packet(0xd000, 1)), Err(ReorderingError::DuplicatePacket(_))));
        assert!(matches!(buffer.push(make_packet(0x1000, 1)), Err(ReorderingError::BufferFull(_))));

        buffer = ReorderingBuffer::new(4);

        buffer.inner.start = Some(u64::MAX);

        assert!(matches!(buffer.push(make_packet(0xffff, 1)), Ok(u64::MAX)));
        assert!(matches!(buffer.push(make_packet(0x0000, 1)), Ok(0)));

        assert_eq!(buffer.estimate_index(0xf000), 0xffff_ffff_ffff_f000);
        assert_eq!(buffer.estimate_index(0x1000), 0x0000_0000_0000_1000);

        assert!(matches!(buffer.push(make_packet(0xf000, 1)), Err(ReorderingError::DuplicatePacket(_))));
        assert!(matches!(buffer.push(make_packet(0x1000, 1)), Err(ReorderingError::BufferFull(_))));
    }

    #[test]
    fn test_reordering_buffer() {
        let mut buffer = ReorderingBuffer::new(5);

        assert!(buffer.is_empty());

        assert!(matches!(buffer.push(make_packet(2, 1)), Ok(2)));
        assert!(matches!(buffer.push(make_packet(0, 1)), Err(ReorderingError::DuplicatePacket(_))));
        assert!(matches!(buffer.push(make_packet(1, 1)), Err(ReorderingError::DuplicatePacket(_))));
        assert!(matches!(buffer.push(make_packet(4, 1)), Ok(4)));
        assert!(matches!(buffer.push(make_packet(3, 1)), Ok(3)));
        assert!(matches!(buffer.push(make_packet(3, 1)), Err(ReorderingError::DuplicatePacket(_))));
        assert!(matches!(buffer.push(make_packet(6, 1)), Ok(6)));
        assert!(matches!(buffer.push(make_packet(7, 1)), Err(ReorderingError::BufferFull(_))));

        assert!(!buffer.is_empty());

        assert_eq!(buffer.next().unwrap().index(), 2);
        assert_eq!(buffer.next().unwrap().index(), 3);
        assert_eq!(buffer.next().unwrap().index(), 4);

        assert!(matches!(buffer.next(), None));

        assert!(!buffer.is_empty());

        assert!(matches!(buffer.take(), None));

        assert!(!buffer.is_empty());

        assert_eq!(buffer.next().unwrap().index(), 6);

        assert!(buffer.is_empty());
    }

    #[test]
    fn test_reordering_multi_buffer() {
        let mut buffer = ReorderingMultiBuffer::new(8, Some(2));

        assert!(buffer.is_empty());

        assert!(matches!(buffer.push(make_packet(2, 1)), Ok(2)));
        assert!(matches!(buffer.push(make_packet(0, 1)), Err(ReorderingError::DuplicatePacket(_))));
        assert!(matches!(buffer.push(make_packet(1, 1)), Err(ReorderingError::DuplicatePacket(_))));
        assert!(matches!(buffer.push(make_packet(4, 1)), Ok(4)));
        assert!(matches!(buffer.push(make_packet(3, 1)), Ok(3)));
        assert!(matches!(buffer.push(make_packet(3, 1)), Err(ReorderingError::DuplicatePacket(_))));
        assert!(matches!(buffer.push(make_packet(6, 1)), Ok(6)));
        assert!(matches!(buffer.push(make_packet(13, 1)), Err(ReorderingError::BufferFull(_))));

        assert!(matches!(buffer.push(make_packet(10, 2)), Ok(10)));
        assert!(matches!(buffer.push(make_packet(9, 2)), Err(ReorderingError::DuplicatePacket(_))));
        assert!(matches!(buffer.push(make_packet(8, 2)), Err(ReorderingError::DuplicatePacket(_))));
        assert!(matches!(buffer.push(make_packet(12, 2)), Ok(12)));
        assert!(matches!(buffer.push(make_packet(11, 2)), Ok(11)));
        assert!(matches!(buffer.push(make_packet(11, 2)), Err(ReorderingError::DuplicatePacket(_))));
        assert!(matches!(buffer.push(make_packet(21, 2)), Err(ReorderingError::BufferFull(_))));
        assert!(matches!(buffer.push(make_packet(14, 2)), Ok(14)));
        assert!(matches!(buffer.push(make_packet(15, 2)), Err(ReorderingError::BufferFull(_))));

        assert!(!buffer.is_empty());

        assert_eq!(buffer.next().unwrap().index(), 2);
        assert_eq!(buffer.next().unwrap().index(), 3);
        assert_eq!(buffer.next().unwrap().index(), 4);

        assert_eq!(buffer.next().unwrap().index(), 10);
        assert_eq!(buffer.next().unwrap().index(), 11);
        assert_eq!(buffer.next().unwrap().index(), 12);

        assert!(matches!(buffer.next(), None));

        assert!(!buffer.is_empty());

        assert!(matches!(buffer.take(), None));

        assert!(!buffer.is_empty());

        assert_eq!(buffer.next().unwrap().index(), 6);

        assert!(matches!(buffer.next(), None));

        assert!(!buffer.is_empty());

        assert!(matches!(buffer.take(), None));

        assert!(!buffer.is_empty());

        assert_eq!(buffer.next().unwrap().index(), 14);

        assert!(buffer.is_empty());
    }
}
