use std::{cmp::Ordering, collections::BTreeMap};

/// NAL unit reordering buffer.
///
/// The reordering buffer can be used for NAL unit reordering into their
/// original decoding order. Reordering is based on the DON numbers derived
/// from the incoming RTP packets.
///
/// # Operation
///
/// 1. Push a NAL unit to the buffer using the `push` method.
/// 2. Keep calling the `take` method until it returns `None`.
/// 3. If there are more NAL units to be reordered, go to 1.
/// 4. If there are no more NAL units to be reordered, keep calling the `flush`
///    method until it returns `None`.
pub struct ReorderingBuffer<T> {
    buffer: BTreeMap<ReorderingBufferKey, T>,
    max_don_diff: i32,
    max_nal_units: usize,
    last_don: u16,
    last_abs_don: Option<i32>,
    next_packet_id: u32,
}

impl<T> ReorderingBuffer<T> {
    const MIN_ABS_DON: i32 = i32::MIN / 2;
    const MAX_ABS_DON: i32 = i32::MAX / 2;

    /// Create a new reordering buffer.
    ///
    /// # Arguments
    ///
    /// * `max_don_diff` - value of the sprop-max-don-diff parameter
    /// * `max_nal_units` - value of the sprop-depack-buf-nalus parameter
    pub fn new(max_don_diff: u16, max_nal_units: usize) -> Self {
        ReorderingBuffer {
            buffer: BTreeMap::new(),
            max_don_diff: max_don_diff.min(32_767) as i32,
            max_nal_units: max_nal_units.min(32_767),
            last_don: 0,
            last_abs_don: None,
            next_packet_id: 0,
        }
    }

    /// Push a given NAL unit to the buffer.
    pub fn push(&mut self, don: u16, nal_unit: T) {
        let mut current_abs_don = if let Some(last_abs_don) = self.last_abs_don {
            let current_sub_last = don.wrapping_sub(self.last_don);
            let last_sub_current = self.last_don.wrapping_sub(don);

            if current_sub_last < last_sub_current {
                last_abs_don.wrapping_add(current_sub_last as i32)
            } else if current_sub_last > last_sub_current {
                last_abs_don.wrapping_sub(last_sub_current as i32)
            } else if don < self.last_don {
                last_abs_don.wrapping_add(current_sub_last as i32)
            } else {
                last_abs_don.wrapping_sub(current_sub_last as i32)
            }
        } else {
            don as i32
        };

        let key = ReorderingBufferKey::new(current_abs_don, self.next_packet_id);

        self.next_packet_id = self.next_packet_id.wrapping_add(1);

        self.buffer.insert(key, nal_unit);

        self.last_don = don;

        // NOTE: This will prevent absolute DON overflow. We don't really care about the value of
        //   the absolute DON as long as the NAL unit order is correct.
        // NOTE: Shifting the absolute DON values by the current absolute DON value so that the
        //   current absolute DON value becomes zero is safe because the maximum absolute DON
        //   difference within the buffer is limited to 32767.
        if !(Self::MIN_ABS_DON..=Self::MAX_ABS_DON).contains(&current_abs_don) {
            for (mut key, nal_unit) in std::mem::take(&mut self.buffer) {
                let abs_don = key.abs_don - current_abs_don;

                key.abs_don = abs_don;

                self.buffer.insert(key, nal_unit);
            }

            current_abs_don = 0;
        }

        self.last_abs_don = Some(current_abs_don);
    }

    /// Take the next available NAL unit.
    pub fn take(&mut self) -> Option<T> {
        if self.max_don_diff > 0 {
            let buffered = self.buffer.len();

            let min_abs_don = self
                .buffer
                .first_key_value()
                .map(|(k, _)| k.abs_don)
                .unwrap_or(0);

            let max_abs_don = self
                .buffer
                .last_key_value()
                .map(|(k, _)| k.abs_don)
                .unwrap_or(0);

            let abs_don_diff = max_abs_don - min_abs_don;

            if abs_don_diff < self.max_don_diff && buffered <= self.max_nal_units {
                return None;
            }
        }

        self.remove()
    }

    /// Flush the buffer and return any remaining NAL unit.
    pub fn flush(&mut self) -> Option<T> {
        self.remove()
    }

    /// Remove the first NAL unit from the buffer.
    pub fn remove(&mut self) -> Option<T> {
        self.buffer.pop_first().map(|(_, nal_unit)| nal_unit)
    }

    /// Get the number of NAL units in the buffer.
    pub fn len(&self) -> usize {
        self.buffer.len()
    }
}

/// Key for the reordering buffer.
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
struct ReorderingBufferKey {
    abs_don: i32,
    packet_id: u32,
}

impl ReorderingBufferKey {
    /// Create a new key.
    fn new(abs_don: i32, packet_id: u32) -> Self {
        ReorderingBufferKey { abs_don, packet_id }
    }
}

impl PartialOrd for ReorderingBufferKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ReorderingBufferKey {
    fn cmp(&self, other: &Self) -> Ordering {
        let ordering = self.abs_don.cmp(&other.abs_don);

        if ordering == Ordering::Equal {
            self.packet_id.cmp(&other.packet_id)
        } else {
            ordering
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ReorderingBuffer;

    /// Fake NAL unit.
    struct InternalNalUnit {
        rtp_timestamp: u64,
    }

    /// Helper function.
    fn create_nal_unit(rtp_timestamp: u64) -> InternalNalUnit {
        InternalNalUnit { rtp_timestamp }
    }

    /// Helper function.
    fn get_timestamp_abs_don_pairs(buffer: &ReorderingBuffer<InternalNalUnit>) -> Vec<(u64, i32)> {
        buffer
            .buffer
            .iter()
            .map(|(k, v)| (v.rtp_timestamp, k.abs_don))
            .collect::<Vec<_>>()
    }

    #[test]
    fn test_reordering_buffer_abs_don_calculation() {
        // DON[n] == DON[n-1]
        let mut buffer = ReorderingBuffer::new(u16::MAX, 5);

        assert_eq!(buffer.max_don_diff, 32_767);

        buffer.push(100, create_nal_unit(0));
        buffer.push(100, create_nal_unit(1));

        let expectd = [(0, 100), (1, 100)];

        assert_eq!(&expectd[..], get_timestamp_abs_don_pairs(&buffer));

        // DON[n] > DON[n-1] and DON[n] - DON[n-1] < 32768
        buffer = ReorderingBuffer::new(u16::MAX, 5);

        buffer.push(100, create_nal_unit(0));
        buffer.push(200, create_nal_unit(1));

        let expectd = [(0, 100), (1, 200)];

        assert_eq!(&expectd[..], get_timestamp_abs_don_pairs(&buffer));

        buffer = ReorderingBuffer::new(u16::MAX, 5);

        buffer.push(100, create_nal_unit(0));
        buffer.push(32_867, create_nal_unit(1));

        let expectd = [(0, 100), (1, 32_867)];

        assert_eq!(&expectd[..], get_timestamp_abs_don_pairs(&buffer));

        // DON[n] < DON[n-1] and DON[n-1] - DON[n] >= 32768
        buffer = ReorderingBuffer::new(u16::MAX, 5);

        buffer.push(65_500, create_nal_unit(0));
        buffer.push(100, create_nal_unit(1));

        let expectd = [(0, 65_500), (1, 65_636)];

        assert_eq!(&expectd[..], get_timestamp_abs_don_pairs(&buffer));

        buffer = ReorderingBuffer::new(u16::MAX, 5);

        buffer.push(32_868, create_nal_unit(0));
        buffer.push(100, create_nal_unit(1));

        let expectd = [(0, 32_868), (1, 65_636)];

        assert_eq!(&expectd[..], get_timestamp_abs_don_pairs(&buffer));

        // DON[n] > DON[n-1] and DON[n] - DON[n-1] >= 32768
        buffer = ReorderingBuffer::new(u16::MAX, 5);

        buffer.push(100, create_nal_unit(0));
        buffer.push(65_500, create_nal_unit(1));

        let expectd = [(1, -36), (0, 100)];

        assert_eq!(&expectd[..], get_timestamp_abs_don_pairs(&buffer));

        buffer = ReorderingBuffer::new(u16::MAX, 5);

        buffer.push(100, create_nal_unit(0));
        buffer.push(32_868, create_nal_unit(1));

        let expectd = [(1, -32_668), (0, 100)];

        assert_eq!(&expectd[..], get_timestamp_abs_don_pairs(&buffer));

        // DON[n] < DON[n-1] and DON[n-1] - DON[n] < 32768
        buffer = ReorderingBuffer::new(u16::MAX, 5);

        buffer.push(200, create_nal_unit(0));
        buffer.push(100, create_nal_unit(1));

        let expectd = [(1, 100), (0, 200)];

        assert_eq!(&expectd[..], get_timestamp_abs_don_pairs(&buffer));

        buffer = ReorderingBuffer::new(u16::MAX, 5);

        buffer.push(32_867, create_nal_unit(0));
        buffer.push(100, create_nal_unit(1));

        let expectd = [(1, 100), (0, 32_867)];

        assert_eq!(&expectd[..], get_timestamp_abs_don_pairs(&buffer));
    }

    #[test]
    fn test_reordering_buffer_min_abs_don() {
        const MIN_ABS_DON: i32 = ReorderingBuffer::<InternalNalUnit>::MIN_ABS_DON;

        let mut buffer = ReorderingBuffer::new(u16::MAX, 5);

        buffer.last_don = 1000;
        buffer.last_abs_don = Some(MIN_ABS_DON);

        buffer.push(1000, create_nal_unit(0));

        let expectd = [(0, MIN_ABS_DON)];

        assert_eq!(&expectd[..], get_timestamp_abs_don_pairs(&buffer));

        buffer.push(0, create_nal_unit(1));

        assert_eq!(buffer.last_abs_don, Some(0));

        let expectd = [(1, 0), (0, 1000)];

        assert_eq!(&expectd[..], get_timestamp_abs_don_pairs(&buffer));
    }

    #[test]
    fn test_reordering_buffer_max_abs_don() {
        const MAX_ABS_DON: i32 = ReorderingBuffer::<InternalNalUnit>::MAX_ABS_DON;

        let mut buffer = ReorderingBuffer::new(u16::MAX, 5);

        buffer.last_don = 0;
        buffer.last_abs_don = Some(MAX_ABS_DON);

        buffer.push(0, create_nal_unit(0));

        let expectd = [(0, MAX_ABS_DON)];

        assert_eq!(&expectd[..], get_timestamp_abs_don_pairs(&buffer));

        buffer.push(1000, create_nal_unit(1));

        assert_eq!(buffer.last_abs_don, Some(0));

        let expectd = [(0, -1000), (1, 0)];

        assert_eq!(&expectd[..], get_timestamp_abs_don_pairs(&buffer));
    }

    #[test]
    fn test_reordering_buffer_take() {
        let mut buffer = ReorderingBuffer::new(1000, 5);

        buffer.push(100, create_nal_unit(0));
        buffer.push(200, create_nal_unit(1));
        buffer.push(300, create_nal_unit(2));
        buffer.push(400, create_nal_unit(3));
        buffer.push(500, create_nal_unit(4));

        assert!(buffer.take().is_none());

        buffer.push(600, create_nal_unit(5));

        assert!(buffer.take().is_some());
        assert!(buffer.take().is_none());

        buffer = ReorderingBuffer::new(1000, 5);

        buffer.push(100, create_nal_unit(0));
        buffer.push(1099, create_nal_unit(1));

        assert!(buffer.take().is_none());

        buffer.push(1100, create_nal_unit(3));

        assert!(buffer.take().is_some());
        assert!(buffer.take().is_none());
    }
}
