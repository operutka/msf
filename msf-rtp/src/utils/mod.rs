//! Helpers.

mod reorder;

use std::time::{Duration, SystemTime};

pub use self::reorder::{
    OrderedRtpPacket, ReorderingBuffer, ReorderingError, ReorderingMultiBuffer,
};

/// Get NTP timestamp as a 32.32 fixed point number.
///
/// This timestamp can be used for RTCP sender reports.
pub fn ntp_timestamp() -> u64 {
    let ts = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO);

    let s = ts.as_secs();
    let n = ts.subsec_nanos();

    let f = (n as u64) * (1u64 << 32) / 1_000_000_000u64;

    ((s + 2_208_988_800) << 32) + f
}
