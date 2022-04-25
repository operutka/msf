use std::{
    error::Error,
    fmt::{self, Display, Formatter},
};

use bytes::{Buf, Bytes};

#[derive(Debug, Copy, Clone)]
pub struct InvalidByteStream;

impl Display for InvalidByteStream {
    #[inline]
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.write_str("invalid h264 byte stream")
    }
}

impl Error for InvalidByteStream {}

/// Extract the next NAL unit from a given NAL unit byte stream.
pub fn extract_nal_unit(data: &mut Bytes) -> Result<Option<Bytes>, InvalidByteStream> {
    loop {
        if data.starts_with(&[0, 0, 1]) {
            // skip the start code
            data.advance(3);

            // find the end of the NAL unit
            let len = find_nal_unit_end(data);

            let nal_unit = data.split_to(len);

            return Ok(Some(nal_unit));
        } else if let Some(first) = data.first() {
            if *first == 0 {
                data.advance(1);
            } else {
                return Err(InvalidByteStream);
            }
        } else {
            return Ok(None);
        }
    }
}

/// Find the end of the current NAL unit.
fn find_nal_unit_end(stream: &[u8]) -> usize {
    for i in 0..stream.len() {
        let suffix = &stream[i..];

        if suffix.starts_with(&[0, 0, 0]) || suffix.starts_with(&[0, 0, 1]) {
            return i;
        }
    }

    stream.len()
}
