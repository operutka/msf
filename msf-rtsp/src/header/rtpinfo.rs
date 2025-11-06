//! RTP-Info header and related types.

use std::{
    borrow::{Borrow, Cow},
    fmt::{self, Display, Formatter},
};

use crate::header::HeaderFieldValue;

/// RTP info header field.
#[derive(Clone)]
pub struct RTPInfo {
    inner: RTPInfoRef<'static>,
}

impl RTPInfo {
    /// Create a new RTP-Info header.
    pub fn new<T>(url: T) -> Self
    where
        T: Into<String>,
    {
        let inner = RTPInfoRef {
            url: Cow::Owned(url.into()),
            seq: None,
            rtp_time: None,
        };

        Self { inner }
    }

    /// Set the RTP packet sequence number.
    #[inline]
    pub const fn with_seq(mut self, seq: u16) -> Self {
        self.inner.seq = Some(seq);
        self
    }

    /// Set the RTP timestamp.
    #[inline]
    pub const fn with_rtp_time(mut self, rtp_time: u32) -> Self {
        self.inner.rtp_time = Some(rtp_time);
        self
    }
}

impl Borrow<RTPInfoRef<'static>> for RTPInfo {
    #[inline]
    fn borrow(&self) -> &RTPInfoRef<'static> {
        &self.inner
    }
}

impl Display for RTPInfo {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(Borrow::<RTPInfoRef>::borrow(self), f)
    }
}

impl From<RTPInfo> for HeaderFieldValue {
    #[inline]
    fn from(value: RTPInfo) -> Self {
        HeaderFieldValue::from(value.to_string())
    }
}

/// RTP info header field.
#[derive(Clone)]
pub struct RTPInfoRef<'a> {
    url: Cow<'a, str>,
    seq: Option<u16>,
    rtp_time: Option<u32>,
}

impl<'a> RTPInfoRef<'a> {
    /// Create a new RTP-Info header.
    #[inline]
    pub const fn new(url: &'a str) -> Self {
        Self {
            url: Cow::Borrowed(url),
            seq: None,
            rtp_time: None,
        }
    }
}

impl RTPInfoRef<'_> {
    /// Set the RTP packet sequence number.
    #[inline]
    pub const fn with_seq(mut self, seq: u16) -> Self {
        self.seq = Some(seq);
        self
    }

    /// Set the RTP timestamp.
    #[inline]
    pub const fn with_rtp_time(mut self, rtp_time: u32) -> Self {
        self.rtp_time = Some(rtp_time);
        self
    }
}

impl Display for RTPInfoRef<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "url={}", self.url)?;

        if let Some(seq) = self.seq {
            write!(f, ";seq={seq}")?;
        }

        if let Some(rtp_time) = self.rtp_time {
            write!(f, ";rtptime={rtp_time}")?;
        }

        Ok(())
    }
}

impl From<RTPInfoRef<'_>> for HeaderFieldValue {
    #[inline]
    fn from(value: RTPInfoRef) -> Self {
        HeaderFieldValue::from(value.to_string())
    }
}
