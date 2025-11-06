//! Range and Media-Range types.

use std::{
    fmt::{self, Display, Formatter},
    num::ParseFloatError,
    str::FromStr,
};

use crate::{Error, header::HeaderFieldValue};

/// NPT range.
///
/// It can be used either as the `Range` header or as the `Media-Range` header.
#[derive(Debug, Copy, Clone)]
pub enum NptRange {
    StartFrom(NptTime),
    EndAt(NptTime),
    Range(NptTime, NptTime),
}

impl Display for NptRange {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "npt=")?;

        match self {
            Self::StartFrom(start) => write!(f, "{start}-"),
            Self::EndAt(end) => write!(f, "-{end}"),
            Self::Range(start, end) => write!(f, "{start}-{end}"),
        }
    }
}

impl From<NptRange> for HeaderFieldValue {
    #[inline]
    fn from(value: NptRange) -> Self {
        HeaderFieldValue::from(value.to_string())
    }
}

impl FromStr for NptRange {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let range = s
            .strip_prefix("npt=")
            .ok_or_else(|| Error::from_static_msg("not an NPT range"))?;

        let (start, end) = range
            .split_once('-')
            .ok_or_else(|| Error::from_static_msg("invalid NPT range"))?;

        let start = if start.is_empty() {
            None
        } else {
            start
                .parse()
                .map(Some)
                .map_err(|_| Error::from_static_msg("invalid NPT range"))?
        };

        let end = if end.is_empty() {
            None
        } else {
            end.parse()
                .map(Some)
                .map_err(|_| Error::from_static_msg("invalid NPT range"))?
        };

        if let Some(start) = start {
            if let Some(end) = end {
                Ok(Self::Range(start, end))
            } else {
                Ok(Self::StartFrom(start))
            }
        } else if let Some(end) = end {
            Ok(Self::EndAt(end))
        } else {
            Err(Error::from_static_msg("invalid NPT range"))
        }
    }
}

impl TryFrom<&HeaderFieldValue> for NptRange {
    type Error = Error;

    fn try_from(value: &HeaderFieldValue) -> Result<Self, Self::Error> {
        value
            .to_str()
            .map_err(|_| Error::from_static_msg("header field is not UTF-8 encoded"))?
            .parse()
    }
}

/// NPT time.
#[derive(Debug, Copy, Clone)]
pub enum NptTime {
    Now,
    Timestamp(f64),
}

impl Display for NptTime {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Now => f.write_str("now"),
            Self::Timestamp(t) => write!(f, "{t:.3}"),
        }
    }
}

impl FromStr for NptTime {
    type Err = ParseFloatError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "now" {
            Ok(Self::Now)
        } else {
            s.parse().map(Self::Timestamp)
        }
    }
}
