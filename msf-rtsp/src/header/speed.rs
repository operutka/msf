//! Speed header and related types.

use std::{
    fmt::{self, Display, Formatter},
    str::FromStr,
};

use crate::{Error, header::HeaderFieldValue};

/// Speed header.
#[derive(Copy, Clone)]
pub struct SpeedHeader {
    min: Option<f32>,
    max: f32,
}

impl SpeedHeader {
    /// Create a new RTSP/1.0 Speed header.
    ///
    /// # Panics
    /// Panics if `max` is not greater than zero.
    #[inline]
    pub const fn new_v10(max: f32) -> Self {
        assert!(max > 0f32);

        Self { min: None, max }
    }

    /// Create a new RTSP/2.0 Speed header.
    ///
    /// # Panics
    /// Panics if `min` or `max` are not greater than zero, or if `min` is
    /// greater than `max`.
    #[inline]
    pub const fn new_v20(min: f32, max: f32) -> Self {
        assert!(min > 0f32);
        assert!(max > 0f32);
        assert!(min <= max);

        Self {
            min: Some(min),
            max,
        }
    }

    /// Get the minimum acceptable speed.
    #[inline]
    pub fn min(&self) -> f32 {
        self.min.unwrap_or(self.max)
    }

    /// Get the maximum acceptable speed.
    #[inline]
    pub fn max(&self) -> f32 {
        self.max
    }
}

impl Display for SpeedHeader {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if let Some(min) = self.min {
            write!(f, "{}-{}", min, self.max)
        } else {
            Display::fmt(&self.max, f)
        }
    }
}

impl From<SpeedHeader> for HeaderFieldValue {
    #[inline]
    fn from(value: SpeedHeader) -> Self {
        HeaderFieldValue::from(value.to_string())
    }
}

impl FromStr for SpeedHeader {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some((min, max)) = s.split_once('-') {
            let min = min
                .parse()
                .map_err(|_| Error::from_static_msg("invalid speed header"))?;

            let max = max
                .parse()
                .map_err(|_| Error::from_static_msg("invalid speed header"))?;

            if min <= 0f32 || max <= 0f32 || min > max {
                return Err(Error::from_static_msg("speed out of bounds"));
            }

            let res = Self {
                min: Some(min),
                max,
            };

            Ok(res)
        } else {
            let max = s
                .parse()
                .map_err(|_| Error::from_static_msg("invalid speed header"))?;

            if max <= 0f32 {
                return Err(Error::from_static_msg("speed out of bounds"));
            }

            let res = Self { min: None, max };

            Ok(res)
        }
    }
}

impl TryFrom<&HeaderFieldValue> for SpeedHeader {
    type Error = Error;

    fn try_from(value: &HeaderFieldValue) -> Result<Self, Self::Error> {
        value
            .to_str()
            .map_err(|_| Error::from_static_msg("header field is not UTF-8 encoded"))?
            .parse()
    }
}
