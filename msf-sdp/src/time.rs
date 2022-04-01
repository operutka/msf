//! Time description.

use std::{
    fmt::{self, Display, Formatter},
    ops::{Deref, DerefMut},
    str::FromStr,
};

use str_reader::StringReader;

use crate::{
    parser::{FromSessionDescriptionLines, SessionDescriptionLines},
    ParseError,
};

/// Time description.
#[derive(Clone)]
pub struct TimeDescription {
    start: u64,
    stop: u64,
    repeat_times: Vec<RepeatTime>,
}

impl TimeDescription {
    /// Create a new time description.
    #[inline]
    pub fn new<T>(start: u64, stop: u64, repeat_times: T) -> Self
    where
        T: Into<Vec<RepeatTime>>,
    {
        Self {
            start,
            stop,
            repeat_times: repeat_times.into(),
        }
    }

    /// Get the start time.
    #[inline]
    pub fn start(&self) -> u64 {
        self.start
    }

    /// Get the stop time.
    #[inline]
    pub fn stop(&self) -> u64 {
        self.stop
    }

    /// Get the repeat times.
    #[inline]
    pub fn repeat_times(&self) -> &[RepeatTime] {
        &self.repeat_times
    }
}

impl Default for TimeDescription {
    #[inline]
    fn default() -> Self {
        Self::new(0, 0, Vec::new())
    }
}

impl Display for TimeDescription {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "t={} {}\r\n", self.start, self.stop)?;

        for repeat in &self.repeat_times {
            write!(f, "r={}\r\n", repeat)?;
        }

        Ok(())
    }
}

impl FromSessionDescriptionLines for TimeDescription {
    fn from_sdp_lines(lines: &mut SessionDescriptionLines) -> Result<Self, ParseError> {
        let (t, v) = lines.current().unwrap();

        debug_assert_eq!(t, 't');

        let mut reader = StringReader::new(v);

        let mut res = Self {
            start: reader.read_u64()?,
            stop: reader.read_u64()?,
            repeat_times: Vec::new(),
        };

        reader.skip_whitespace();

        if !reader.is_empty() {
            return Err(ParseError::plain());
        }

        lines.next()?;

        while let Some((t, _)) = lines.current() {
            if t == 'r' {
                let repeat_time = lines
                    .parse()
                    .map_err(|err| ParseError::with_cause_and_msg("invalid repeat time", err))?;

                res.repeat_times.push(repeat_time);
            } else {
                break;
            }
        }

        Ok(res)
    }
}

/// Repeat time.
#[derive(Clone)]
pub struct RepeatTime {
    repeat_interval: UnsignedCompactDuration,
    active_duration: UnsignedCompactDuration,
    offsets: Vec<UnsignedCompactDuration>,
}

impl RepeatTime {
    /// Create a new repeat time.
    #[inline]
    pub fn new<T>(
        repeat_interval: UnsignedCompactDuration,
        active_duration: UnsignedCompactDuration,
        offsets: T,
    ) -> Self
    where
        T: Into<Vec<UnsignedCompactDuration>>,
    {
        Self {
            repeat_interval,
            active_duration,
            offsets: offsets.into(),
        }
    }

    /// Get the repeat interval.
    #[inline]
    pub fn repeat_interval(&self) -> UnsignedCompactDuration {
        self.repeat_interval
    }

    /// Get the active duration.
    #[inline]
    pub fn active_duration(&self) -> UnsignedCompactDuration {
        self.active_duration
    }

    /// Get the offsets from the corresponding start time.
    #[inline]
    pub fn offsets(&self) -> &[UnsignedCompactDuration] {
        &self.offsets
    }
}

impl Display for RepeatTime {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{} {}", self.repeat_interval, self.active_duration)?;

        for offset in &self.offsets {
            write!(f, " {}", offset)?;
        }

        Ok(())
    }
}

impl FromStr for RepeatTime {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut reader = StringReader::new(s);

        let mut res = Self {
            repeat_interval: reader.parse_word()?,
            active_duration: reader.parse_word()?,
            offsets: Vec::new(),
        };

        loop {
            reader.skip_whitespace();

            if reader.is_empty() {
                return Ok(res);
            }

            res.offsets.push(reader.parse_word()?);
        }
    }
}

/// Timezone adjustment.
#[derive(Copy, Clone)]
pub struct TimeZoneAdjustment {
    adjustment_time: u64,
    offset: CompactDuration,
}

impl TimeZoneAdjustment {
    /// Create a new timezone adjustment.
    #[inline]
    pub const fn new(adjustment_time: u64, offset: CompactDuration) -> Self {
        Self {
            adjustment_time,
            offset,
        }
    }

    /// Get the NTP time at which the adjustment is supposed to happen.
    #[inline]
    pub fn adjustment_time(&self) -> u64 {
        self.adjustment_time
    }

    /// Get the adjustment offset.
    #[inline]
    pub fn offset(&self) -> CompactDuration {
        self.offset
    }
}

impl Display for TimeZoneAdjustment {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{} {}", self.adjustment_time, self.offset)
    }
}

impl FromStr for TimeZoneAdjustment {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut reader = StringReader::new(s);

        let res = Self {
            adjustment_time: reader.read_u64()?,
            offset: reader.parse_word()?,
        };

        reader.skip_whitespace();

        if reader.is_empty() {
            Ok(res)
        } else {
            Err(ParseError::plain())
        }
    }
}

/// Collection of timezone adjustments.
#[derive(Clone)]
pub struct TimeZoneAdjustments {
    inner: Vec<TimeZoneAdjustment>,
}

impl TimeZoneAdjustments {
    /// Create a new empty collection of timezone adjustments.
    #[inline]
    pub const fn empty() -> Self {
        Self { inner: Vec::new() }
    }
}

impl Deref for TimeZoneAdjustments {
    type Target = Vec<TimeZoneAdjustment>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for TimeZoneAdjustments {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl Display for TimeZoneAdjustments {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let mut iter = self.inner.iter();

        if let Some(adj) = iter.next() {
            write!(f, "{}", adj)?;
        }

        for adj in iter {
            write!(f, " {}", adj)?;
        }

        Ok(())
    }
}

impl FromStr for TimeZoneAdjustments {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut reader = StringReader::new(s);

        let mut res = Self::empty();

        loop {
            let adjustment_time = reader.read_u64()?;
            let offset = reader.parse_word()?;

            res.inner
                .push(TimeZoneAdjustment::new(adjustment_time, offset));

            reader.skip_whitespace();

            if reader.is_empty() {
                return Ok(res);
            }
        }
    }
}

/// Duration that can be expressed in the compact form used in SDP.
#[derive(Copy, Clone)]
pub enum CompactDuration {
    Seconds(i64),
    Minutes(i64),
    Hours(i64),
    Days(i64),
}

impl CompactDuration {
    /// Get the duration in seconds.
    #[inline]
    pub fn as_secs(&self) -> i64 {
        match *self {
            Self::Seconds(n) => n,
            Self::Minutes(n) => n * 60,
            Self::Hours(n) => n * 3_600,
            Self::Days(n) => n * 86_400,
        }
    }
}

impl Display for CompactDuration {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Self::Seconds(v) => write!(f, "{}", v),
            Self::Minutes(v) => write!(f, "{}m", v),
            Self::Hours(v) => write!(f, "{}h", v),
            Self::Days(v) => write!(f, "{}d", v),
        }
    }
}

impl FromStr for CompactDuration {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut reader = StringReader::new(s.trim());

        let n = reader
            .read_until(|c| !c.is_ascii_digit() && c != '-')
            .parse()?;

        let res = match reader.current_char() {
            Some('s') => Self::Seconds(n),
            Some('m') => Self::Minutes(n),
            Some('h') => Self::Hours(n),
            Some('d') => Self::Days(n),
            None => Self::Seconds(n),
            _ => return Err(ParseError::plain()),
        };

        if reader.is_empty() {
            Ok(res)
        } else {
            Err(ParseError::plain())
        }
    }
}

/// Unsigned duration that can be expressed in the compact form used in SDP.
#[derive(Copy, Clone)]
pub enum UnsignedCompactDuration {
    Seconds(u64),
    Minutes(u64),
    Hours(u64),
    Days(u64),
}

impl UnsignedCompactDuration {
    /// Get the duration in seconds.
    #[inline]
    pub fn as_secs(&self) -> u64 {
        match *self {
            Self::Seconds(n) => n,
            Self::Minutes(n) => n * 60,
            Self::Hours(n) => n * 3_600,
            Self::Days(n) => n * 86_400,
        }
    }
}

impl Display for UnsignedCompactDuration {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Self::Seconds(v) => write!(f, "{}", v),
            Self::Minutes(v) => write!(f, "{}m", v),
            Self::Hours(v) => write!(f, "{}h", v),
            Self::Days(v) => write!(f, "{}d", v),
        }
    }
}

impl FromStr for UnsignedCompactDuration {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut reader = StringReader::new(s.trim());

        let n = reader.read_until(|c| !c.is_ascii_digit()).parse()?;

        let res = match reader.current_char() {
            Some('s') => Self::Seconds(n),
            Some('m') => Self::Minutes(n),
            Some('h') => Self::Hours(n),
            Some('d') => Self::Days(n),
            None => Self::Seconds(n),
            _ => return Err(ParseError::plain()),
        };

        if reader.is_empty() {
            Ok(res)
        } else {
            Err(ParseError::plain())
        }
    }
}
