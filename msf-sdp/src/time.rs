//! Time description.

use std::{
    fmt::{self, Display, Formatter},
    ops::{Deref, DerefMut},
    str::FromStr,
};

use str_reader::StringReader;

use crate::{
    parser::{
        FromSessionDescriptionLines, FromSessionDescriptionLinesLossy, SessionDescriptionLines,
        SessionDescriptionLinesLossy,
    },
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
    /// Parse a given 't' line.
    fn from_t_line(line: &str) -> Result<Self, ParseError> {
        let mut reader = StringReader::new(line);

        let res = Self {
            start: reader.read_u64()?,
            stop: reader.read_u64()?,
            repeat_times: Vec::new(),
        };

        reader.skip_whitespace();

        if reader.is_empty() {
            Ok(res)
        } else {
            Err(ParseError::plain())
        }
    }

    /// Parse a given 't' line.
    fn from_t_line_lossy(line: &str) -> Self {
        let mut reader = StringReader::new(line);

        Self {
            start: reader.read_word().parse().unwrap_or(0),
            stop: reader.read_word().parse().unwrap_or(0),
            repeat_times: Vec::new(),
        }
    }

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
            write!(f, "r={repeat}\r\n")?;
        }

        Ok(())
    }
}

impl FromSessionDescriptionLines for TimeDescription {
    fn from_sdp_lines(lines: &mut SessionDescriptionLines) -> Result<Self, ParseError> {
        let (t, v) = lines.current().unwrap();

        debug_assert_eq!(t, 't');

        let mut res = Self::from_t_line(v)?;

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

impl FromSessionDescriptionLinesLossy for TimeDescription {
    fn from_sdp_lines(lines: &mut SessionDescriptionLinesLossy) -> Result<Self, ParseError> {
        let (t, v) = lines.current().unwrap();

        debug_assert_eq!(t, 't');

        let mut res = Self::from_t_line_lossy(v);

        // skip the current 't' line
        lines.next();

        while let Some((t, _)) = lines.current() {
            if t == 'r' {
                if let Ok(rt) = lines.parse() {
                    res.repeat_times.push(rt);
                }
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
            write!(f, " {offset}")?;
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
#[derive(Default, Clone)]
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
            write!(f, "{adj}")?;
        }

        for adj in iter {
            write!(f, " {adj}")?;
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
            Self::Minutes(n) => n.saturating_mul(60),
            Self::Hours(n) => n.saturating_mul(3_600),
            Self::Days(n) => n.saturating_mul(86_400),
        }
    }
}

impl Display for CompactDuration {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Self::Seconds(v) => write!(f, "{v}"),
            Self::Minutes(v) => write!(f, "{v}m"),
            Self::Hours(v) => write!(f, "{v}h"),
            Self::Days(v) => write!(f, "{v}d"),
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

        reader.skip_char();

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
            Self::Minutes(n) => n.saturating_mul(60),
            Self::Hours(n) => n.saturating_mul(3_600),
            Self::Days(n) => n.saturating_mul(86_400),
        }
    }
}

impl Display for UnsignedCompactDuration {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Self::Seconds(v) => write!(f, "{v}"),
            Self::Minutes(v) => write!(f, "{v}m"),
            Self::Hours(v) => write!(f, "{v}h"),
            Self::Days(v) => write!(f, "{v}d"),
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

        reader.skip_char();

        if reader.is_empty() {
            Ok(res)
        } else {
            Err(ParseError::plain())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{CompactDuration, RepeatTime, TimeZoneAdjustments, UnsignedCompactDuration};

    #[test]
    fn test_compact_duration() {
        let cases = [
            ("90", 90, "90"),
            ("90s", 90, "90"),
            ("5m", 300, "5m"),
            ("2h", 7_200, "2h"),
            ("7d", 604_800, "7d"),
            ("-1h", -3_600, "-1h"),
        ];

        for (input, secs, output) in cases {
            let duration = input.parse::<CompactDuration>().unwrap();

            assert_eq!(duration.as_secs(), secs);
            assert_eq!(duration.to_string(), output);
        }

        // the conversion saturates instead of overflowing
        assert_eq!(CompactDuration::Days(i64::MAX).as_secs(), i64::MAX);
        assert_eq!(CompactDuration::Days(i64::MIN).as_secs(), i64::MIN);
    }

    #[test]
    fn test_compact_duration_errors() {
        assert!("".parse::<CompactDuration>().is_err());
        assert!("h".parse::<CompactDuration>().is_err());

        // an unknown unit
        assert!("5x".parse::<CompactDuration>().is_err());

        // a trailing garbage
        assert!("5hx".parse::<CompactDuration>().is_err());
    }

    #[test]
    fn test_unsigned_compact_duration() {
        let duration = "7d".parse::<UnsignedCompactDuration>().unwrap();

        assert_eq!(duration.as_secs(), 604_800);
        assert_eq!(duration.to_string(), "7d");

        assert_eq!(
            "90".parse::<UnsignedCompactDuration>().unwrap().as_secs(),
            90
        );

        // negative durations are not allowed here
        assert!("-1h".parse::<UnsignedCompactDuration>().is_err());
        assert!("5x".parse::<UnsignedCompactDuration>().is_err());

        // the conversion saturates instead of overflowing
        assert_eq!(UnsignedCompactDuration::Days(u64::MAX).as_secs(), u64::MAX);
    }

    #[test]
    fn test_repeat_time() {
        let repeat = "604800 3600 0 90000".parse::<RepeatTime>().unwrap();

        assert_eq!(repeat.repeat_interval().as_secs(), 604_800);
        assert_eq!(repeat.active_duration().as_secs(), 3_600);
        assert_eq!(repeat.offsets().len(), 2);
        assert_eq!(repeat.offsets()[1].as_secs(), 90_000);
        assert_eq!(repeat.to_string(), "604800 3600 0 90000");

        // the active duration is mandatory
        assert!("7d".parse::<RepeatTime>().is_err());

        // an invalid offset
        assert!("7d 1h bogus".parse::<RepeatTime>().is_err());
    }

    #[test]
    fn test_tz_adjustments() {
        let adjustments = "2882844526 -1h 2898848070 0"
            .parse::<TimeZoneAdjustments>()
            .unwrap();

        assert_eq!(adjustments.len(), 2);
        assert_eq!(adjustments[0].adjustment_time(), 2882844526);
        assert_eq!(adjustments[0].offset().as_secs(), -3_600);
        assert_eq!(adjustments[1].adjustment_time(), 2898848070);
        assert_eq!(adjustments[1].offset().as_secs(), 0);

        assert_eq!(adjustments.to_string(), "2882844526 -1h 2898848070 0");

        assert!(TimeZoneAdjustments::empty().to_string().is_empty());

        // a missing offset
        assert!("2882844526".parse::<TimeZoneAdjustments>().is_err());
        assert!("2882844526 -1h 2898848070"
            .parse::<TimeZoneAdjustments>()
            .is_err());
    }
}
