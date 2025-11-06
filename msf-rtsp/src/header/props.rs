//! Media-Properties and related types.

use std::{
    borrow::{Borrow, Cow},
    fmt::{self, Display, Formatter},
    ops::Deref,
    str::FromStr,
};

use str_reader::StringReader;

#[cfg(feature = "abs-time")]
use chrono::{DateTime, Utc};

use crate::{
    Error,
    header::{CharExt, HeaderFieldValue, StringReaderExt, ValueListDisplay},
};

/// Media properties header.
#[derive(Default, Clone)]
pub struct MediaPropertiesHeader {
    random_access: Option<RandomAccess>,
    content_modifications: Option<ContentModifications>,
    retention: Option<Retention>,
    scales: Option<Scales>,
    other: Vec<String>,
}

impl MediaPropertiesHeader {
    /// Create a new media properties header with no properties set.
    #[inline]
    pub const fn new() -> Self {
        Self {
            random_access: None,
            content_modifications: None,
            retention: None,
            scales: None,
            other: Vec::new(),
        }
    }

    /// Get the random access property.
    #[inline]
    pub fn random_access(&self) -> Option<RandomAccess> {
        self.random_access
    }

    /// Set the random access property.
    #[inline]
    pub const fn with_random_access(mut self, random_access: Option<RandomAccess>) -> Self {
        self.random_access = random_access;
        self
    }

    /// Get the content modifications property.
    #[inline]
    pub fn content_modifications(&self) -> Option<ContentModifications> {
        self.content_modifications
    }

    /// Set the content modifications property.
    #[inline]
    pub const fn with_content_modifications(
        mut self,
        content_modifications: Option<ContentModifications>,
    ) -> Self {
        self.content_modifications = content_modifications;
        self
    }

    /// Get the retention property.
    #[inline]
    pub fn retention(&self) -> Option<Retention> {
        self.retention
    }

    /// Set the retention property.
    #[inline]
    pub const fn with_retention(mut self, retention: Option<Retention>) -> Self {
        self.retention = retention;
        self
    }

    /// Get the scales property.
    #[inline]
    pub fn scales(&self) -> Option<&[Scale]> {
        self.scales.as_ref().map(|s| &s.inner[..])
    }

    /// Set the scales property.
    #[inline]
    pub fn with_scales(mut self, scales: Option<Scales>) -> Self {
        self.scales = scales;
        self
    }

    /// Get other properties.
    #[inline]
    pub fn other_properties(&self) -> &[String] {
        &self.other
    }

    /// Set other properties.
    pub fn with_other_properties<T>(mut self, other: T) -> Self
    where
        T: Into<Vec<String>>,
    {
        self.other = other.into();
        self
    }
}

impl Display for MediaPropertiesHeader {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let props = [
            self.random_access.map(MediaProperty::from),
            self.content_modifications.map(MediaProperty::from),
            self.retention.map(MediaProperty::from),
            self.scales.as_ref().map(MediaProperty::from),
        ];

        let other = self
            .other
            .iter()
            .map(|p| MediaProperty::Other(Cow::Borrowed(p)));

        let properties = props.into_iter().flatten().chain(other);

        Display::fmt(&ValueListDisplay::new(", ", properties), f)
    }
}

impl From<MediaPropertiesHeader> for HeaderFieldValue {
    #[inline]
    fn from(header: MediaPropertiesHeader) -> Self {
        HeaderFieldValue::from(header.to_string())
    }
}

impl FromStr for MediaPropertiesHeader {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut reader = StringReader::new(s.trim());

        let mut res = Self::new();

        while !reader.is_empty() {
            let property = reader
                .parse_media_property()
                .map_err(|err| Error::from_static_msg_and_cause("invalid media property", err))?;

            match property {
                MediaProperty::RandomAccess(p) => res.random_access = Some(p),
                MediaProperty::ContentModifications(p) => res.content_modifications = Some(p),
                MediaProperty::Retention(p) => res.retention = Some(p),
                MediaProperty::Scales(p) => res.scales = Some(p.into_owned()),
                MediaProperty::Other(p) => res.other.push(p.into_owned()),
            }

            if reader.match_rtsp_separator(',').is_err() {
                break;
            }
        }

        if reader.is_empty() {
            Ok(res)
        } else {
            Err(Error::from_static_msg("unexpected character"))
        }
    }
}

impl TryFrom<&HeaderFieldValue> for MediaPropertiesHeader {
    type Error = Error;

    fn try_from(value: &HeaderFieldValue) -> Result<Self, Self::Error> {
        value
            .to_str()
            .map_err(|_| Error::from_static_msg("header field is not UTF-8 encoded"))?
            .parse()
    }
}

/// Random access media property.
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum RandomAccess {
    RandomAccess(Option<f32>),
    BeginningOnly,
    NoSeeking,
}

impl Display for RandomAccess {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::RandomAccess(Some(max_delta)) => write!(f, "Random-Access={max_delta}"),
            Self::RandomAccess(None) => f.write_str("Random-Access"),
            Self::BeginningOnly => f.write_str("Beginning-Only"),
            Self::NoSeeking => f.write_str("No-Seeking"),
        }
    }
}

/// Content modifications media property.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ContentModifications {
    Immutable,
    Dynamic,
    TimeProgressing,
}

impl Display for ContentModifications {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Immutable => "Immutable",
            Self::Dynamic => "Dynamic",
            Self::TimeProgressing => "Time-Progressing",
        };

        f.write_str(s)
    }
}

/// Retention media property.
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum Retention {
    Unlimited,
    #[cfg_attr(docsrs, doc(cfg(feature = "abs-time")))]
    #[cfg(feature = "abs-time")]
    TimeLimited(DateTime<Utc>),
    TimeDuration(f32),
}

impl Display for Retention {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unlimited => f.write_str("Unlimited"),
            #[cfg(feature = "abs-time")]
            Self::TimeLimited(t) => write!(f, "Time-Limited={}", t.format("%Y%m%dT%H%M%S%.3fZ")),
            Self::TimeDuration(d) => write!(f, "Time-Duration={d}"),
        }
    }
}

/// Media scale.
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum Scale {
    Value(f32),
    Range(f32, f32),
}

impl Display for Scale {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Value(v) => Display::fmt(v, f),
            Self::Range(start, end) => write!(f, "{start}:{end}"),
        }
    }
}

/// Scales media property.
#[derive(Clone)]
pub struct Scales {
    inner: Vec<Scale>,
}

impl Scales {
    /// Create a new scales media property.
    pub fn new<T>(scales: T) -> Self
    where
        T: Into<Vec<Scale>>,
    {
        Self {
            inner: scales.into(),
        }
    }
}

impl Display for Scales {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Scales=\"")?;

        let mut scales = self.inner.iter();

        if let Some(scale) = scales.next() {
            Display::fmt(scale, f)?;
        }

        for scale in scales {
            write!(f, ", {scale}")?;
        }

        f.write_str("\"")
    }
}

impl AsRef<[Scale]> for Scales {
    #[inline]
    fn as_ref(&self) -> &[Scale] {
        &self.inner
    }
}

impl Borrow<[Scale]> for Scales {
    #[inline]
    fn borrow(&self) -> &[Scale] {
        &self.inner
    }
}

impl Deref for Scales {
    type Target = [Scale];

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// Media property reference.
#[derive(Clone)]
enum MediaProperty<'a> {
    RandomAccess(RandomAccess),
    ContentModifications(ContentModifications),
    Retention(Retention),
    Scales(Cow<'a, Scales>),
    Other(Cow<'a, str>),
}

impl Display for MediaProperty<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::RandomAccess(p) => Display::fmt(p, f),
            Self::ContentModifications(p) => Display::fmt(p, f),
            Self::Retention(p) => Display::fmt(p, f),
            Self::Scales(p) => Display::fmt(p, f),
            Self::Other(p) => f.write_str(p),
        }
    }
}

impl From<RandomAccess> for MediaProperty<'_> {
    #[inline]
    fn from(property: RandomAccess) -> Self {
        Self::RandomAccess(property)
    }
}

impl From<ContentModifications> for MediaProperty<'_> {
    #[inline]
    fn from(property: ContentModifications) -> Self {
        Self::ContentModifications(property)
    }
}

impl From<Retention> for MediaProperty<'_> {
    #[inline]
    fn from(property: Retention) -> Self {
        Self::Retention(property)
    }
}

impl<'a> From<&'a Scales> for MediaProperty<'a> {
    #[inline]
    fn from(property: &'a Scales) -> Self {
        Self::Scales(Cow::Borrowed(property))
    }
}

impl From<Scales> for MediaProperty<'_> {
    #[inline]
    fn from(property: Scales) -> Self {
        Self::Scales(Cow::Owned(property))
    }
}

/// Helper trait.
trait MediaPropertyParser<'a> {
    /// Parse the next media property.
    fn parse_media_property(&mut self) -> Result<MediaProperty<'a>, Error>;

    /// Read other media property value.
    fn read_other_media_property_value(&mut self) -> Result<&'a str, Error>;

    /// Parse scales.
    fn parse_scales(&mut self) -> Result<Scales, Error>;
}

impl<'a> MediaPropertyParser<'a> for StringReader<'a> {
    fn parse_media_property(&mut self) -> Result<MediaProperty<'a>, Error> {
        let s = self.as_str();

        let mut reader = StringReader::new(s);

        let name = reader.read_rtsp_token()?;

        let property = if name.eq_ignore_ascii_case("Random-Access") {
            if reader.match_rtsp_separator('=').is_ok() {
                let max_delta = reader.parse_positive_f32()?;

                MediaProperty::from(RandomAccess::RandomAccess(Some(max_delta)))
            } else {
                MediaProperty::from(RandomAccess::RandomAccess(None))
            }
        } else if name.eq_ignore_ascii_case("Beginning-Only") {
            MediaProperty::from(RandomAccess::BeginningOnly)
        } else if name.eq_ignore_ascii_case("No-Seeking") {
            MediaProperty::from(RandomAccess::NoSeeking)
        } else if name.eq_ignore_ascii_case("Immutable") {
            MediaProperty::from(ContentModifications::Immutable)
        } else if name.eq_ignore_ascii_case("Dynamic") {
            MediaProperty::from(ContentModifications::Dynamic)
        } else if name.eq_ignore_ascii_case("Time-Progressing") {
            MediaProperty::from(ContentModifications::TimeProgressing)
        } else if name.eq_ignore_ascii_case("Unlimited") {
            MediaProperty::from(Retention::Unlimited)
        } else if name.eq_ignore_ascii_case("Time-Limited") {
            reader.match_rtsp_separator('=')?;

            let timestamp =
                reader.read_while(|c| c.is_ascii_digit() || matches!(c, 'T' | 'Z' | '.'));

            #[cfg(feature = "abs-time")]
            {
                let ts = DateTime::parse_from_str(timestamp, "%Y%m%dT%H%M%S%.fZ")
                    .map_err(|_| Error::from_static_msg("invalid timestamp"))?
                    .to_utc();

                MediaProperty::from(Retention::TimeLimited(ts))
            }

            #[cfg(not(feature = "abs-time"))]
            {
                let _ = timestamp;

                let r = reader.as_str();

                let original_len = s.len();
                let remaining_len = r.len();

                let len = original_len - remaining_len;

                let property = &s[..len];

                MediaProperty::Other(Cow::Borrowed(property))
            }
        } else if name.eq_ignore_ascii_case("Time-Duration") {
            reader.match_rtsp_separator('=')?;

            let duration = reader.parse_positive_f32()?;

            MediaProperty::from(Retention::TimeDuration(duration))
        } else if name.eq_ignore_ascii_case("Scales") {
            reader.match_rtsp_separator('=')?;

            let scales = reader.read_rtsp_quoted_string()?.trim_matches('"').trim();

            let mut reader = StringReader::new(scales);

            let scales = reader.parse_scales()?;

            if !reader.is_empty() {
                return Err(Error::from_static_msg("unexpected character"));
            }

            MediaProperty::from(scales)
        } else {
            if reader.match_rtsp_separator('=').is_ok() {
                reader.read_other_media_property_value()?;
            }

            let r = reader.as_str();

            let original_len = s.len();
            let remaining_len = r.len();

            let len = original_len - remaining_len;

            let property = &s[..len];

            MediaProperty::Other(Cow::Borrowed(property))
        };

        *self = reader;

        Ok(property)
    }

    fn read_other_media_property_value(&mut self) -> Result<&'a str, Error> {
        let s = self.as_str();

        let mut reader = StringReader::new(s);

        let c = reader
            .current_char()
            .ok_or_else(|| Error::from_static_msg("unexpected end of input"))?;

        if c == '"' {
            reader.read_rtsp_quoted_string()?;
        } else if c.is_rtsp_unreserved() {
            reader.read_while(|c| c.is_rtsp_unreserved());
        } else {
            return Err(Error::from_static_msg("unexpected character"));
        }

        let r = reader.as_str();

        let original_len = s.len();
        let remaining_len = r.len();

        let len = original_len - remaining_len;

        *self = reader;

        Ok(&s[..len])
    }

    fn parse_scales(&mut self) -> Result<Scales, Error> {
        let mut reader = StringReader::new(self.as_str());

        let mut scales = Vec::new();

        loop {
            let a = reader.parse_f32()?;

            if reader.match_rtsp_separator(':').is_ok() {
                let b = reader.parse_f32()?;

                scales.push(Scale::Range(a, b));
            } else {
                scales.push(Scale::Value(a));
            }

            if reader.match_rtsp_separator(',').is_err() {
                break;
            }
        }

        *self = reader;

        Ok(Scales::new(scales))
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::{ContentModifications, MediaPropertiesHeader, RandomAccess, Retention, Scale};

    #[test]
    fn test_parser() {
        let header = MediaPropertiesHeader::from_str(" , ");

        assert!(header.is_err());

        let header = MediaPropertiesHeader::from_str("Random-Access , , Time-Progressing");

        assert!(header.is_err());

        let header = MediaPropertiesHeader::from_str("").unwrap();

        assert!(header.random_access().is_none());
        assert!(header.content_modifications().is_none());
        assert!(header.retention().is_none());
        assert!(header.scales().is_none());
        assert!(header.other_properties().is_empty());

        let header = MediaPropertiesHeader::from_str(
            "Random-Access, Time-Progressing, Unlimited, Scales=\"1.5, 2:5\", Other",
        )
        .unwrap();

        assert_eq!(
            header.random_access().unwrap(),
            RandomAccess::RandomAccess(None)
        );
        assert_eq!(
            header.content_modifications().unwrap(),
            ContentModifications::TimeProgressing
        );
        assert_eq!(header.retention().unwrap(), Retention::Unlimited);
        assert_eq!(
            header.scales().unwrap(),
            &[Scale::Value(1.5f32), Scale::Range(2f32, 5f32)]
        );
        assert_eq!(header.other_properties(), &["Other"]);

        let header = MediaPropertiesHeader::from_str(
            "Random-Access, Time-Progressing, Time-Duration=30.000",
        );

        assert!(header.is_ok());
    }
}
