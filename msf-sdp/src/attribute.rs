//! Session and media attributes.

use std::{
    borrow::Cow,
    convert::Infallible,
    fmt::{self, Display, Formatter},
    ops::{Deref, DerefMut},
    str::FromStr,
};

use str_reader::StringReader;

use crate::ParseError;

/// SDP attribute.
#[derive(Debug, Clone)]
pub struct Attribute {
    name: String,
    value: Option<String>,
}

impl Attribute {
    /// Create a new flag-attribute (i.e. an attribute without a value).
    #[inline]
    pub fn new_flag<N>(name: N) -> Self
    where
        N: ToString,
    {
        Self {
            name: name.to_string(),
            value: None,
        }
    }

    /// Create a new attribute.
    #[inline]
    pub fn new_attribute<N, V>(name: N, value: V) -> Self
    where
        N: ToString,
        V: ToString,
    {
        Self {
            name: name.to_string(),
            value: Some(value.to_string()),
        }
    }

    /// Get attribute name.
    #[inline]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get attribute value (if any).
    #[inline]
    pub fn value(&self) -> Option<&str> {
        self.value.as_deref()
    }
}

impl Display for Attribute {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.write_str(&self.name)?;

        if let Some(v) = self.value.as_ref() {
            write!(f, ":{}", v)?;
        }

        Ok(())
    }
}

impl FromStr for Attribute {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (name, value) = if let Some(colon) = s.find(':') {
            let (name, rest) = s.split_at(colon);

            let value = &rest[1..];

            (name, Some(value))
        } else {
            (s, None)
        };

        let res = Self {
            name: name.to_string(),
            value: value.map(|v| v.to_string()),
        };

        Ok(res)
    }
}

/// Collection of attributes.
#[derive(Clone)]
pub struct Attributes {
    inner: Vec<Attribute>,
}

impl Attributes {
    /// Create a new collection of attributes.
    #[inline]
    pub const fn new() -> Self {
        Self { inner: Vec::new() }
    }

    /// Find the first attribute matching a given predicate.
    #[inline]
    pub fn find<F>(&self, predicate: F) -> Option<&Attribute>
    where
        F: FnMut(&Attribute) -> bool,
    {
        self.find_all(predicate).next()
    }

    /// Find all attributes matching a given predicate.
    #[inline]
    pub fn find_all<F>(&self, predicate: F) -> PredicateMatchingIter<'_, F>
    where
        F: FnMut(&Attribute) -> bool,
    {
        PredicateMatchingIter::new(self, predicate)
    }

    /// Get the first attribute matching a given name (case sensitive).
    #[inline]
    pub fn get(&self, name: &str) -> Option<&Attribute> {
        self.find(|a| a.name() == name)
    }

    /// Get all attributes matching a given name (case sensitive).
    #[inline]
    pub fn get_all<'a>(&'a self, name: &'a str) -> NameMatchingIter<'a> {
        NameMatchingIter::new(self, name)
    }

    /// Get value of the first attribute matching a given name (case
    /// sensitive).
    #[inline]
    pub fn get_value(&self, name: &str) -> Option<&str> {
        self.get(name).and_then(|a| a.value())
    }

    /// Check if there is an attribute matching a given name (case sensitive).
    #[inline]
    pub fn contains(&self, name: &str) -> bool {
        self.get(name).is_some()
    }
}

impl Default for Attributes {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl Deref for Attributes {
    type Target = Vec<Attribute>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for Attributes {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

/// Iterator over attributes matching a given predicate.
pub struct PredicateMatchingIter<'a, F> {
    predicate: F,
    attributes: std::slice::Iter<'a, Attribute>,
}

impl<'a, F> PredicateMatchingIter<'a, F> {
    /// Create a new iterator.
    fn new(attributes: &'a [Attribute], predicate: F) -> Self {
        Self {
            predicate,
            attributes: attributes.iter(),
        }
    }
}

impl<'a, F> Iterator for PredicateMatchingIter<'a, F>
where
    F: FnMut(&Attribute) -> bool,
{
    type Item = &'a Attribute;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(item) = self.attributes.next() {
                if (self.predicate)(item) {
                    return Some(item);
                }
            } else {
                return None;
            }
        }
    }
}

/// Iterator over attributes matching a given name.
pub struct NameMatchingIter<'a> {
    name: &'a str,
    attributes: std::slice::Iter<'a, Attribute>,
}

impl<'a> NameMatchingIter<'a> {
    /// Create a new iterator.
    fn new(attributes: &'a [Attribute], name: &'a str) -> Self {
        Self {
            name,
            attributes: attributes.iter(),
        }
    }
}

impl<'a> Iterator for NameMatchingIter<'a> {
    type Item = &'a Attribute;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(item) = self.attributes.next() {
                if item.name() == self.name {
                    return Some(item);
                }
            } else {
                return None;
            }
        }
    }
}

/// Mapping from an RTP payload type to an actual encoding.
#[derive(Clone)]
pub struct RTPMap<'a> {
    payload_type: u8,
    encoding_name: &'a str,
    clock_rate: u32,
    encoding_parameters: Option<Cow<'a, str>>,
}

impl<'a> RTPMap<'a> {
    /// Create a new rtpmap attribute value.
    #[inline]
    pub const fn new(payload_type: u8, encoding_name: &'a str, clock_rate: u32) -> Self {
        Self {
            payload_type,
            encoding_name,
            clock_rate,
            encoding_parameters: None,
        }
    }

    /// Set the encoding parameters.
    #[inline]
    pub fn with_encoding_parameters<T>(mut self, params: T) -> Self
    where
        T: ToString,
    {
        self.encoding_parameters = Some(Cow::Owned(params.to_string()));
        self
    }

    /// Get the payload type.
    #[inline]
    pub fn payload_type(&self) -> u8 {
        self.payload_type
    }

    /// Get name of the encoding.
    #[inline]
    pub fn encoding_name(&self) -> &str {
        self.encoding_name
    }

    /// Get the clock rate.
    #[inline]
    pub fn clock_rate(&self) -> u32 {
        self.clock_rate
    }

    /// Get the encoding parameters (if specified).
    #[inline]
    pub fn encoding_parameters(&self) -> Option<&str> {
        self.encoding_parameters.as_deref()
    }
}

impl<'a> Display for RTPMap<'a> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(
            f,
            "{} {}/{}",
            self.payload_type, self.encoding_name, self.clock_rate
        )?;

        if let Some(params) = self.encoding_parameters.as_ref() {
            write!(f, "/{}", params)?;
        }

        Ok(())
    }
}

impl<'a> TryFrom<&'a str> for RTPMap<'a> {
    type Error = ParseError;

    fn try_from(s: &'a str) -> Result<Self, Self::Error> {
        let mut reader = StringReader::new(s);

        let payload_type = reader.read_u8()?;

        reader.skip_whitespace();

        let encoding_name = reader.read_until(|c| c == '/');

        reader.match_char('/')?;

        let clock_rate = reader.read_until(|c| c == '/').parse()?;

        let encoding_parameters = if reader.is_empty() {
            None
        } else {
            Some(Cow::Borrowed(&reader.as_str()[1..]))
        };

        let res = Self {
            payload_type,
            encoding_name,
            clock_rate,
            encoding_parameters,
        };

        Ok(res)
    }
}

/// Format-specific parameters.
#[derive(Clone)]
pub struct FormatParameters<'a> {
    format: Cow<'a, str>,
    params: Cow<'a, str>,
}

impl<'a> FormatParameters<'a> {
    /// Create a new fmtp attribute value.
    #[inline]
    pub fn new<T, U>(format: T, parameters: U) -> Self
    where
        T: ToString,
        U: ToString,
    {
        Self {
            format: Cow::Owned(format.to_string()),
            params: Cow::Owned(parameters.to_string()),
        }
    }

    /// Get the format.
    #[inline]
    pub fn format(&self) -> &str {
        &self.format
    }

    /// Get the format parameters.
    #[inline]
    pub fn parameters(&self) -> &str {
        &self.params
    }
}

impl<'a> Display for FormatParameters<'a> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{} {}", self.format, self.params)
    }
}

impl<'a> From<&'a str> for FormatParameters<'a> {
    fn from(s: &'a str) -> Self {
        let s = s.trim();

        let (format, params) = if let Some(space) = s.find(' ') {
            let (f, r) = s.split_at(space);

            let p = &r[1..];

            (f, p)
        } else {
            (s, "")
        };

        Self {
            format: Cow::Borrowed(format),
            params: Cow::Borrowed(params),
        }
    }
}
