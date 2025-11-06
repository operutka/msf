//! Transport headers.

mod v10;
mod v20;

use std::{
    fmt::{self, Display, Formatter},
    num::ParseIntError,
    str::FromStr,
};

use str_reader::StringReader;

use crate::{
    Error,
    header::{CharExt, StringReaderExt},
};

pub use self::{
    v10::TransportHeaderV10,
    v20::{TransportAddress, TransportHeaderV20},
};

/// Transport header.
#[derive(Debug, Clone)]
pub enum TransportHeader {
    /// RTSP/1.0 transport header.
    V10(TransportHeaderV10),
    /// RTSP/2.0 transport header.
    V20(TransportHeaderV20),
}

impl Display for TransportHeader {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::V10(header) => Display::fmt(header, f),
            Self::V20(header) => Display::fmt(header, f),
        }
    }
}

impl From<TransportHeaderV10> for TransportHeader {
    #[inline]
    fn from(header: TransportHeaderV10) -> Self {
        Self::V10(header)
    }
}

impl From<TransportHeaderV20> for TransportHeader {
    #[inline]
    fn from(header: TransportHeaderV20) -> Self {
        Self::V20(header)
    }
}

/// Port pair.
#[derive(Debug, Copy, Clone)]
pub struct PortPair {
    rtp: u16,
    rtcp: Option<u16>,
}

impl PortPair {
    /// Create a new port pair.
    #[inline]
    pub const fn new(rtp: u16, rtcp: Option<u16>) -> Self {
        Self { rtp, rtcp }
    }

    /// Get the RTP port number.
    #[inline]
    pub fn rtp(&self) -> u16 {
        self.rtp
    }

    /// Get the RTCP port number.
    #[inline]
    pub fn rtcp(&self) -> Option<u16> {
        self.rtcp
    }
}

impl Display for PortPair {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if let Some(rtcp) = self.rtcp {
            write!(f, "{}-{}", self.rtp, rtcp)
        } else {
            write!(f, "{}", self.rtp)
        }
    }
}

impl FromStr for PortPair {
    type Err = ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        NumberPair::from_str(s).map(|NumberPair(rtp, rtcp)| Self { rtp, rtcp })
    }
}

impl From<u16> for PortPair {
    #[inline]
    fn from(rtp: u16) -> Self {
        Self::new(rtp, None)
    }
}

impl From<(u16,)> for PortPair {
    #[inline]
    fn from((rtp,): (u16,)) -> Self {
        Self::new(rtp, None)
    }
}

impl From<(u16, u16)> for PortPair {
    #[inline]
    fn from((rtp, rtcp): (u16, u16)) -> Self {
        Self::new(rtp, Some(rtcp))
    }
}

impl From<(u16, Option<u16>)> for PortPair {
    #[inline]
    fn from((rtp, rtcp): (u16, Option<u16>)) -> Self {
        Self::new(rtp, rtcp)
    }
}

/// Interleaved channel pair.
#[derive(Debug, Copy, Clone)]
pub struct InterleavedPair {
    rtp: u8,
    rtcp: Option<u8>,
}

impl InterleavedPair {
    /// Create a new channel pair.
    #[inline]
    pub const fn new(rtp: u8, rtcp: Option<u8>) -> Self {
        Self { rtp, rtcp }
    }

    /// Get the RTP channel number.
    #[inline]
    pub fn rtp(&self) -> u8 {
        self.rtp
    }

    /// Get the RTCP channel number.
    #[inline]
    pub fn rtcp(&self) -> Option<u8> {
        self.rtcp
    }
}

impl Display for InterleavedPair {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if let Some(rtcp) = self.rtcp {
            write!(f, "{}-{}", self.rtp, rtcp)
        } else {
            write!(f, "{}", self.rtp)
        }
    }
}

impl FromStr for InterleavedPair {
    type Err = ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        NumberPair::from_str(s).map(|NumberPair(rtp, rtcp)| Self { rtp, rtcp })
    }
}

impl From<u8> for InterleavedPair {
    #[inline]
    fn from(rtp: u8) -> Self {
        Self::new(rtp, None)
    }
}

impl From<(u8,)> for InterleavedPair {
    #[inline]
    fn from((rtp,): (u8,)) -> Self {
        Self::new(rtp, None)
    }
}

impl From<(u8, u8)> for InterleavedPair {
    #[inline]
    fn from((rtp, rtcp): (u8, u8)) -> Self {
        Self::new(rtp, Some(rtcp))
    }
}

impl From<(u8, Option<u8>)> for InterleavedPair {
    #[inline]
    fn from((rtp, rtcp): (u8, Option<u8>)) -> Self {
        Self::new(rtp, rtcp)
    }
}

/// Helper struct.
struct NumberPair<T>(T, Option<T>);

impl<T> FromStr for NumberPair<T>
where
    T: FromStr,
{
    type Err = T::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // helper function to avoid expensive monomorphizations
        fn inner(s: &str) -> (&str, Option<&str>) {
            let (a, b) = s
                .split_once('-')
                .map(|(a, b)| (a, Some(b)))
                .unwrap_or((s, None));

            let a = a.trim();
            let b = b.map(|b| b.trim());

            (a, b)
        }

        let (a, b) = inner(s);

        let a = a.parse()?;
        let b = b.map(|b| b.parse()).transpose()?;

        Ok(Self(a, b))
    }
}

/// Key-value pair.
type KeyValuePair<'a> = (&'a str, Option<&'a str>);

/// Base transport header parser.
trait BaseTransportParser<'a> {
    /// Read the transport ID.
    fn read_transport_id(&mut self) -> Result<&'a str, Error>;

    /// Read a transport parameter.
    fn read_transport_parameter(&mut self) -> Result<KeyValuePair<'a>, Error>;

    /// Read a transport parameter value.
    fn read_transport_parameter_value(&mut self) -> Result<&'a str, Error>;
}

impl<'a> BaseTransportParser<'a> for StringReader<'a> {
    fn read_transport_id(&mut self) -> Result<&'a str, Error> {
        let s = self.as_str();

        let mut reader = StringReader::new(s);

        reader.read_rtsp_token()?;

        while reader.current_char() == Some('/') {
            reader.skip_char();
            reader.read_rtsp_token()?;
        }

        *self = reader;

        let r = self.as_str();

        let original_len = s.len();
        let remaining_len = r.len();

        let len = original_len - remaining_len;

        Ok(&s[..len])
    }

    fn read_transport_parameter(&mut self) -> Result<KeyValuePair<'a>, Error> {
        let mut reader = StringReader::new(self.as_str());

        let key = reader.read_rtsp_token()?;

        let value = match reader.match_rtsp_separator('=') {
            Ok(_) => Some(reader.read_transport_parameter_value()?),
            Err(_) => None,
        };

        *self = reader;

        Ok((key, value))
    }

    fn read_transport_parameter_value(&mut self) -> Result<&'a str, Error> {
        let s = self.as_str();

        let mut reader = StringReader::new(s);

        while let Some(c) = reader.current_char() {
            if c == '"' {
                reader.read_rtsp_quoted_string()?;
            } else if c.is_rtsp_unreserved() || c == ':' {
                reader.skip_char();
            } else if reader.match_rtsp_separator('/').is_err() {
                break;
            }
        }

        *self = reader;

        let r = self.as_str();

        let original_len = s.len();
        let remaining_len = r.len();

        let len = original_len - remaining_len;

        Ok(&s[..len])
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use str_reader::StringReader;

    use super::{BaseTransportParser, NumberPair};

    #[test]
    fn test_number_pair_parser() {
        assert!(NumberPair::<u8>::from_str("").is_err());
        assert!(NumberPair::<u8>::from_str(" ").is_err());
        assert!(NumberPair::<u8>::from_str("333").is_err());
        assert!(NumberPair::<u8>::from_str("1-333").is_err());

        let pair = NumberPair::<u8>::from_str("12").unwrap();

        assert!(matches!(pair, NumberPair(12, None)));

        let pair = NumberPair::<u8>::from_str("23-34").unwrap();

        assert!(matches!(pair, NumberPair(23, Some(34))));
    }

    #[test]
    fn test_read_transport_id() {
        let mut reader = StringReader::new("");

        assert!(reader.read_transport_id().is_err());

        let mut reader = StringReader::new(" ");

        assert!(reader.read_transport_id().is_err());

        let mut reader = StringReader::new(" foo");

        assert!(reader.read_transport_id().is_err());
        assert_eq!(reader.as_str(), " foo");

        let mut reader = StringReader::new("foo");

        assert!(matches!(reader.read_transport_id(), Ok("foo")));

        let mut reader = StringReader::new("foo/bar");

        assert!(matches!(reader.read_transport_id(), Ok("foo/bar")));

        let mut reader = StringReader::new("foo / bar");

        let id = reader.read_transport_id();
        let rest = reader.as_str();

        assert!(matches!(id, Ok("foo")));
        assert_eq!(rest, " / bar");
    }

    #[test]
    fn test_read_transport_parameter() {
        let mut reader = StringReader::new("");

        assert!(reader.read_transport_parameter().is_err());

        let mut reader = StringReader::new(" ");

        assert!(reader.read_transport_parameter().is_err());

        let mut reader = StringReader::new(" foo");

        assert!(reader.read_transport_parameter().is_err());
        assert_eq!(reader.as_str(), " foo");

        let mut reader = StringReader::new("foo ");

        let param = reader.read_transport_parameter();
        let rest = reader.as_str();

        assert!(matches!(param, Ok(("foo", None))));
        assert_eq!(rest, " ");

        let mut reader = StringReader::new("foo = bar ");

        let param = reader.read_transport_parameter();
        let rest = reader.as_str();

        assert!(matches!(param, Ok(("foo", Some("bar")))));
        assert_eq!(rest, " ");

        let mut reader = StringReader::new("foo = \" b a r \"\" \" / \":123\" ");

        let param = reader.read_transport_parameter();
        let rest = reader.as_str();

        assert!(matches!(
            param,
            Ok(("foo", Some("\" b a r \"\" \" / \":123\"")))
        ));
        assert_eq!(rest, " ");
    }
}
