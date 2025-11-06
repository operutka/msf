//! Header fields.

pub mod props;
pub mod range;
pub mod rtpinfo;
pub mod session;
pub mod speed;
pub mod transport;

use std::fmt::{self, Display, Formatter};

use str_reader::{ParseError, StringReader};

use crate::Error;

pub use crate::ttpkit::header::{
    FieldIter, HeaderField, HeaderFieldDecoder, HeaderFieldEncoder, HeaderFieldName,
    HeaderFieldValue, HeaderFields, Iter, ValueParseError,
};

pub use self::{
    props::MediaPropertiesHeader,
    rtpinfo::RTPInfo,
    session::SessionHeader,
    speed::SpeedHeader,
    transport::{TransportHeader, TransportHeaderV10, TransportHeaderV20},
};

/// Formatter for a list of items separated by a given separator.
#[derive(Clone)]
pub struct ValueListDisplay<S, T> {
    separator: S,
    items: T,
}

impl<S, T> ValueListDisplay<S, T> {
    /// Create a new list formatter.
    #[inline]
    pub const fn new(separator: S, items: T) -> Self {
        Self { separator, items }
    }
}

impl<S, T, I> Display for ValueListDisplay<S, T>
where
    S: Display,
    T: IntoIterator<Item = I> + Clone,
    I: Display,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut items = self.items.clone().into_iter();

        if let Some(item) = items.next() {
            Display::fmt(&item, f)?;
        }

        for item in items {
            write!(f, "{}{}", self.separator, item)?;
        }

        Ok(())
    }
}

impl<S, T, I> From<ValueListDisplay<S, T>> for HeaderFieldValue
where
    S: Display,
    T: IntoIterator<Item = I> + Clone,
    I: Display,
{
    fn from(value: ValueListDisplay<S, T>) -> Self {
        HeaderFieldValue::from(value.to_string())
    }
}

/// Parse a given header parameter.
fn parse_header_parameter(s: &str) -> (&str, &str) {
    let (n, v) = s.split_once('=').unwrap_or((s, ""));

    let name = n.trim();
    let value = v.trim();

    (name, value)
}

/// Character extensions.
trait CharExt {
    /// Check if the character is an RTSP token character.
    fn is_rtsp_token(&self) -> bool;

    /// Check if the character is an RTSP unreserved character.
    fn is_rtsp_unreserved(&self) -> bool;
}

impl CharExt for char {
    fn is_rtsp_token(&self) -> bool {
        match *self {
            '!' | '#' | '$' | '%' | '&' | '\'' | '*' | '+' | '-' | '.' | '^' | '_' | '`' | '|'
            | '~' => true,
            _ => self.is_ascii_alphanumeric(),
        }
    }

    fn is_rtsp_unreserved(&self) -> bool {
        match *self {
            '!' | '$' | '\'' | '(' | ')' | '*' | '+' | '-' | '.' | '_' => true,
            _ => self.is_ascii_alphanumeric(),
        }
    }
}

/// String reader extension.
trait StringReaderExt<'a> {
    /// Read characters while a given condition holds.
    fn read_while<F>(&mut self, condition: F) -> &'a str
    where
        F: FnMut(char) -> bool;

    /// Match a given RTSP separator.
    fn match_rtsp_separator(&mut self, separator: char) -> Result<(), ParseError>;

    /// Read an RTP token.
    fn read_rtsp_token(&mut self) -> Result<&'a str, Error>;

    /// Read a positive float number.
    fn read_positive_float(&mut self) -> Result<&'a str, Error>;

    /// Parse a positive f32 number.
    fn parse_positive_f32(&mut self) -> Result<f32, Error>;

    /// Read a float number.
    fn read_float(&mut self) -> Result<&'a str, Error>;

    /// Parse an f32 number.
    fn parse_f32(&mut self) -> Result<f32, Error>;

    /// Read an RTSP quoted string.
    fn read_rtsp_quoted_string(&mut self) -> Result<&'a str, Error>;

    /// Parse an RTSP quoted string.
    fn parse_rtsp_quoted_string(&mut self) -> Result<String, Error>;
}

impl<'a> StringReaderExt<'a> for StringReader<'a> {
    fn read_while<F>(&mut self, mut condition: F) -> &'a str
    where
        F: FnMut(char) -> bool,
    {
        self.read_until(|char| !condition(char))
    }

    fn match_rtsp_separator(&mut self, separator: char) -> Result<(), ParseError> {
        let mut reader = StringReader::new(self.as_str());

        reader.skip_whitespace();
        reader.match_char(separator)?;
        reader.skip_whitespace();

        *self = reader;

        Ok(())
    }

    fn read_rtsp_token(&mut self) -> Result<&'a str, Error> {
        let res = self.read_while(|c| c.is_rtsp_token());

        if !res.is_empty() {
            Ok(res)
        } else if self.is_empty() {
            Err(Error::from_static_msg("unexpected end of input"))
        } else {
            Err(Error::from_static_msg("invalid RTSP token"))
        }
    }

    fn read_positive_float(&mut self) -> Result<&'a str, Error> {
        let s = self.as_str();

        let mut reader = StringReader::new(s);

        reader.read_while(|c| c.is_ascii_digit());

        if reader.match_char('.').is_ok() {
            reader.read_while(|c| c.is_ascii_digit());
        }

        *self = reader;

        let r = self.as_str();

        let original_len = s.len();
        let remaining_len = r.len();

        let len = original_len - remaining_len;

        if len == 0 {
            Err(Error::from_static_msg("invalid float number"))
        } else {
            Ok(&s[..len])
        }
    }

    fn parse_positive_f32(&mut self) -> Result<f32, Error> {
        self.read_positive_float()
            .ok()
            .map(|v| v.parse())
            .and_then(|r| r.ok())
            .ok_or_else(|| Error::from_static_msg("invalid float number"))
    }

    fn read_float(&mut self) -> Result<&'a str, Error> {
        let s = self.as_str();

        let mut reader = StringReader::new(s);

        let _ = reader.match_char('-');

        reader.read_positive_float()?;

        *self = reader;

        let r = self.as_str();

        let original_len = s.len();
        let remaining_len = r.len();

        let len = original_len - remaining_len;

        Ok(&s[..len])
    }

    fn parse_f32(&mut self) -> Result<f32, Error> {
        self.read_float()
            .ok()
            .map(|v| v.parse())
            .and_then(|r| r.ok())
            .ok_or_else(|| Error::from_static_msg("invalid float number"))
    }

    fn read_rtsp_quoted_string(&mut self) -> Result<&'a str, Error> {
        let s = self.as_str();

        let mut reader = StringReader::new(s);

        reader.match_char('"')?;

        loop {
            match reader.read_char()? {
                '"' => break,
                '\\' => match reader.read_char()? {
                    '"' | '\\' => (),
                    _ => return Err(Error::from_static_msg("unexpected escape character")),
                },
                _ => (),
            }
        }

        *self = reader;

        let r = self.as_str();

        let original_len = s.len();
        let remaining_len = r.len();

        let len = original_len - remaining_len;

        Ok(&s[..len])
    }

    fn parse_rtsp_quoted_string(&mut self) -> Result<String, Error> {
        let res = self
            .read_rtsp_quoted_string()?
            .trim_matches('"')
            .replace("\\\"", "\"")
            .replace("\\\\", "\\");

        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use str_reader::StringReader;

    use super::StringReaderExt;

    #[test]
    fn test_match_rtsp_separator() {
        let mut reader = StringReader::new("a,b ,c, d , e\t, f\n,g ; h");

        assert!(reader.match_str("a").is_ok());
        assert!(reader.match_rtsp_separator(',').is_ok());
        assert!(reader.match_str("b").is_ok());
        assert!(reader.match_rtsp_separator(',').is_ok());
        assert!(reader.match_str("c").is_ok());
        assert!(reader.match_rtsp_separator(',').is_ok());
        assert!(reader.match_str("d").is_ok());
        assert!(reader.match_rtsp_separator(',').is_ok());
        assert!(reader.match_str("e").is_ok());
        assert!(reader.match_rtsp_separator(',').is_ok());
        assert!(reader.match_str("f").is_ok());
        assert!(reader.match_rtsp_separator(',').is_ok());
        assert!(reader.match_str("g").is_ok());

        assert!(reader.match_rtsp_separator(',').is_err());

        assert_eq!(reader.as_str(), " ; h");

        assert!(reader.match_rtsp_separator(';').is_ok());
        assert!(reader.match_str("h").is_ok());

        assert!(reader.is_empty());
    }

    #[test]
    fn test_read_rtsp_quoted_string() {
        let mut reader = StringReader::new("");

        assert!(reader.read_rtsp_quoted_string().is_err());

        let mut reader = StringReader::new("a");

        assert!(reader.read_rtsp_quoted_string().is_err());

        let mut reader = StringReader::new(" \"\" ");

        assert!(reader.read_rtsp_quoted_string().is_err());

        let mut reader = StringReader::new("\" ");

        assert!(reader.read_rtsp_quoted_string().is_err());

        let mut reader = StringReader::new("\"\\\"");

        assert!(reader.read_rtsp_quoted_string().is_err());

        let mut reader = StringReader::new("\"\\a\"");

        assert!(reader.read_rtsp_quoted_string().is_err());

        let mut reader = StringReader::new("\"\" ");

        let res = reader.read_rtsp_quoted_string();

        assert!(matches!(res, Ok("\"\"")));
        assert_eq!(reader.as_str(), " ");

        let mut reader = StringReader::new("\"abc \t\n\\\"\\\\def \"");

        assert!(matches!(
            reader.read_rtsp_quoted_string(),
            Ok("\"abc \t\n\\\"\\\\def \"")
        ));
    }

    #[test]
    fn test_parse_rtsp_quoted_string() {
        let mut reader = StringReader::new("\"\" ");

        let res = reader.parse_rtsp_quoted_string();

        assert!(matches!(res.as_deref(), Ok("")));
        assert_eq!(reader.as_str(), " ");

        let mut reader = StringReader::new("\"abc \t\n\\\"\\\\def \"");

        let res = reader.parse_rtsp_quoted_string();

        assert!(matches!(res.as_deref(), Ok("abc \t\n\"\\def ")));
    }

    #[test]
    fn test_read_rtsp_token() {
        let input = " abc \nd1f\tfoo-bar";
        let mut reader = StringReader::new(input);

        assert!(reader.read_rtsp_token().is_err());
        assert_eq!(reader.as_str(), input);

        reader.skip_whitespace();

        assert!(matches!(reader.read_rtsp_token(), Ok("abc")));

        reader.skip_whitespace();

        assert!(matches!(reader.read_rtsp_token(), Ok("d1f")));

        reader.skip_whitespace();

        assert!(matches!(reader.read_rtsp_token(), Ok("foo-bar")));

        assert!(reader.is_empty());
    }

    #[test]
    fn test_parse_f32() {
        let mut reader = StringReader::new("1.0");

        assert!(matches!(reader.parse_f32(), Ok(1.0)));
        assert!(reader.is_empty());

        let mut reader = StringReader::new("-1.0");

        assert!(matches!(reader.parse_f32(), Ok(-1.0)));
        assert!(reader.is_empty());

        let mut reader = StringReader::new("1.0 ");

        assert!(matches!(reader.parse_f32(), Ok(1.0)));
        assert_eq!(reader.as_str(), " ");

        let mut reader = StringReader::new("1.0a");

        assert!(matches!(reader.parse_f32(), Ok(1.0)));
        assert_eq!(reader.as_str(), "a");

        let mut reader = StringReader::new("a1.0");

        assert!(reader.parse_f32().is_err());
        assert_eq!(reader.as_str(), "a1.0");
    }
}
