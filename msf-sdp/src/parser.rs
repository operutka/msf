use std::str::{FromStr, Lines};

use str_reader::StringReader;

use crate::ParseError;

/// Parser for SDP lines.
pub struct SessionDescriptionLines<'a> {
    lines: Lines<'a>,
    current: Option<(char, &'a str)>,
}

impl<'a> SessionDescriptionLines<'a> {
    /// Create a new parser for a given SDP.
    pub fn new(sdp: &'a str) -> Result<Self, ParseError> {
        let mut res = Self {
            lines: sdp.lines(),
            current: None,
        };

        res.next()?;

        Ok(res)
    }

    /// Get the current SDP line.
    pub fn current(&self) -> Option<(char, &'a str)> {
        self.current
    }

    /// Advance the input.
    pub fn next(&mut self) -> Result<(), ParseError> {
        for line in &mut self.lines {
            let line = line.trim();

            if line.is_empty() {
                continue;
            }

            let line = parse_sdp_line(line)
                .map_err(|err| ParseError::with_cause_and_msg("invalid SDP line", err))?;

            self.current = Some(line);

            return Ok(());
        }

        self.current = None;

        Ok(())
    }

    /// Parse a single SDP line.
    pub fn parse<T>(&mut self) -> Result<T, ParseError>
    where
        T: FromStr,
        ParseError: From<T::Err>,
    {
        let (_, v) = self.current.unwrap();

        let res = v.parse()?;

        self.next()?;

        Ok(res)
    }

    /// Parse multiple SDP lines.
    pub fn parse_multiple<T>(&mut self) -> Result<T, ParseError>
    where
        T: FromSessionDescriptionLines,
    {
        T::from_sdp_lines(self)
    }
}

/// Parse a single SDP line/field and return the single-character field name
/// and the field value.
fn parse_sdp_line(line: &str) -> Result<(char, &str), ParseError> {
    let mut reader = StringReader::new(line);

    reader.skip_whitespace();
    let t = reader.read_char()?;
    reader.skip_whitespace();
    reader.match_char('=')?;

    Ok((t, reader.as_str()))
}

/// Helper trait.
pub trait FromSessionDescriptionLines: Sized {
    /// Parse a new object by consuming given SDP lines.
    fn from_sdp_lines(lines: &mut SessionDescriptionLines) -> Result<Self, ParseError>;
}
