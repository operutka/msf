use std::{
    convert::Infallible,
    fmt::{self, Display, Formatter},
    str::FromStr,
};

use str_reader::StringReader;

use crate::ParseError;

/// Bandwidth type.
#[derive(Clone)]
pub enum BandwidthType {
    AS,
    CT,
    Other(String),
}

impl Display for BandwidthType {
    #[inline]
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let s = match self {
            Self::AS => "AS",
            Self::CT => "CT",
            Self::Other(t) => t.as_str(),
        };

        f.write_str(s)
    }
}

impl FromStr for BandwidthType {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let res = match s {
            "AS" => Self::AS,
            "CT" => Self::CT,
            _ => Self::Other(s.to_string()),
        };

        Ok(res)
    }
}

/// Bandwidth field.
#[derive(Clone)]
pub struct Bandwidth {
    bandwidth_type: BandwidthType,
    bandwidth: u32,
}

impl Bandwidth {
    /// Create a new bandwidth field with a given type and bandwidth.
    #[inline]
    pub fn new(bandwidth_type: BandwidthType, bandwidth: u32) -> Self {
        Self {
            bandwidth_type,
            bandwidth,
        }
    }

    /// Get the type of the bandwidth.
    #[inline]
    pub fn bandwidth_type(&self) -> &BandwidthType {
        &self.bandwidth_type
    }

    /// Get the bandwidth.
    #[inline]
    pub fn bandwidth(&self) -> u32 {
        self.bandwidth
    }
}

impl Display for Bandwidth {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}:{}", self.bandwidth_type, self.bandwidth)
    }
}

impl FromStr for Bandwidth {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut reader = StringReader::new(s);

        let bandwidth_type = reader.read_until(|c| c == ':').trim().parse()?;

        reader.match_char(':')?;

        let bandwidth = reader.read_u32()?;

        reader.skip_whitespace();

        if !reader.is_empty() {
            return Err(ParseError::plain());
        }

        Ok(Self::new(bandwidth_type, bandwidth))
    }
}
