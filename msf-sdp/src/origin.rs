use std::{
    fmt::{self, Display, Formatter},
    str::FromStr,
};

use str_reader::StringReader;

use crate::{AddressType, NetworkType, ParseError};

/// SDP origin.
#[derive(Clone)]
pub struct Origin {
    username: String,
    session_id: u64,
    session_version: u64,
    network_type: NetworkType,
    address_type: AddressType,
    unicast_address: String,
}

impl Origin {
    /// Create a new origin.
    #[inline]
    pub fn new<U, A>(
        username: U,
        session_id: u64,
        session_version: u64,
        network_type: NetworkType,
        address_type: AddressType,
        unicast_address: A,
    ) -> Self
    where
        U: ToString,
        A: ToString,
    {
        Self {
            username: username.to_string(),
            session_id,
            session_version,
            network_type,
            address_type,
            unicast_address: unicast_address.to_string(),
        }
    }

    /// Get the username.
    #[inline]
    pub fn username(&self) -> &str {
        &self.username
    }

    /// Get the session ID.
    #[inline]
    pub fn session_id(&self) -> u64 {
        self.session_id
    }

    /// Get the session version.
    #[inline]
    pub fn session_version(&self) -> u64 {
        self.session_version
    }

    /// Get the network type.
    #[inline]
    pub fn network_type(&self) -> &NetworkType {
        &self.network_type
    }

    /// Get the address type.
    #[inline]
    pub fn address_type(&self) -> &AddressType {
        &self.address_type
    }

    /// Get the unicast address.
    #[inline]
    pub fn unicast_address(&self) -> &str {
        &self.unicast_address
    }
}

impl Default for Origin {
    #[inline]
    fn default() -> Self {
        Self {
            username: String::from("-"),
            session_id: 0,
            session_version: 0,
            network_type: NetworkType::Internet,
            address_type: AddressType::IPv4,
            unicast_address: String::from("0.0.0.0"),
        }
    }
}

impl Display for Origin {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(
            f,
            "{} {} {} {} {} {}",
            self.username,
            self.session_id,
            self.session_version,
            self.network_type,
            self.address_type,
            self.unicast_address
        )
    }
}

impl FromStr for Origin {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut reader = StringReader::new(s);

        let username = reader.read_word().to_string();
        let session_id = reader.read_u64()?;
        let session_version = reader.read_u64()?;
        let network_type = reader.parse_word()?;
        let address_type = reader.parse_word()?;
        let unicast_address = reader.read_word().to_string();

        reader.skip_whitespace();

        if unicast_address.is_empty() || !reader.is_empty() {
            return Err(ParseError::plain());
        }

        let res = Self {
            username,
            session_id,
            session_version,
            network_type,
            address_type,
            unicast_address,
        };

        Ok(res)
    }
}
