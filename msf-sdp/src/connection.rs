//! Connection information.

use std::{
    fmt::{self, Display, Formatter},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

use str_reader::StringReader;

use crate::{NetworkType, ParseError};

/// Connection information.
#[derive(Clone)]
pub struct ConnectionInfo {
    network_type: NetworkType,
    address: ConnectionAddress,
}

impl ConnectionInfo {
    /// Create a new connection info.
    #[inline]
    pub fn new<T>(network_type: NetworkType, address: T) -> Self
    where
        T: Into<ConnectionAddress>,
    {
        let address = address.into();

        Self {
            network_type,
            address,
        }
    }

    /// Get the network type.
    #[inline]
    pub fn network_type(&self) -> &NetworkType {
        &self.network_type
    }

    /// Get the connection address.
    #[inline]
    pub fn address(&self) -> &ConnectionAddress {
        &self.address
    }
}

impl Display for ConnectionInfo {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{} {}", self.network_type, self.address)
    }
}

impl FromStr for ConnectionInfo {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut reader = StringReader::new(s);

        let network_type = reader.parse_word()?;
        let address = reader.as_str().parse()?;

        let res = Self {
            network_type,
            address,
        };

        Ok(res)
    }
}

/// Connection address.
#[derive(Clone)]
pub enum ConnectionAddress {
    IPv4(IPv4Address),
    IPv6(IPv6Address),
    Other(OtherAddress),
}

impl ConnectionAddress {
    /// Create unicast connection address from a given IP address.
    #[inline]
    pub fn unicast<A>(addr: A) -> Self
    where
        A: Into<IpAddr>,
    {
        match addr.into() {
            IpAddr::V4(addr) => Self::IPv4(IPv4Address::unicast(addr)),
            IpAddr::V6(addr) => Self::IPv6(IPv6Address::unicast(addr)),
        }
    }
}

impl Display for ConnectionAddress {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Self::IPv4(addr) => write!(f, "IP4 {addr}"),
            Self::IPv6(addr) => write!(f, "IP6 {addr}"),
            Self::Other(addr) => write!(f, "{} {}", addr.address_type, addr),
        }
    }
}

impl FromStr for ConnectionAddress {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut reader = StringReader::new(s);

        let address_type = reader.read_word();
        let address = reader.as_str();

        let res = match address_type {
            "IP4" => Self::IPv4(address.parse()?),
            "IP6" => Self::IPv6(address.parse()?),
            _ => Self::Other(OtherAddress::new(address_type, address.trim())),
        };

        Ok(res)
    }
}

impl From<IPv4Address> for ConnectionAddress {
    #[inline]
    fn from(addr: IPv4Address) -> Self {
        Self::IPv4(addr)
    }
}

impl From<IPv6Address> for ConnectionAddress {
    #[inline]
    fn from(addr: IPv6Address) -> Self {
        Self::IPv6(addr)
    }
}

impl From<OtherAddress> for ConnectionAddress {
    #[inline]
    fn from(addr: OtherAddress) -> Self {
        Self::Other(addr)
    }
}

/// IPv4 connection address.
#[derive(Copy, Clone)]
pub struct IPv4Address {
    address: Ipv4Addr,
    ttl: Option<u8>,
    count: Option<u32>,
}

impl IPv4Address {
    /// Create a single unicast IPv4 connection address.
    #[inline]
    pub const fn unicast(address: Ipv4Addr) -> Self {
        Self {
            address,
            ttl: None,
            count: None,
        }
    }

    /// Create multicast IPv4 connection address(es).
    #[inline]
    pub const fn multicast(address: Ipv4Addr, ttl: u8, count: Option<u32>) -> Self {
        Self {
            address,
            ttl: Some(ttl),
            count,
        }
    }

    /// Get the IP address.
    #[inline]
    pub fn address(&self) -> Ipv4Addr {
        self.address
    }

    /// Get multicast TTL value.
    #[inline]
    pub fn ttl(&self) -> Option<u8> {
        self.ttl
    }

    /// Get number of addresses.
    #[inline]
    pub fn count(&self) -> Option<u32> {
        self.count
    }
}

impl Display for IPv4Address {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", self.address)?;

        if let Some(ttl) = self.ttl {
            write!(f, "/{ttl}")?;

            if let Some(count) = self.count {
                write!(f, "/{count}")?;
            }
        }

        Ok(())
    }
}

impl FromStr for IPv4Address {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut reader = StringReader::new(s.trim());

        let address = reader
            .read_until(|c| c.is_whitespace() || c == '/')
            .parse()?;

        reader.skip_whitespace();

        let ttl = if reader.is_empty() {
            None
        } else {
            reader.match_char('/')?;
            reader.skip_whitespace();

            let ttl = reader.read_until(|c| !c.is_ascii_digit()).parse()?;

            Some(ttl)
        };

        reader.skip_whitespace();

        let count = if reader.is_empty() {
            None
        } else {
            reader.match_char('/')?;
            reader.skip_whitespace();

            let count = reader.read_until(|c| !c.is_ascii_digit()).parse()?;

            Some(count)
        };

        if !reader.is_empty() {
            return Err(ParseError::plain());
        }

        let res = Self {
            address,
            ttl,
            count,
        };

        Ok(res)
    }
}

/// IPv6 connection address.
#[derive(Copy, Clone)]
pub struct IPv6Address {
    address: Ipv6Addr,
    count: Option<u32>,
}

impl IPv6Address {
    /// Create a single unicast IPv6 connection address.
    #[inline]
    pub const fn unicast(address: Ipv6Addr) -> Self {
        Self {
            address,
            count: None,
        }
    }

    /// Create multicast IPv6 connection address(es).
    #[inline]
    pub const fn multicast(address: Ipv6Addr, count: Option<u32>) -> Self {
        Self { address, count }
    }

    /// Get the IPv6 address.
    #[inline]
    pub fn address(&self) -> Ipv6Addr {
        self.address
    }

    /// Get number of addresses.
    #[inline]
    pub fn count(&self) -> Option<u32> {
        self.count
    }
}

impl Display for IPv6Address {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", self.address)?;

        if let Some(count) = self.count {
            write!(f, "/{count}")?;
        }

        Ok(())
    }
}

impl FromStr for IPv6Address {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut reader = StringReader::new(s.trim());

        let address = reader
            .read_until(|c| c.is_whitespace() || c == '/')
            .parse()?;

        reader.skip_whitespace();

        let count = if reader.is_empty() {
            None
        } else {
            reader.match_char('/')?;
            reader.skip_whitespace();

            let count = reader.read_until(|c| !c.is_ascii_digit()).parse()?;

            Some(count)
        };

        if !reader.is_empty() {
            return Err(ParseError::plain());
        }

        let res = Self { address, count };

        Ok(res)
    }
}

/// Other connection address.
#[derive(Clone)]
pub struct OtherAddress {
    address_type: String,
    address: String,
}

impl OtherAddress {
    /// Create a new connection address that is not IPv4 or IPv6.
    #[inline]
    pub fn new<T, A>(address_type: T, address: A) -> Self
    where
        T: ToString,
        A: ToString,
    {
        Self {
            address_type: address_type.to_string(),
            address: address.to_string(),
        }
    }

    /// Get the type of the address.
    #[inline]
    pub fn address_type(&self) -> &str {
        &self.address_type
    }

    /// Get the address.
    #[inline]
    pub fn address(&self) -> &str {
        &self.address
    }
}

impl Display for OtherAddress {
    #[inline]
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.write_str(&self.address)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use crate::NetworkType;

    use super::{ConnectionAddress, ConnectionInfo, IPv4Address, IPv6Address};

    #[test]
    fn test_ipv4_address() {
        let addr = "192.0.2.1".parse::<IPv4Address>().unwrap();

        assert_eq!(addr.address(), Ipv4Addr::new(192, 0, 2, 1));
        assert_eq!(addr.ttl(), None);
        assert_eq!(addr.count(), None);
        assert_eq!(addr.to_string(), "192.0.2.1");

        let addr = "224.2.17.12/127".parse::<IPv4Address>().unwrap();

        assert_eq!(addr.address(), Ipv4Addr::new(224, 2, 17, 12));
        assert_eq!(addr.ttl(), Some(127));
        assert_eq!(addr.count(), None);
        assert_eq!(addr.to_string(), "224.2.17.12/127");

        let addr = "224.2.17.12/127/3".parse::<IPv4Address>().unwrap();

        assert_eq!(addr.ttl(), Some(127));
        assert_eq!(addr.count(), Some(3));
        assert_eq!(addr.to_string(), "224.2.17.12/127/3");
    }

    #[test]
    fn test_ipv4_address_errors() {
        assert!("not-an-address".parse::<IPv4Address>().is_err());

        // the TTL does not fit into a single byte
        assert!("224.2.17.12/300".parse::<IPv4Address>().is_err());

        // there is nothing after the address count
        assert!("224.2.17.12/127/3/4".parse::<IPv4Address>().is_err());
    }

    #[test]
    fn test_ipv6_address() {
        let addr = "ff15::101".parse::<IPv6Address>().unwrap();

        assert_eq!(
            addr.address(),
            Ipv6Addr::new(0xff15, 0, 0, 0, 0, 0, 0, 0x101)
        );
        assert_eq!(addr.count(), None);
        assert_eq!(addr.to_string(), "ff15::101");

        let addr = "ff15::101/3".parse::<IPv6Address>().unwrap();

        assert_eq!(addr.count(), Some(3));
        assert_eq!(addr.to_string(), "ff15::101/3");

        assert!("192.0.2.1".parse::<IPv6Address>().is_err());
        assert!("ff15::101/3/4".parse::<IPv6Address>().is_err());
    }

    #[test]
    fn test_other_address() {
        let info = "ATM NSAP 47.0001".parse::<ConnectionInfo>().unwrap();

        assert!(matches!(info.network_type(), NetworkType::Other(t) if t == "ATM"));

        let ConnectionAddress::Other(addr) = info.address() else {
            panic!("non-IP connection address expected");
        };

        assert_eq!(addr.address_type(), "NSAP");
        assert_eq!(addr.address(), "47.0001");

        assert_eq!(info.to_string(), "ATM NSAP 47.0001");
    }

    #[test]
    fn test_connection_info_errors() {
        assert!("IN IP4 not-an-address".parse::<ConnectionInfo>().is_err());
        assert!("IN IP6 192.0.2.1".parse::<ConnectionInfo>().is_err());
    }

    #[test]
    fn test_multicast_constructors() {
        let addr = ConnectionAddress::from(IPv4Address::multicast(
            Ipv4Addr::new(224, 2, 17, 12),
            127,
            Some(3),
        ));

        assert_eq!(addr.to_string(), "IP4 224.2.17.12/127/3");

        let addr = ConnectionAddress::from(IPv6Address::multicast(
            Ipv6Addr::new(0xff15, 0, 0, 0, 0, 0, 0, 0x101),
            Some(3),
        ));

        assert_eq!(addr.to_string(), "IP6 ff15::101/3");
    }
}
