use std::{net::SocketAddr, ops::Deref};

use crate::attribute::{Attribute, ErrorCode, FullSha256Hash, PasswordAlgorithm};

#[cfg(feature = "turn")]
use crate::attribute::turn::{AddressFamily, EvenPort, TransportProtocol};

macro_rules! find_matching_variant {
    ($needle:path, $haystack:expr) => {
        ($haystack).iter().find_map(|elem| match elem {
            $needle(val) => Some(val),
            _ => None,
        })
    };
}

/// Collection of attributes.
#[derive(Clone)]
pub struct Attributes {
    inner: Vec<Attribute>,
}

impl Attributes {
    /// Create an empty collection of attributes.
    pub(crate) const fn empty() -> Self {
        Self::new(Vec::new())
    }

    /// Create a new collection of attributes.
    pub(crate) const fn new(attributes: Vec<Attribute>) -> Self {
        Self { inner: attributes }
    }

    /// Get the error code attribute.
    #[inline]
    pub fn get_error_code(&self) -> Option<&ErrorCode> {
        find_matching_variant!(Attribute::ErrorCode, self.inner)
    }

    /// Get the unknown attributes attribute.
    #[inline]
    pub fn get_unknown_attributes(&self) -> Option<&[u16]> {
        find_matching_variant!(Attribute::UnknownAttributes, self.inner).map(|attrs| attrs.as_ref())
    }

    /// Get the alternate server attribute.
    #[inline]
    pub fn get_alternate_server(&self) -> Option<SocketAddr> {
        find_matching_variant!(Attribute::AlternateServer, self.inner).copied()
    }

    /// Get the alternate domain attribute.
    #[inline]
    pub fn get_alternate_domain(&self) -> Option<&str> {
        find_matching_variant!(Attribute::AlternateDomain, self.inner).map(|domain| &**domain)
    }

    /// Get the mapped address attribute.
    #[inline]
    pub fn get_mapped_address(&self) -> Option<SocketAddr> {
        find_matching_variant!(Attribute::MappedAddress, self.inner).copied()
    }

    /// Get the XOR mapped address attribute.
    #[inline]
    pub fn get_xor_mapped_address(&self) -> Option<SocketAddr> {
        find_matching_variant!(Attribute::XorMappedAddress, self.inner).copied()
    }

    /// Get either the XOR mapped address attribute or the mapped address
    /// attribute if the XOR mapped attribute does not exist.
    #[inline]
    pub fn get_any_mapped_address(&self) -> Option<SocketAddr> {
        self.get_xor_mapped_address()
            .or_else(|| self.get_mapped_address())
    }

    /// Get the username attribute.
    #[inline]
    pub fn get_username(&self) -> Option<&str> {
        find_matching_variant!(Attribute::Username, self.inner).map(|username| &**username)
    }

    /// Get the userhash attribute.
    #[inline]
    pub fn get_userhash(&self) -> Option<&FullSha256Hash> {
        find_matching_variant!(Attribute::Userhash, self.inner)
    }

    /// Get the realm attribute.
    #[inline]
    pub fn get_realm(&self) -> Option<&str> {
        find_matching_variant!(Attribute::Realm, self.inner).map(|realm| &**realm)
    }

    /// Get the nonce attribute.
    #[inline]
    pub fn get_nonce(&self) -> Option<&str> {
        find_matching_variant!(Attribute::Nonce, self.inner).map(|nonce| &**nonce)
    }

    /// Get the password algorithm attribute.
    #[inline]
    pub fn get_password_algorithm(&self) -> Option<&PasswordAlgorithm> {
        find_matching_variant!(Attribute::PasswordAlgorithm, self.inner)
    }

    /// Get the password algorithms attribute.
    #[inline]
    pub fn get_password_algorithms(&self) -> Option<&[PasswordAlgorithm]> {
        find_matching_variant!(Attribute::PasswordAlgorithms, self.inner).map(|algs| algs.as_ref())
    }

    /// Get the software attribute.
    #[inline]
    pub fn get_software(&self) -> Option<&str> {
        find_matching_variant!(Attribute::Software, self.inner).map(|sw| &**sw)
    }

    /// Check if the message integrity attribute is present.
    #[inline]
    pub fn contains_message_integrity(&self) -> bool {
        self.inner
            .iter()
            .any(|attr| matches!(attr, Attribute::MessageIntegrity(_)))
    }

    /// Check if the message integrity SHA-256 attribute is present.
    #[inline]
    pub fn contains_message_integrity_sha256(&self) -> bool {
        self.inner
            .iter()
            .any(|attr| matches!(attr, Attribute::MessageIntegritySha256(_)))
    }
}

#[cfg(feature = "ice")]
#[cfg_attr(docsrs, doc(cfg(feature = "ice")))]
impl Attributes {
    /// Get ICE candidate priority.
    #[inline]
    pub fn get_priority(&self) -> Option<u32> {
        find_matching_variant!(Attribute::Priority, self.inner).copied()
    }

    /// Check if the use ICE candidate attribute is present.
    #[inline]
    pub fn contains_use_candidate(&self) -> bool {
        self.inner
            .iter()
            .any(|attr| matches!(attr, Attribute::UseCandidate))
    }

    /// Get the ICE controlled attribute.
    #[inline]
    pub fn get_ice_controlled(&self) -> Option<u64> {
        find_matching_variant!(Attribute::ICEControlled, self.inner).copied()
    }

    /// Get the ICE controlling attribute.
    #[inline]
    pub fn get_ice_controlling(&self) -> Option<u64> {
        find_matching_variant!(Attribute::ICEControlling, self.inner).copied()
    }
}

#[cfg(feature = "turn")]
#[cfg_attr(docsrs, doc(cfg(feature = "turn")))]
impl Attributes {
    /// Get the requested transport protocol.
    #[inline]
    pub fn get_requested_transport(&self) -> Option<TransportProtocol> {
        find_matching_variant!(Attribute::RequestedTransport, self.inner).copied()
    }

    /// Check if the don't fragment attribute is present.
    #[inline]
    pub fn contains_dont_fragment(&self) -> bool {
        self.inner
            .iter()
            .any(|attr| matches!(attr, Attribute::DontFragment))
    }

    /// Get the reservation token.
    #[inline]
    pub fn get_reservation_token(&self) -> Option<u64> {
        find_matching_variant!(Attribute::ReservationToken, self.inner).copied()
    }

    /// Get the event port attribute.
    #[inline]
    pub fn get_even_port(&self) -> Option<EvenPort> {
        find_matching_variant!(Attribute::EvenPort, self.inner).copied()
    }

    /// Get the requested address family.
    #[inline]
    pub fn get_requested_address_family(&self) -> Option<AddressFamily> {
        find_matching_variant!(Attribute::RequestedAddressFamily, self.inner).copied()
    }

    /// Get the additional address family.
    #[inline]
    pub fn get_additional_address_family(&self) -> Option<AddressFamily> {
        find_matching_variant!(Attribute::AdditionalAddressFamily, self.inner).copied()
    }
}

impl Deref for Attributes {
    type Target = [Attribute];

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}
