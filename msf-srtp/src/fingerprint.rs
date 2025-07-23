use std::{
    fmt::{self, Display, Formatter},
    str::FromStr,
};

use openssl::{hash::MessageDigest, x509::X509Ref};

use crate::Error;

/// Unknown hash function.
#[derive(Debug, Copy, Clone)]
pub struct UnknownHashFunction;

impl Display for UnknownHashFunction {
    #[inline]
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.write_str("unknown hash function")
    }
}

impl std::error::Error for UnknownHashFunction {}

/// Hash function.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum HashFunction {
    Md5,
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

impl HashFunction {
    /// Get the OpenSSL message digest.
    pub(crate) fn into_message_digest(self) -> MessageDigest {
        match self {
            Self::Md5 => MessageDigest::md5(),
            Self::Sha1 => MessageDigest::sha1(),
            Self::Sha224 => MessageDigest::sha224(),
            Self::Sha256 => MessageDigest::sha256(),
            Self::Sha384 => MessageDigest::sha384(),
            Self::Sha512 => MessageDigest::sha512(),
        }
    }

    /// Get size of the resulting hash in bits.
    pub(crate) fn hash_size(self) -> usize {
        match self {
            Self::Md5 => 128,
            Self::Sha1 => 160,
            Self::Sha224 => 224,
            Self::Sha256 => 256,
            Self::Sha384 => 384,
            Self::Sha512 => 512,
        }
    }
}

impl Display for HashFunction {
    #[inline]
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let s = match self {
            Self::Md5 => "md5",
            Self::Sha1 => "sha-1",
            Self::Sha224 => "sha-224",
            Self::Sha256 => "sha-256",
            Self::Sha384 => "sha-384",
            Self::Sha512 => "sha-512",
        };

        f.write_str(s)
    }
}

impl FromStr for HashFunction {
    type Err = UnknownHashFunction;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let res = match s {
            "md5" => Self::Md5,
            "sha-1" => Self::Sha1,
            "sha-224" => Self::Sha224,
            "sha-256" => Self::Sha256,
            "sha-384" => Self::Sha384,
            "sha-512" => Self::Sha512,
            _ => return Err(UnknownHashFunction),
        };

        Ok(res)
    }
}

/// Invalid fingerprint.
#[derive(Debug, Copy, Clone)]
pub enum InvalidFingerprint {
    UnknownHashFunction,
    InvalidData,
}

impl Display for InvalidFingerprint {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Self::UnknownHashFunction => Display::fmt(&UnknownHashFunction, f),
            Self::InvalidData => f.write_str("invalid data"),
        }
    }
}

impl std::error::Error for InvalidFingerprint {}

impl From<UnknownHashFunction> for InvalidFingerprint {
    #[inline]
    fn from(_: UnknownHashFunction) -> Self {
        Self::UnknownHashFunction
    }
}

/// Certificate fingerprint.
///
/// The fingerprint can be formatted/parsed to/from an uppercase hex string
/// prefixed with the name of the hash function.
#[derive(Clone, Eq, PartialEq)]
pub struct CertificateFingerprint {
    hash_function: HashFunction,
    fingerprint: Vec<u8>,
}

impl CertificateFingerprint {
    /// Create fingerprint of a given certificate.
    #[inline]
    pub fn new(cert: &X509Ref, hash_function: HashFunction) -> Result<Self, Error> {
        let digest = cert.digest(hash_function.into_message_digest())?;

        let res = Self {
            hash_function,
            fingerprint: digest.to_vec(),
        };

        Ok(res)
    }

    /// Verify that this fingerprint matches a given certificate.
    #[inline]
    pub fn verify(&self, cert: &X509Ref) -> Result<bool, Error> {
        let other = Self::new(cert, self.hash_function)?;

        Ok(self == &other)
    }
}

impl Display for CertificateFingerprint {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(&self.hash_function, f)?;

        let mut bytes = self.fingerprint.iter();

        if let Some(b) = bytes.next() {
            write!(f, " {b:02X}")?;
        }

        for b in bytes {
            write!(f, ":{b:02X}")?;
        }

        Ok(())
    }
}

impl FromStr for CertificateFingerprint {
    type Err = InvalidFingerprint;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();

        if let Some(space) = s.find(' ') {
            let (hash_function, rest) = s.split_at(space);

            let digest = rest.trim();

            let hash_function = HashFunction::from_str(hash_function)?;

            let hash_size = hash_function.hash_size() >> 3;

            let mut fingerprint = Vec::with_capacity(hash_size);

            for byte in digest.split(':') {
                let byte =
                    u8::from_str_radix(byte, 16).map_err(|_| InvalidFingerprint::InvalidData)?;

                fingerprint.push(byte);
            }

            if fingerprint.len() != hash_size {
                return Err(InvalidFingerprint::InvalidData);
            }

            let res = Self {
                hash_function,
                fingerprint,
            };

            Ok(res)
        } else {
            Err(InvalidFingerprint::InvalidData)
        }
    }
}
