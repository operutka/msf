use std::fmt::{self, Display, Formatter};

use crate::{Error, InternalError};

/// SRTP profile ID.
#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum SrtpProfileId {
    SRTP_NULL_SHA1_32,
    SRTP_NULL_SHA1_80,
    SRTP_AES128_CM_SHA1_32,
    SRTP_AES128_CM_SHA1_80,
}

impl SrtpProfileId {
    /// Convert a given SRTP profile ID from OpenSSL into this ID.
    fn from_openssl(id: openssl::srtp::SrtpProfileId) -> Result<Self, InternalError> {
        let res = match id {
            openssl::srtp::SrtpProfileId::SRTP_NULL_SHA1_32 => Self::SRTP_NULL_SHA1_32,
            openssl::srtp::SrtpProfileId::SRTP_NULL_SHA1_80 => Self::SRTP_NULL_SHA1_80,
            openssl::srtp::SrtpProfileId::SRTP_AES128_CM_SHA1_32 => Self::SRTP_AES128_CM_SHA1_32,
            openssl::srtp::SrtpProfileId::SRTP_AES128_CM_SHA1_80 => Self::SRTP_AES128_CM_SHA1_80,
            _ => return Err(InternalError::UnsupportedProfile),
        };

        Ok(res)
    }
}

impl Display for SrtpProfileId {
    #[inline]
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let id = match self {
            Self::SRTP_NULL_SHA1_32 => "SRTP_NULL_SHA1_32",
            Self::SRTP_NULL_SHA1_80 => "SRTP_NULL_SHA1_80",
            Self::SRTP_AES128_CM_SHA1_32 => "SRTP_AES128_CM_SHA1_32",
            Self::SRTP_AES128_CM_SHA1_80 => "SRTP_AES128_CM_SHA1_80",
        };

        f.write_str(id)
    }
}

/// SRTP profile information.
#[derive(Copy, Clone)]
pub struct SrtpProfile {
    inner: &'static InnerProfileParameters,
}

impl SrtpProfile {
    /// Get SRTP profile information from a given OpenSSL SRTP profile ID.
    pub fn from_openssl(id: openssl::srtp::SrtpProfileId) -> Result<Self, Error> {
        let id = SrtpProfileId::from_openssl(id)?;

        Ok(id.into())
    }

    /// Get SRTP profile ID.
    pub fn id(&self) -> SrtpProfileId {
        self.inner.id
    }

    /// Get length of the master key in bits.
    pub fn master_key_len(&self) -> u32 {
        self.inner.master_key_len
    }

    /// Get length of the master salt in bits.
    pub fn master_salt_len(&self) -> u32 {
        self.inner.master_salt_len
    }

    /// Get length of the session encoding key in bits.
    pub fn session_enc_key_len(&self) -> u32 {
        self.inner.session_enc_key_len
    }

    /// Get length of the session authentication key in bits.
    pub fn session_auth_key_len(&self) -> u32 {
        self.inner.session_auth_key_len
    }

    /// Get length of the session salt in bits.
    pub fn session_salt_len(&self) -> u32 {
        self.inner.session_salt_len
    }

    /// Get the value of key-derivation rate.
    pub fn key_derivation_rate(&self) -> u64 {
        self.inner.key_derivation_rate
    }

    /// Get length of the RTP authentication tag in bits.
    pub fn rtp_auth_tag_len(&self) -> u32 {
        self.inner.rtp_auth_tag_len
    }

    /// Get length of the RTCP authentication tag in bits.
    pub fn rtcp_auth_tag_len(&self) -> u32 {
        self.inner.rtcp_auth_tag_len
    }

    /// Get length of the authentication function output in bits.
    pub fn auth_output_len(&self) -> u32 {
        self.inner.auth_output_len
    }

    /// Get the SRTP prefix length value.
    pub fn srtp_prefix_len(&self) -> u32 {
        self.inner.srtp_prefix_len
    }
}

impl From<SrtpProfileId> for SrtpProfile {
    fn from(id: SrtpProfileId) -> Self {
        let params = match id {
            SrtpProfileId::SRTP_NULL_SHA1_32 => &PARAMS_SRTP_NULL_SHA1_32,
            SrtpProfileId::SRTP_NULL_SHA1_80 => &PARAMS_SRTP_NULL_SHA1_80,
            SrtpProfileId::SRTP_AES128_CM_SHA1_32 => &PARAMS_SRTP_AES128_CM_SHA1_32,
            SrtpProfileId::SRTP_AES128_CM_SHA1_80 => &PARAMS_SRTP_AES128_CM_SHA1_80,
        };

        Self { inner: params }
    }
}

/// Helper struct.
struct InnerProfileParameters {
    id: SrtpProfileId,
    master_key_len: u32,
    master_salt_len: u32,
    session_enc_key_len: u32,
    session_auth_key_len: u32,
    session_salt_len: u32,
    key_derivation_rate: u64,
    rtp_auth_tag_len: u32,
    rtcp_auth_tag_len: u32,
    auth_output_len: u32,
    srtp_prefix_len: u32,
}

impl InnerProfileParameters {
    /// Construct profile parameters for a given SRTP profile ID.
    const fn new(id: SrtpProfileId) -> Self {
        let mut res = Self {
            id,
            master_key_len: 128,
            master_salt_len: 112,
            session_enc_key_len: 0,
            session_auth_key_len: 160,
            session_salt_len: 0,
            key_derivation_rate: 0,
            rtp_auth_tag_len: 80,
            rtcp_auth_tag_len: 80,
            auth_output_len: 160,
            srtp_prefix_len: 0,
        };

        match id {
            SrtpProfileId::SRTP_NULL_SHA1_32 => {
                res.rtp_auth_tag_len = 32;
            }
            SrtpProfileId::SRTP_NULL_SHA1_80 => (),
            SrtpProfileId::SRTP_AES128_CM_SHA1_32 => {
                res.session_enc_key_len = 128;
                res.session_salt_len = 112;
                res.rtp_auth_tag_len = 32;
            }
            SrtpProfileId::SRTP_AES128_CM_SHA1_80 => {
                res.session_enc_key_len = 128;
                res.session_salt_len = 112;
            }
        }

        res
    }
}

static PARAMS_SRTP_NULL_SHA1_32: InnerProfileParameters =
    InnerProfileParameters::new(SrtpProfileId::SRTP_NULL_SHA1_32);
static PARAMS_SRTP_NULL_SHA1_80: InnerProfileParameters =
    InnerProfileParameters::new(SrtpProfileId::SRTP_NULL_SHA1_80);
static PARAMS_SRTP_AES128_CM_SHA1_32: InnerProfileParameters =
    InnerProfileParameters::new(SrtpProfileId::SRTP_AES128_CM_SHA1_32);
static PARAMS_SRTP_AES128_CM_SHA1_80: InnerProfileParameters =
    InnerProfileParameters::new(SrtpProfileId::SRTP_AES128_CM_SHA1_80);
