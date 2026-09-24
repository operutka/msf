//! H.264 extensions.

use std::{
    fmt::{self, Display, Formatter},
    str::FromStr,
};

use base64::{display::Base64Display, engine::Engine, prelude::BASE64_STANDARD, DecodeError};
use bytes::Bytes;
use msf_util::h264::{extract_nal_unit, InvalidByteStream};

/// Invalid H.264 parameters.
#[derive(Debug, Copy, Clone)]
pub struct InvalidParameters;

impl Display for InvalidParameters {
    #[inline]
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.write_str("invalid h264 parameters")
    }
}

impl std::error::Error for InvalidParameters {}

impl From<InvalidByteStream> for InvalidParameters {
    fn from(_: InvalidByteStream) -> Self {
        Self
    }
}

impl From<InvalidProfileLevelId> for InvalidParameters {
    fn from(_: InvalidProfileLevelId) -> Self {
        Self
    }
}

/// H.264 format parameters.
#[derive(Clone)]
pub struct H264Parameters {
    packetization_mode: u8,
    interleaving_depth: Option<u16>,
    max_don_diff: Option<u16>,
    profile_level_id: Option<ProfileLevelId>,
    parameter_sets: Option<Bytes>,
}

impl H264Parameters {
    /// Create new H.264 format parameters.
    ///
    /// # Arguments
    /// * `packetization_mode` - packetization mode as defined in RFC 6184
    /// * `parameter_sets` - session and picture parameter sets encoded as a
    ///   single H.264 byte stream
    pub fn new(
        packetization_mode: u8,
        parameter_sets: Option<Bytes>,
    ) -> Result<Self, InvalidParameters> {
        let mut profile_level_id = None;

        if let Some(mut parameter_sets) = parameter_sets.clone() {
            while let Some(nal_unit) = extract_nal_unit(&mut parameter_sets)? {
                if nal_unit.is_empty() || (nal_unit[0] & 0x1f) != 7 {
                    continue;
                }

                if nal_unit.len() < 4 {
                    return Err(InvalidParameters);
                }

                let profile_idc = nal_unit[1];
                let constraints = nal_unit[2];
                let level_idc = nal_unit[3];

                profile_level_id = Some(ProfileLevelId::new(profile_idc, constraints, level_idc));
            }
        }

        let res = Self {
            packetization_mode,
            interleaving_depth: None,
            max_don_diff: None,
            profile_level_id,
            parameter_sets,
        };

        Ok(res)
    }

    /// Get the packetization mode.
    #[inline]
    pub fn packetization_mode(&self) -> u8 {
        self.packetization_mode
    }

    /// Get the interleaving depth.
    #[inline]
    pub fn interleaving_depth(&self) -> Option<u16> {
        self.interleaving_depth
    }

    /// Set the interleaving depth.
    #[inline]
    pub fn with_interleaving_depth(mut self, depth: u16) -> Self {
        self.interleaving_depth = Some(depth);
        self
    }

    /// Get the maximum DON difference.
    #[inline]
    pub fn max_don_diff(&self) -> Option<u16> {
        self.max_don_diff
    }

    /// Set the maximum DON difference.
    #[inline]
    pub fn with_max_don_diff(mut self, max_don_diff: u16) -> Self {
        self.max_don_diff = Some(max_don_diff);
        self
    }

    /// Get the profile-level ID.
    #[inline]
    pub fn profile_level_id(&self) -> Option<ProfileLevelId> {
        self.profile_level_id
    }

    /// Get the parameter sets.
    #[inline]
    pub fn parameter_sets(&self) -> Option<&Bytes> {
        self.parameter_sets.as_ref()
    }
}

impl Display for H264Parameters {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "packetization-mode={}", self.packetization_mode)?;

        if let Some(depth) = self.interleaving_depth {
            write!(f, ";sprop-interleaving-depth={depth}")?;
        }

        if let Some(max_don_diff) = self.max_don_diff {
            write!(f, ";sprop-max-don-diff={max_don_diff}")?;
        }

        if let Some(profile_level_id) = self.profile_level_id.as_ref() {
            write!(f, ";profile-level-id={profile_level_id}")?;
        }

        if let Some(mut parameter_sets) = self.parameter_sets.clone() {
            f.write_str(";sprop-parameter-sets=")?;

            if let Ok(Some(nal_unit)) = extract_nal_unit(&mut parameter_sets) {
                write!(f, "{}", Base64Display::new(&nal_unit, &BASE64_STANDARD))?;
            }

            while let Ok(Some(nal_unit)) = extract_nal_unit(&mut parameter_sets) {
                write!(f, ",{}", Base64Display::new(&nal_unit, &BASE64_STANDARD))?;
            }
        }

        Ok(())
    }
}

impl FromStr for H264Parameters {
    type Err = InvalidParameters;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let params = s
            .split(';')
            .map(str::trim)
            .filter(|param| !param.is_empty());

        let mut packetization_mode = None;
        let mut interleaving_depth = None;
        let mut max_don_diff = None;
        let mut profile_level_id = None;
        let mut parameter_sets = None;

        for param in params {
            let (key, value) = param.split_once('=').ok_or(InvalidParameters)?;

            let key = key.trim();
            let value = value.trim();

            match key {
                "packetization-mode" => packetization_mode = Some(value),
                "sprop-interleaving-depth" => interleaving_depth = Some(value),
                "sprop-max-don-diff" => max_don_diff = Some(value),
                "profile-level-id" => profile_level_id = Some(value),
                "sprop-parameter-sets" => parameter_sets = Some(value),
                _ => (),
            }
        }

        let packetization_mode = packetization_mode
            .unwrap_or("0")
            .parse::<u8>()
            .map_err(|_| InvalidParameters)?;

        let interleaving_depth = interleaving_depth
            .map(u16::from_str)
            .transpose()
            .map_err(|_| InvalidParameters)?;

        let max_don_diff = max_don_diff
            .map(u16::from_str)
            .transpose()
            .map_err(|_| InvalidParameters)?;

        let profile_level_id = profile_level_id.map(ProfileLevelId::from_str).transpose()?;

        let parameter_sets = parameter_sets
            .map(parse_parameter_sets)
            .transpose()
            .map_err(|_| InvalidParameters)?;

        let res = Self {
            packetization_mode,
            interleaving_depth,
            max_don_diff,
            profile_level_id,
            parameter_sets,
        };

        Ok(res)
    }
}

/// Invalid H.264 profile-level ID.
#[derive(Debug, Copy, Clone)]
pub struct InvalidProfileLevelId;

impl Display for InvalidProfileLevelId {
    #[inline]
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.write_str("invalid h264 profile-level-id")
    }
}

impl std::error::Error for InvalidProfileLevelId {}

/// Profile-level ID.
#[derive(Copy, Clone)]
pub struct ProfileLevelId {
    profile_idc: u8,
    constraints: u8,
    level_idc: u8,
}

impl ProfileLevelId {
    /// Create a new profile level ID.
    #[inline]
    pub const fn new(profile_idc: u8, constraints: u8, level_idc: u8) -> Self {
        Self {
            profile_idc,
            constraints,
            level_idc,
        }
    }

    /// Get the profile IDC.
    #[inline]
    pub const fn profile_idc(&self) -> u8 {
        self.profile_idc
    }

    /// Get the constraints.
    #[inline]
    pub const fn constraints(&self) -> u8 {
        self.constraints
    }

    /// Get the level IDC.
    #[inline]
    pub const fn level_idc(&self) -> u8 {
        self.level_idc
    }
}

impl Display for ProfileLevelId {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(
            f,
            "{:02X}{:02X}{:02X}",
            self.profile_idc, self.constraints, self.level_idc
        )
    }
}

impl FromStr for ProfileLevelId {
    type Err = InvalidProfileLevelId;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != 6 {
            return Err(InvalidProfileLevelId);
        }

        let n = u32::from_str_radix(s, 16).map_err(|_| InvalidProfileLevelId)?;

        let profile_idc = (n >> 16) as u8;
        let constraints = (n >> 8) as u8;
        let level_idc = n as u8;

        let res = Self::new(profile_idc, constraints, level_idc);

        Ok(res)
    }
}

/// Parse parameter sets from a given Base64 list.
fn parse_parameter_sets(s: &str) -> Result<Bytes, DecodeError> {
    let mut res = Vec::new();

    for b64 in s.split(',') {
        let input = b64.trim();

        if input.is_empty() {
            continue;
        }

        res.extend_from_slice(&[0, 0, 1]);

        Engine::decode_vec(&BASE64_STANDARD, input, &mut res)?;
    }

    Ok(res.into())
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::{H264Parameters, ProfileLevelId};

    /// H.264 byte stream containing an SPS and a PPS NAL unit.
    const PARAMETER_SETS: &[u8] = &[
        0, 0, 1, 0x67, 0x42, 0xe0, 0x1e, 0xab, 0, 0, 1, 0x68, 0xce, 0x3c, 0x80,
    ];

    const FMTP: &str = concat!(
        "packetization-mode=1",
        ";sprop-interleaving-depth=2",
        ";sprop-max-don-diff=3",
        ";profile-level-id=42E01E",
        ";sprop-parameter-sets=Z0LgHqs=,aM48gA==",
    );

    #[test]
    fn test_new() {
        let params = H264Parameters::new(1, Some(Bytes::from_static(PARAMETER_SETS))).unwrap();

        assert_eq!(params.packetization_mode(), 1);
        assert_eq!(params.interleaving_depth(), None);
        assert_eq!(params.max_don_diff(), None);
        assert_eq!(params.parameter_sets().unwrap(), PARAMETER_SETS);

        // the profile-level ID is extracted from the SPS
        let profile_level_id = params.profile_level_id().unwrap();

        assert_eq!(profile_level_id.profile_idc(), 0x42);
        assert_eq!(profile_level_id.constraints(), 0xe0);
        assert_eq!(profile_level_id.level_idc(), 0x1e);

        assert_eq!(
            params.to_string(),
            "packetization-mode=1;profile-level-id=42E01E;sprop-parameter-sets=Z0LgHqs=,aM48gA=="
        );

        // there is no SPS to take the profile-level ID from
        let params = H264Parameters::new(0, None).unwrap();

        assert!(params.profile_level_id().is_none());
        assert!(params.parameter_sets().is_none());
        assert_eq!(params.to_string(), "packetization-mode=0");
    }

    #[test]
    fn test_new_errors() {
        // a truncated SPS
        let sps = Bytes::from_static(&[0, 0, 1, 0x67, 0x42]);

        assert!(H264Parameters::new(1, Some(sps)).is_err());

        // not a byte stream at all
        let sets = Bytes::from_static(&[0x67, 0x42, 0xe0, 0x1e]);

        assert!(H264Parameters::new(1, Some(sets)).is_err());
    }

    #[test]
    fn test_from_str() {
        let params = FMTP.parse::<H264Parameters>().unwrap();

        assert_eq!(params.packetization_mode(), 1);
        assert_eq!(params.interleaving_depth(), Some(2));
        assert_eq!(params.max_don_diff(), Some(3));
        assert_eq!(params.profile_level_id().unwrap().to_string(), "42E01E");
        assert_eq!(params.parameter_sets().unwrap(), PARAMETER_SETS);

        assert_eq!(params.to_string(), FMTP);
    }

    #[test]
    fn test_from_str_defaults() {
        // unknown parameters are ignored and the packetization mode defaults
        // to zero
        let params = "profile-level-id=42E01E;foo=bar"
            .parse::<H264Parameters>()
            .unwrap();

        assert_eq!(params.packetization_mode(), 0);
        assert!(params.parameter_sets().is_none());

        let params = H264Parameters::new(0, None)
            .unwrap()
            .with_interleaving_depth(5)
            .with_max_don_diff(6);

        assert_eq!(params.interleaving_depth(), Some(5));
        assert_eq!(params.max_don_diff(), Some(6));
        assert_eq!(
            params.to_string(),
            "packetization-mode=0;sprop-interleaving-depth=5;sprop-max-don-diff=6"
        );
    }

    #[test]
    fn test_from_str_errors() {
        // a parameter without a value
        assert!("packetization-mode".parse::<H264Parameters>().is_err());

        assert!("packetization-mode=x".parse::<H264Parameters>().is_err());
        assert!("sprop-interleaving-depth=x"
            .parse::<H264Parameters>()
            .is_err());
        assert!("sprop-max-don-diff=x".parse::<H264Parameters>().is_err());
        assert!("profile-level-id=42E0".parse::<H264Parameters>().is_err());
        assert!("sprop-parameter-sets=@@@"
            .parse::<H264Parameters>()
            .is_err());
    }

    #[test]
    fn test_profile_level_id() {
        let id = "42E01E".parse::<ProfileLevelId>().unwrap();

        assert_eq!(id.profile_idc(), 0x42);
        assert_eq!(id.constraints(), 0xe0);
        assert_eq!(id.level_idc(), 0x1e);
        assert_eq!(id.to_string(), "42E01E");

        // lower-case input is accepted as well
        assert_eq!(
            "42e01e".parse::<ProfileLevelId>().unwrap().to_string(),
            "42E01E"
        );

        assert_eq!(ProfileLevelId::new(0x4d, 0x40, 0x28).to_string(), "4D4028");

        // an invalid length
        assert!("42E01".parse::<ProfileLevelId>().is_err());
        assert!("42E01E0".parse::<ProfileLevelId>().is_err());

        // not a hexadecimal number
        assert!("42E0XX".parse::<ProfileLevelId>().is_err());
    }
}
