//! H.264 extensions.

use std::fmt::{self, Display, Formatter};

use base64::display::Base64Display;
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

/// H.264 format parameters.
#[derive(Clone)]
pub struct H264Parameters {
    packetization_mode: u8,
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
            profile_level_id,
            parameter_sets,
        };

        Ok(res)
    }
}

impl Display for H264Parameters {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "packetization-mode={}", self.packetization_mode)?;

        if let Some(profile_level_id) = self.profile_level_id.as_ref() {
            write!(f, ";profile-level-id={}", profile_level_id)?;
        }

        if let Some(mut parameter_sets) = self.parameter_sets.clone() {
            f.write_str(";sprop-parameter-sets=")?;

            if let Ok(Some(nal_unit)) = extract_nal_unit(&mut parameter_sets) {
                write!(
                    f,
                    "{}",
                    Base64Display::with_config(&nal_unit, base64::STANDARD)
                )?;
            }

            while let Ok(Some(nal_unit)) = extract_nal_unit(&mut parameter_sets) {
                write!(
                    f,
                    ",{}",
                    Base64Display::with_config(&nal_unit, base64::STANDARD)
                )?;
            }
        }

        Ok(())
    }
}

/// Helper struct.
#[derive(Copy, Clone)]
struct ProfileLevelId {
    profile_idc: u8,
    constraints: u8,
    level_idc: u8,
}

impl ProfileLevelId {
    /// Create a new profile level ID.
    const fn new(profile_idc: u8, constraints: u8, level_idc: u8) -> Self {
        Self {
            profile_idc,
            constraints,
            level_idc,
        }
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
