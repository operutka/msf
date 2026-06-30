use bytes::{Buf, Bytes};

use crate::attribute::{Attribute, AttributeError};

pub const ATTR_TYPE_PRIORITY: u16 = 0x0024;
pub const ATTR_TYPE_USE_CANDIDATE: u16 = 0x0025;
pub const ATTR_TYPE_ICE_CONTROLLED: u16 = 0x8029;
pub const ATTR_TYPE_ICE_CONTROLLING: u16 = 0x802A;

/// Helper trait for reading ICE attribute values from a byte stream.
pub trait BytesExt {
    /// Try to get an ICE attribute value from the byte stream.
    fn try_get_ice_attribute_value(
        &mut self,
        attribute_type: u16,
    ) -> Result<Option<Attribute>, AttributeError>;
}

impl BytesExt for Bytes {
    fn try_get_ice_attribute_value(
        &mut self,
        attribute_type: u16,
    ) -> Result<Option<Attribute>, AttributeError> {
        let res = match attribute_type {
            ATTR_TYPE_PRIORITY => self
                .try_get_u32()
                .map(Attribute::Priority)
                .map_err(|_| AttributeError::InvalidAttribute)?,
            ATTR_TYPE_USE_CANDIDATE => Attribute::UseCandidate,
            ATTR_TYPE_ICE_CONTROLLED => self
                .try_get_u64()
                .map(Attribute::ICEControlled)
                .map_err(|_| AttributeError::InvalidAttribute)?,
            ATTR_TYPE_ICE_CONTROLLING => self
                .try_get_u64()
                .map(Attribute::ICEControlling)
                .map_err(|_| AttributeError::InvalidAttribute)?,
            _ => return Ok(None),
        };

        Ok(Some(res))
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use crate::attribute::{Attribute, AttributeError};

    /// Parse a single attribute from a raw attribute slice.
    fn parse(bytes: &[u8], long_transaction_id: [u8; 16]) -> Result<Attribute, AttributeError> {
        Attribute::from_bytes(&mut Bytes::copy_from_slice(bytes), long_transaction_id)
    }

    #[test]
    fn test_parse_priority() {
        let input = &[0x00, 0x24, 0x00, 0x04, 0, 0, 0, 5];

        let Ok(Attribute::Priority(p)) = parse(input, [0u8; 16]) else {
            panic!("expected a priority");
        };

        assert_eq!(p, 5);
    }

    #[test]
    fn test_parse_use_candidate() {
        let input = &[0x00, 0x25, 0x00, 0x00];

        let Ok(Attribute::UseCandidate) = parse(input, [0u8; 16]) else {
            panic!("expected a use-candidate");
        };
    }

    #[test]
    fn test_parse_ice_controlled() {
        let input = &[0x80, 0x29, 0x00, 0x08, 0, 0, 0, 0, 0, 0, 0, 7];

        let Ok(Attribute::ICEControlled(n)) = parse(input, [0u8; 16]) else {
            panic!("expected an ice-controlled");
        };

        assert_eq!(n, 7);
    }

    #[test]
    fn test_parse_ice_controlling() {
        let input = &[0x80, 0x2a, 0x00, 0x08, 0, 0, 0, 0, 0, 0, 0, 9];

        let Ok(Attribute::ICEControlling(n)) = parse(input, [0u8; 16]) else {
            panic!("expected an ice-controlling");
        };

        assert_eq!(n, 9);
    }
}
