const ICE_CHARACTERS: &[u8; 64] =
    b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+/";

/// Generate a random string of a given length using the ICE characters.
pub fn random_ice_string(len: usize) -> String {
    let mut res = String::with_capacity(len);

    let mut available_bits = 0u8;
    let mut random_bits = 0u16;

    while res.len() < len {
        // fill up the buffer of random bits if needed
        if available_bits < 6 {
            random_bits = (random_bits << 8) | rand::random::<u8>() as u16;
            available_bits += 8;
        }

        // get the top six bits from the buffer
        let index = ((random_bits >> (available_bits - 6)) & 0x3f) as usize;

        res.push(char::from(ICE_CHARACTERS[index]));

        available_bits -= 6;
    }

    res
}
