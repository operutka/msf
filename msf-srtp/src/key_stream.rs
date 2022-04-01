use openssl::symm::{Cipher, Crypter, Mode};

use crate::Error;

/// Key stream.
pub trait KeyStream {
    /// Fill a given buffer with key-stream data.
    fn take(&mut self, output: &mut [u8]) -> Result<(), Error>;

    /// Skip a given number of bytes in the key-stream.
    fn skip(&mut self, mut len: usize) -> Result<(), Error> {
        let mut buf = [0u8; 128];

        while len > 0 {
            let take = len.min(buf.len());

            self.take(&mut buf[..take])?;

            len -= take;
        }

        Ok(())
    }

    /// XOR key-stream data onto given input data and write the result into a
    /// given output buffer.
    ///
    /// # Panics
    /// The method panics if the output buffer is shorter than the input
    /// buffer.
    fn xor(&mut self, input: &[u8], output: &mut [u8]) -> Result<(), Error> {
        let len = input.len();

        debug_assert!(output.len() >= len);

        self.take(&mut output[..len])?;

        let u64_len = len >> 3;
        let rem_len = len & 7;

        let u64_input =
            unsafe { std::slice::from_raw_parts(input.as_ptr() as *const u64, u64_len) };

        let u64_output =
            unsafe { std::slice::from_raw_parts_mut(output.as_mut_ptr() as *mut u64, u64_len) };

        for i in 0..u64_len {
            u64_output[i] ^= u64_input[i];
        }

        let rem_start = len - rem_len;

        for i in rem_start..len {
            output[i] ^= input[i];
        }

        Ok(())
    }
}

/// AES 128 CM key-stream.
pub struct AES128CM {
    crypter: Crypter,
    input: [u8; 128],
    buffer: [u8; 144],
    available: usize,
    offset: usize,
}

impl AES128CM {
    /// Create a new AES 128 CM key-stream.
    pub fn new(key: &[u8], iv: &[u8]) -> Result<Self, Error> {
        let crypter = Crypter::new(Cipher::aes_128_ctr(), Mode::Encrypt, key, Some(iv))?;

        let res = Self {
            crypter,
            input: [0u8; 128],
            buffer: [0u8; 144],
            available: 0,
            offset: 0,
        };

        Ok(res)
    }
}

impl KeyStream for AES128CM {
    fn take(&mut self, output: &mut [u8]) -> Result<(), Error> {
        let output_len = output.len();

        let mut output_offset = 0;

        while output_offset < output_len {
            let remaining = output_len - output_offset;

            if self.available == 0 {
                let max = self.input.len();
                let len = max.min((remaining + 15) & !15);

                let len = self.crypter.update(&self.input[..len], &mut self.buffer)?;

                self.offset = 0;
                self.available = len;
            }

            let take = self.available.min(remaining);

            let buffer_start = self.offset;
            let buffer_end = self.offset + take;
            let output_start = output_offset;
            let output_end = output_offset + take;

            let src = &self.buffer[buffer_start..buffer_end];
            let dst = &mut output[output_start..output_end];

            dst.copy_from_slice(src);

            output_offset += take;

            self.available -= take;
            self.offset += take;
        }

        Ok(())
    }
}
