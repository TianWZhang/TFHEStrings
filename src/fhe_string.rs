use std::ops::{Add, Deref};

use tfhe::integer::{BooleanBlock, IntegerCiphertext, IntegerRadixCiphertext, RadixCiphertext};

use crate::{server_key::ServerKey, SERVER_KEY};

pub const N: usize = 4;
pub const NUM_BLOCKS: usize = 4;

#[derive(Clone)]
pub struct FheString {
    pub(crate) bytes: Vec<RadixCiphertext>,
    pub(crate) padded: bool,
}

impl FheString {
    /// Constructs a trivial `FheString` from a plaintext string and a [`ServerKey`].
    /// This only formats the value to fit the ciphertext. The result is NOT encrypted.
    pub fn enc_trivial(str: &str, server_key: &ServerKey) -> Self {
        let bytes = str
            .bytes()
            .map(|b| server_key.key.create_trivial_radix(b, NUM_BLOCKS))
            .collect();
        Self {
            bytes,
            padded: false,
        }
    }

    pub fn empty() -> Self {
        Self {
            bytes: vec![],
            padded: false,
        }
    }

    // Converts a `FheString` to a `RadixCiphertext`, taking 4 blocks for each `FheAsciiChar`.
    // We can then use a single large uint, that represents a string, in tfhe-rs operations.
    pub fn to_uint(&self, sk: &ServerKey) -> RadixCiphertext {
        self.clone().into_uint(sk)
    }

    pub fn into_uint(self, sk: &ServerKey) -> RadixCiphertext {
        let blocks: Vec<_> = self
            .bytes
            .into_iter()
            .rev()
            .flat_map(|c| c.into_blocks())
            .collect();
        let mut enc_uint = RadixCiphertext::from_blocks(blocks);
        if enc_uint.blocks().is_empty() {
            sk.key
                .extend_radix_with_trivial_zero_blocks_lsb_assign(&mut enc_uint, NUM_BLOCKS);
        }

        enc_uint
    }

    /// Converts a `RadixCiphertext` to a `FheString`, building a `FheAsciiChar` for each `NUM_BLOCKS` blocks.
    /// Panics if the uint doesn't have a number of blocks that is multiple of `NUM_BLOCKS`.
    pub fn from_uint(uint: RadixCiphertext) -> Self {
        let blocks_len = uint.blocks().len();
        assert_eq!(blocks_len % NUM_BLOCKS, 0);

        let mut blocks = uint.into_blocks();
        blocks.reverse();

        let bytes = blocks
            .chunks_exact(NUM_BLOCKS)
            .map(|chuck| RadixCiphertext::from_blocks(chuck.iter().rev().cloned().collect()))
            .collect();

        // We are assuming that the string is not padded,
        // so this isn't safe if we don't know it.
        Self {
            bytes,
            padded: false,
        }
    }

    pub fn append_null(&mut self, sk: &ServerKey) {
        self.bytes
            .push(sk.key.create_trivial_zero_radix(NUM_BLOCKS));
        self.padded = true;
    }

    pub fn to_uppercase(&self) -> FheString {
        SERVER_KEY.with(|sk| {
            let sk = sk.borrow();
            sk.as_ref().unwrap().to_uppercase(self)
        })
    }

    pub fn to_lowercase(&self) -> FheString {
        SERVER_KEY.with(|sk| {
            let sk = sk.borrow();
            sk.as_ref().unwrap().to_lowercase(self)
        })
    }

    pub fn find(&self, pattern: &GenericPattern) -> (RadixCiphertext, BooleanBlock) {
        SERVER_KEY.with(|sk| {
            let sk = sk.borrow();
            sk.as_ref().unwrap().find(self, pattern)
        })
    }
}

impl Add<&FheString> for FheString {
    type Output = Self;

    fn add(self, rhs: &FheString) -> Self::Output {
        SERVER_KEY.with(|sk| {
            let sk = sk.borrow();
            sk.as_ref().unwrap().concat(&self, rhs)
        })
    }
}

#[derive(Clone)]
pub struct PlaintextString {
    pub data: String,
}

impl PlaintextString {
    pub fn new(data: String) -> Self {
        assert!(
            data.is_ascii(),
            "The input string must only contain ascii letters"
        );
        assert!(!data.contains('\0'));
        assert!(data.len() <= 8 * N);
        Self { data }
    }
}

impl Deref for PlaintextString {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

#[derive(Clone)]
pub enum GenericPattern {
    Clear(PlaintextString),
    Enc(FheString),
}

#[cfg(test)]
mod tests {
    use tfhe::shortint::prelude::PARAM_MESSAGE_2_CARRY_2;

    use crate::{generate_keys, set_server_key};

    #[test]
    fn test_to_lowercase() {
        let s = "AF";
        let (ck, sk) = generate_keys(PARAM_MESSAGE_2_CARRY_2);
        set_server_key(sk);
        let fhe_s = ck.enc_str(s, 0);
        let fhe_s_tolowercase = fhe_s.to_lowercase();
        let s_tolowercase = ck.dec_str(&fhe_s_tolowercase);
        assert_eq!(s_tolowercase, s.to_lowercase());
    }
}
