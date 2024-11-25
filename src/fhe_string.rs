use std::ops::Deref;

use tfhe::integer::{IntegerCiphertext, IntegerRadixCiphertext, RadixCiphertext};

use crate::{client_key::ClientKey, server_key::ServerKey};

pub const N: usize = 4;
pub const NUM_BLOCKS: usize = 4;

#[derive(Clone)]
pub struct FheString {
    pub(crate) bytes: Vec<RadixCiphertext>,
}

impl FheString {
    pub fn encrypt(string: PlaintextString, ck: &ClientKey) -> Self {
        let bytes = string
            .bytes()
            .map(|b| ck.key.encrypt_radix(b, NUM_BLOCKS))
            .collect();
        Self { bytes }
    }

    pub fn decrypt(&self, ck: &ClientKey) -> String {
        let bytes = self
            .bytes
            .iter()
            .map(|b| ck.key.decrypt_radix(b))
            .filter(|b| *b != 0)
            .collect();
        String::from_utf8(bytes).unwrap()
    }

    /// Constructs a trivial `FheString` from a plaintext string and a [`ServerKey`].
    /// This only formats the value to fit the ciphertext. The result is NOT encrypted.
    pub fn enc_trivial(str: &str, server_key: &ServerKey) -> Self {
        let bytes = str
            .bytes()
            .map(|b| server_key.key.create_trivial_radix(b, NUM_BLOCKS))
            .collect();
        Self { bytes }
    }

    pub fn empty() -> Self {
        Self { bytes: vec![] }
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
        let mut uint = RadixCiphertext::from_blocks(blocks);
        if uint.blocks().is_empty() {
            sk.key
                .extend_radix_with_trivial_zero_blocks_lsb_assign(&mut uint, NUM_BLOCKS);
        }

        uint
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

        Self { bytes }
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
