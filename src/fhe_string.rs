use std::ops::Deref;

use tfhe::integer::RadixCiphertext;

use crate::{client_key::ClientKey, server_key::ServerKey};

pub const N: usize = 4;
pub const NUM_BLOCKS: usize = 4;

#[derive(Clone)]
pub struct FheString {
    pub(crate) bytes: Vec<RadixCiphertext>,
    pub(crate) padded: bool,
}

impl FheString {
    pub fn encrypt(string: PlaintextString, ck: &ClientKey) -> Self {
        let bytes = string
            .bytes()
            .map(|b| ck.key.encrypt_radix(b, NUM_BLOCKS))
            .collect();
        Self {
            bytes,
            padded: false,
        }
    }

    pub fn decrypt(&self, ck: &ClientKey) -> PlaintextString {
        let bytes = self.bytes.iter().map(|b| ck.key.decrypt_radix(b)).collect();
        PlaintextString::new(String::from_utf8(bytes).unwrap())
    }

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
