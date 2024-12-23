use serde::{Deserialize, Serialize};
use tfhe::{
    integer::{ClientKey as TfheClientKey, RadixCiphertext},
    shortint::ShortintParameterSet,
};

use crate::fhe_string::{FheString, NUM_BLOCKS};

#[derive(Serialize, Deserialize, Clone)]
pub struct ClientKey {
    pub key: TfheClientKey,
}

/// Encrypted `u16` type. It contains an optional `max` to restrict the range of the value.
#[derive(Clone)]
pub struct FheU16 {
    pub(crate) cipher: RadixCiphertext,
    pub(crate) max: Option<u16>,
}

#[derive(Clone)]
pub enum U16Arg {
    Clear(u16),
    Enc(FheU16),
}

impl ClientKey {
    pub fn new<P>(parameters: P) -> Self
    where
        P: TryInto<ShortintParameterSet>,
        <P as TryInto<ShortintParameterSet>>::Error: std::fmt::Debug,
    {
        Self {
            key: TfheClientKey::new(parameters),
        }
    }

    pub fn enc_str(&self, data: &str, padding: u32) -> FheString {
        assert!(data.is_ascii() && !data.contains('\0'));
        let mut bytes: Vec<_> = data
            .bytes()
            .map(|b| self.key.encrypt_radix(b, NUM_BLOCKS))
            .collect();
        let nulls = (0..padding).map(|_| self.key.encrypt_radix(0u8, NUM_BLOCKS));
        bytes.extend(nulls);
        FheString {
            bytes,
            padded: padding > 0,
        }
    }

    /// Decrypts a `FheString`, removes any padding and returns the ASCII string.
    ///
    /// # Panics
    ///
    /// This function will panic if the decrypted string is not ASCII or the `FheString` padding
    /// flag doesn't match the actual string.
    pub fn dec_str(&self, ct: &FheString) -> String {
        let padded = ct.padded;
        let mut notnull = true;
        let bytes = ct
            .bytes
            .iter()
            .filter_map(|enc_char| {
                let b = self.key.decrypt_radix(enc_char);
                if b == 0 {
                    notnull = false;
                    assert!(padded, "Unexpected null byte in non-padded string");
                    None
                } else {
                    assert!(notnull, "Unexpected non-null byte after null byte");
                    Some(b)
                }
            })
            .collect();
        if padded {
            assert!(!notnull, "Padded string must end with null byte");
        }
        String::from_utf8(bytes).unwrap()
    }

    /// Encrypts a u16 value. It also takes an optional `max` value to restrict the range
    /// of the encrypted u16.
    ///
    /// # Panics
    ///
    /// This function will panic if the u16 value exceeds the provided `max`.
    pub fn encrypt_u16(&self, val: u16, max: Option<u16>) -> FheU16 {
        if let Some(max_val) = max {
            assert!(val <= max_val, "val cannot be greater than max")
        }

        FheU16 {
            cipher: self.key.encrypt_radix(
                val,
                16 / ((((self.key.parameters().message_modulus().0) as f64).log2()) as usize),
            ),
            max,
        }
    }
}

impl AsRef<TfheClientKey> for ClientKey {
    fn as_ref(&self) -> &TfheClientKey {
        &self.key
    }
}
