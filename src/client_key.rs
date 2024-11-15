use serde::{Deserialize, Serialize};
use tfhe::{
    integer::{ClientKey as TfheClientKey, RadixCiphertext},
    shortint::ShortintParameterSet,
};

#[derive(Serialize, Deserialize, Clone)]
pub struct ClientKey {
    pub key: TfheClientKey,
}

/// Encrypted `u16` type. It contains an optional `max` to restrict the range of the value.
pub struct FheU16 {
    pub(crate) cipher: RadixCiphertext,
    pub(crate) max: Option<u16>,
}

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
