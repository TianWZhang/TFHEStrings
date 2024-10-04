use std::ops::Deref;

use tfhe::integer::RadixCiphertext;

use crate::client_key::ClientKey;

const N: usize = 4;

#[derive(Clone)]
pub struct FheString {
    pub(crate) bytes: Vec<RadixCiphertext>,
    pub(crate) padded: bool,
}

impl FheString {
    pub fn encrypt(string: PlaintextString, ck: &ClientKey) -> Self {
        let bytes = string.bytes().map(|b| ck.key.encrypt_radix(b, 4)).collect();
        Self {
            bytes,
            padded: false,
        }
    }

    pub fn decrypt(&self, ck: &ClientKey) -> PlaintextString {
        let bytes = self.bytes.iter().map(|b| ck.key.decrypt_radix(b)).collect();
        PlaintextString::new(String::from_utf8(bytes).unwrap())
    }
}

pub struct PlaintextString {
    data: String,
}

impl PlaintextString {
    pub fn new(data: String) -> Self {
        assert!(
            data.is_ascii(),
            "The input string must only contain ascii letters"
        );
        assert!(data.contains('\0'));
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
