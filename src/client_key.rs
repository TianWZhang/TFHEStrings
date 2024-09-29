use std::ops::Deref;

use tfhe::{integer::ClientKey as TfheClientKey, shortint::ShortintParameterSet};

pub struct ClientKey {
    key: TfheClientKey
}

impl ClientKey {
    pub fn new<P>(parameters: P) -> Self
    where 
        P: TryInto<ShortintParameterSet>,
        <P as TryInto<ShortintParameterSet>>::Error: std::fmt::Debug,
    {
        Self {
            key: TfheClientKey::new(parameters)
        }
    }
}

impl AsRef<TfheClientKey> for ClientKey {
    fn as_ref(&self) -> &TfheClientKey {
        &self.key
    }
}