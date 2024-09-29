use tfhe::integer::ServerKey as TfheServerKey;

use crate::client_key::ClientKey;

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct ServerKey {
    key: TfheServerKey
}

impl ServerKey {
    pub fn new(key: &ClientKey) -> Self {
        Self {
            key: TfheServerKey::new_radix_server_key(key)
        }
    }
}

impl AsRef<TfheServerKey> for ServerKey {
    fn as_ref(&self) -> &TfheServerKey {
        &self.key
    }
}