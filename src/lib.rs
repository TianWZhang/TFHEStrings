use client_key::ClientKey;
use server_key::ServerKey;
use tfhe::shortint::ShortintParameterSet;

mod fhe_string;
mod client_key;
mod server_key;

pub fn generate_keys(parameters: ShortintParameterSet) -> (ClientKey, ServerKey) {
    let client_key = ClientKey::new(parameters);
    let server_key = ServerKey::new(&client_key);
    (client_key, server_key)
}