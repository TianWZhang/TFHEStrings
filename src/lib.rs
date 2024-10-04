mod client_key;
mod fhe_string;
mod server_key;

use std::cell::RefCell;

use client_key::ClientKey;
use server_key::ServerKey;
use tfhe::shortint::ShortintParameterSet;

// We store the server keys as thread local, which means each thread has it own set of keys.
thread_local! {
    static SERVER_KEY: RefCell<Option<ServerKey>> = const { RefCell::new(None) };
}

pub fn set_server_key(server_key: ServerKey) {
    SERVER_KEY.with(|sk| sk.replace_with(|_old| Some(server_key)));
}

pub fn unset_server_key() {
    SERVER_KEY.with(|sk| {
        let _ = sk.replace_with(|_old| None);
    })
}

pub fn generate_keys(parameters: ShortintParameterSet) -> (ClientKey, ServerKey) {
    let client_key = ClientKey::new(parameters);
    let server_key = ServerKey::new(&client_key);
    (client_key, server_key)
}
