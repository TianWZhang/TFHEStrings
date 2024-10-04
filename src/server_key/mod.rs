use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use tfhe::integer::ServerKey as TfheServerKey;

use crate::{client_key::ClientKey, fhe_string::FheString};

const UP_LOWER_DIST: u8 = 32;

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct ServerKey {
    key: TfheServerKey,
}

impl ServerKey {
    pub fn new(key: &ClientKey) -> Self {
        Self {
            key: TfheServerKey::new_radix_server_key(key),
        }
    }

    pub fn to_lowercase(&self, str: &FheString) -> FheString {
        let res = str
            .bytes
            .par_iter()
            .map(|c| {
                let gt_64 = self.key.scalar_gt_parallelized(c, 64u8);
                let lt_91 = self.key.scalar_lt_parallelized(c, 91u8);
                let is_uppercase = self
                    .key
                    .boolean_bitand(&gt_64, &lt_91)
                    .into_radix(1, &self.key);
                let up_lower_dist = self
                    .key
                    .scalar_mul_parallelized(&is_uppercase, UP_LOWER_DIST);
                self.key.add_parallelized(c, &up_lower_dist)
            })
            .collect();
        FheString {
            bytes: res,
            padded: str.padded,
        }
    }

    pub fn to_uppercase(&self, str: &FheString) -> FheString {
        let res = str
            .bytes
            .par_iter()
            .map(|c| {
                let gt_96 = self.key.scalar_gt_parallelized(c, 96u8);
                let lt_123 = self.key.scalar_lt_parallelized(c, 123u8);
                let is_lowercase = self
                    .key
                    .boolean_bitand(&gt_96, &lt_123)
                    .into_radix(1, &self.key);
                let up_lower_dist = self
                    .key
                    .scalar_mul_parallelized(&is_lowercase, UP_LOWER_DIST);
                self.key.sub_parallelized(c, &up_lower_dist)
            })
            .collect();
        FheString {
            bytes: res,
            padded: str.padded,
        }
    }
}

impl AsRef<TfheServerKey> for ServerKey {
    fn as_ref(&self) -> &TfheServerKey {
        &self.key
    }
}
