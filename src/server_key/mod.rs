use std::cmp::Ordering;

use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use tfhe::integer::{
    bigint::StaticUnsignedBigInt, BooleanBlock, IntegerCiphertext, RadixCiphertext,
    ServerKey as TfheServerKey,
};

use crate::{
    client_key::ClientKey,
    fhe_string::{FheString, GenericPattern, PlaintextString, N, NUM_BLOCKS},
};

pub mod contains;
pub mod find;
pub mod strip;

const UP_LOWER_DIST: u8 = 32;

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct ServerKey {
    pub key: TfheServerKey,
}

impl ServerKey {
    pub fn new(key: &ClientKey) -> Self {
        Self {
            key: TfheServerKey::new_radix_server_key(key),
        }
    }

    fn trim_ciphertexts_lsb(&self, lhs: &mut RadixCiphertext, rhs: &mut RadixCiphertext) {
        let lhs_blocks = lhs.blocks_mut().len();
        let rhs_blocks = rhs.blocks_mut().len();

        match lhs_blocks.cmp(&rhs_blocks) {
            Ordering::Less => {
                let diff = rhs_blocks - lhs_blocks;
                self.key.trim_radix_blocks_lsb_assign(rhs, diff);
            }
            Ordering::Greater => {
                let diff = lhs_blocks - rhs_blocks;
                self.key.trim_radix_blocks_lsb_assign(lhs, diff);
            }
            _ => (),
        }
    }

    /// lhs.blocks().len() >= N * 8 * NUM_BLOCKS
    fn pad_cipher_and_plaintext_lsb(
        &self,
        lhs: &mut RadixCiphertext,
        rhs: &str,
    ) -> StaticUnsignedBigInt<N> {
        let mut rhs_bytes = rhs.as_bytes().to_vec();
        // Resize rhs with nulls at the end such that it matches the N const u64 length
        rhs_bytes.resize(N * 8, 0);
        let mut rhs_plaintext = StaticUnsignedBigInt::<N>::from(0u8);
        rhs_plaintext.copy_from_be_byte_slice(&rhs_bytes);

        // Fill the lhs with null blocks at the end
        // Each u8 (char) is represented by `NUM_BLOCKS` blocks
        if lhs.blocks().len() < N * 8 * NUM_BLOCKS {
            let diff = N * 8 * NUM_BLOCKS - lhs.blocks().len();
            self.key
                .extend_radix_with_trivial_zero_blocks_lsb_assign(lhs, diff);
        }
        rhs_plaintext
    }

    fn fhestrings_eq(&self, lhs: &[RadixCiphertext], rhs: &[RadixCiphertext]) -> BooleanBlock {
        let blocks_lhs = lhs
            .into_iter()
            .rev()
            .flat_map(|c| c.blocks().to_owned())
            .collect();
        let blocks_rhs = rhs
            .into_iter()
            .rev()
            .flat_map(|c| c.blocks().to_owned())
            .collect();
        let mut lhs = RadixCiphertext::from_blocks(blocks_lhs);
        let mut rhs = RadixCiphertext::from_blocks(blocks_rhs);
        self.trim_ciphertexts_lsb(&mut lhs, &mut rhs);
        self.key.eq_parallelized(&lhs, &rhs)
    }

    fn fhestring_eq_string(&self, lhs: &[RadixCiphertext], rhs: &str) -> BooleanBlock {
        let blocks_lhs: Vec<_> = lhs
            .into_iter()
            .rev()
            .flat_map(|c| c.blocks().to_owned())
            .collect();
        let blocks_lhs_len = blocks_lhs.len();
        let mut lhs = RadixCiphertext::from_blocks(blocks_lhs);

        let mut rhs = rhs;
        if blocks_lhs_len < rhs.len() * NUM_BLOCKS {
            rhs = &rhs[..blocks_lhs_len / NUM_BLOCKS];
        } else if blocks_lhs_len > rhs.len() * NUM_BLOCKS {
            let diff = blocks_lhs_len - rhs.len() * NUM_BLOCKS;
            self.key.trim_radix_blocks_lsb_assign(&mut lhs, diff);
        }
        let rhs_uint = self.pad_cipher_and_plaintext_lsb(&mut lhs, rhs);

        self.key.scalar_eq_parallelized(&lhs, rhs_uint)
    }

    pub fn eq(&self, lhs: &FheString, rhs: &GenericPattern) -> BooleanBlock {
        match rhs {
            GenericPattern::Enc(pat) => self.fhestrings_eq(&lhs.bytes, &pat.bytes),
            GenericPattern::Clear(pat) => self.fhestring_eq_string(&lhs.bytes, &pat.data),
        }
    }

    pub fn ne(&self, lhs: &FheString, rhs: &GenericPattern) -> BooleanBlock {
        let eq = self.eq(lhs, rhs);
        self.key.boolean_bitnot(&eq)
    }

    pub fn to_lowercase(&self, str: &FheString) -> FheString {
        let res = str
            .bytes
            .par_iter()
            .map(|c| {
                let gt_64 = self.key.scalar_gt_parallelized(c, 64u8);
                let lt_91 = self.key.scalar_lt_parallelized(c, 91u8);
                let up_lower_dist = self.key.create_trivial_radix(UP_LOWER_DIST, NUM_BLOCKS);
                let is_uppercase = self
                    .key
                    .boolean_bitand(&gt_64, &lt_91)
                    .into_radix(1, &self.key);
                let up_lower_dist = self.key.mul_parallelized(&is_uppercase, &up_lower_dist);
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
                let up_lower_dist = self.key.create_trivial_radix(UP_LOWER_DIST, NUM_BLOCKS);
                let is_lowercase = self
                    .key
                    .boolean_bitand(&gt_96, &lt_123)
                    .into_radix(1, &self.key);
                let up_lower_dist = self.key.mul_parallelized(&is_lowercase, &up_lower_dist);
                self.key.sub_parallelized(c, &up_lower_dist)
            })
            .collect();
        FheString {
            bytes: res,
            padded: str.padded,
        }
    }

    /// Returns `true` if an encrypted string and a pattern (either encrypted or clear) are equal,
    /// ignoring case differences.
    ///
    /// Returns `false` if they are not equal.
    ///
    /// The pattern for comparison (`rhs`) can be specified as either `GenericPattern::Clear` for a
    /// clear string or `GenericPattern::Enc` for an encrypted string.
    pub fn eq_ignore_case(&self, lhs: &FheString, rhs: &GenericPattern) -> BooleanBlock {
        let (lhs, rhs) = rayon::join(
            || self.to_lowercase(lhs), 
            || match rhs {
                GenericPattern::Enc(rhs) => GenericPattern::Enc(self.to_lowercase(rhs)),
                GenericPattern::Clear(rhs) => GenericPattern::Clear(PlaintextString::new(rhs.data.to_lowercase())),
            },
        );
        self.eq(&lhs, &rhs)
    }

    pub fn len(&self, str: &FheString) -> usize {
        str.bytes.len()
    }

    pub fn is_empty(&self, str: &FheString) -> bool {
        str.bytes.is_empty()
    }
}

impl AsRef<TfheServerKey> for ServerKey {
    fn as_ref(&self) -> &TfheServerKey {
        &self.key
    }
}

#[cfg(test)]
mod tests {
    use tfhe::shortint::prelude::PARAM_MESSAGE_2_CARRY_2;

    use crate::{
        fhe_string::{FheString, PlaintextString},
        generate_keys,
    };

    #[test]
    fn test_to_lowercase() {
        let s = "AF";
        let (ck, sk) = generate_keys(PARAM_MESSAGE_2_CARRY_2.into());
        let fhe_s = FheString::encrypt(PlaintextString::new(s.to_string()), &ck);
        let fhe_s_tolowercase = sk.to_lowercase(&fhe_s);
        let s_tolowercase = fhe_s_tolowercase.decrypt(&ck);
        assert_eq!(s_tolowercase, s.to_lowercase());
    }

    #[test]
    fn test_to_uppercase() {
        let s = "AaBcdE";
        let (ck, sk) = generate_keys(PARAM_MESSAGE_2_CARRY_2.into());
        let fhe_s = FheString::encrypt(PlaintextString::new(s.to_string()), &ck);
        let fhe_s_touppercase = sk.to_uppercase(&fhe_s);
        let s_touppercase = fhe_s_touppercase.decrypt(&ck);
        assert_eq!(s_touppercase, s.to_uppercase());
    }
}
