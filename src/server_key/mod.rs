use std::{cmp::Ordering, u16};

use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use tfhe::integer::{
    bigint::StaticUnsignedBigInt, prelude::ServerKeyDefaultCMux, BooleanBlock, IntegerCiphertext,
    RadixCiphertext, ServerKey as TfheServerKey,
};

use crate::{
    client_key::{ClientKey, U16Arg},
    fhe_string::{FheString, GenericPattern, PlaintextString, N, NUM_BLOCKS},
};

pub mod contains;
pub mod find;
pub mod strip;
pub mod trim;

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

    fn pad_ciphertexts_lsb(&self, lhs: &mut RadixCiphertext, rhs: &mut RadixCiphertext) {
        let lhs_blocks = lhs.blocks().len();
        let rhs_blocks = rhs.blocks().len();

        match lhs_blocks.cmp(&rhs_blocks) {
            Ordering::Less => {
                let diff = rhs_blocks - lhs_blocks;
                self.key
                    .extend_radix_with_trivial_zero_blocks_lsb_assign(lhs, diff);
            }
            Ordering::Greater => {
                let diff = lhs_blocks - rhs_blocks;
                self.key
                    .extend_radix_with_trivial_zero_blocks_lsb_assign(rhs, diff);
            }
            _ => (),
        }
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

    fn conditional_fhestring(
        &self,
        condition: &BooleanBlock,
        true_ct: &FheString,
        false_ct: &FheString,
    ) -> FheString {
        let mut true_ct_uint = true_ct.to_uint(self);
        let mut false_ct_uint = false_ct.to_uint(self);
        self.pad_ciphertexts_lsb(&mut true_ct_uint, &mut false_ct_uint);
        let res_uint = self
            .key
            .if_then_else_parallelized(condition, &true_ct_uint, &false_ct_uint);
        FheString::from_uint(res_uint)
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

    /// Returns `true` if the first encrypted string is less than the second encrypted string.
    ///
    /// Returns `false` otherwise.
    pub fn lt(&self, lhs: &FheString, rhs: &FheString) -> BooleanBlock {
        let mut lhs_uint = lhs.to_uint(self);
        let mut rhs_uint = rhs.to_uint(self);
        self.pad_ciphertexts_lsb(&mut lhs_uint, &mut rhs_uint);
        self.key.lt_parallelized(&lhs_uint, &rhs_uint)
    }

    /// Returns `true` if the first encrypted string is greater than the second encrypted string.
    ///
    /// Returns `false` otherwise.
    pub fn gt(&self, lhs: &FheString, rhs: &FheString) -> BooleanBlock {
        let mut lhs_uint = lhs.to_uint(self);
        let mut rhs_uint = rhs.to_uint(self);
        self.pad_ciphertexts_lsb(&mut lhs_uint, &mut rhs_uint);
        self.key.gt_parallelized(&lhs_uint, &rhs_uint)
    }

    /// Returns `true` if the first encrypted string is less than or equal to the second encrypted string.
    ///
    /// Returns `false` otherwise.
    pub fn le(&self, lhs: &FheString, rhs: &FheString) -> BooleanBlock {
        let mut lhs_uint = lhs.to_uint(self);
        let mut rhs_uint = rhs.to_uint(self);
        self.pad_ciphertexts_lsb(&mut lhs_uint, &mut rhs_uint);
        self.key.le_parallelized(&lhs_uint, &rhs_uint)
    }

    /// Returns `true` if the first encrypted string is greater than or equal to the second encrypted string.
    ///
    /// Returns `false` otherwise.
    pub fn ge(&self, lhs: &FheString, rhs: &FheString) -> BooleanBlock {
        let mut lhs_uint = lhs.to_uint(self);
        let mut rhs_uint = rhs.to_uint(self);
        self.pad_ciphertexts_lsb(&mut lhs_uint, &mut rhs_uint);
        self.key.ge_parallelized(&lhs_uint, &rhs_uint)
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
                GenericPattern::Clear(rhs) => {
                    GenericPattern::Clear(PlaintextString::new(rhs.data.to_lowercase()))
                }
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

    /// Concatenates two encrypted strings and returns the result as a new encrypted string.
    ///
    /// This function is equivalent to using the `+` operator on standard strings.
    pub fn concat(&self, lhs: &FheString, rhs: &FheString) -> FheString {
        let mut res = lhs.bytes.clone();
        res.extend_from_slice(&rhs.bytes);
        FheString {
            bytes: res,
            padded: lhs.padded || rhs.padded,
        }
    }

    /// Returns a new encrypted string which is the original encrypted string repeated `n` times.
    ///
    /// The number of repetitions `n` is specified by a `UIntArg`, which can be either `Clear` or
    /// `Enc`.
    pub fn repeat(&self, str: &FheString, n: &U16Arg) -> FheString {
        if let U16Arg::Clear(0) = n {
            return FheString::empty();
        }

        let str_len = str.bytes.len();
        if str_len == 0 || (str.padded && str_len == 1) {
            return FheString::empty();
        }

        let mut res = str.clone();
        match n {
            U16Arg::Clear(n) => {
                for _ in 1..*n {
                    res = self.concat(&res, str);
                }
            }
            U16Arg::Enc(enc_n) => {
                let is_zero = self.key.scalar_eq_parallelized(&enc_n.cipher, 0u16);
                res = self.conditional_fhestring(&is_zero, &FheString::empty(), str);
                for i in 1..enc_n.max.unwrap_or(u16::MAX) {
                    let is_i_exceeded = self.key.scalar_le_parallelized(&enc_n.cipher, i);
                    let append =
                        self.conditional_fhestring(&is_i_exceeded, &FheString::empty(), str);
                    res = self.concat(&res, &append);
                }
            }
        }
        res
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
        client_key::U16Arg,
        fhe_string::{FheString, GenericPattern, PlaintextString},
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

    #[test]
    fn test_to_eq_ignore_case() {
        let s1 = "Hello";
        let s2 = "hello";
        let (ck, sk) = generate_keys(PARAM_MESSAGE_2_CARRY_2.into());
        let fhe_s1 = FheString::encrypt(PlaintextString::new(s1.to_string()), &ck);
        let fhe_s2 = GenericPattern::Enc(FheString::encrypt(
            PlaintextString::new(s2.to_string()),
            &ck,
        ));
        let fhe_res = sk.eq_ignore_case(&fhe_s1, &fhe_s2);
        let res = ck.key.decrypt_bool(&fhe_res);
        assert_eq!(res, s1.eq_ignore_ascii_case(s2));
    }

    #[test]
    fn test_lt() {
        let (s1, s2) = ("apple", "banana");
        let (ck, sk) = generate_keys(PARAM_MESSAGE_2_CARRY_2.into());
        let fhe_s1 = FheString::encrypt(PlaintextString::new(s1.to_string()), &ck);
        let fhe_s2 = FheString::encrypt(PlaintextString::new(s2.to_string()), &ck);
        let fhe_res = sk.lt(&fhe_s1, &fhe_s2);
        let res = ck.key.decrypt_bool(&fhe_res);
        assert_eq!(res, s1.lt(s2));
    }

    #[test]
    fn test_concat() {
        let (s1, s2) = ("Hello, ", "world!");
        let (ck, sk) = generate_keys(PARAM_MESSAGE_2_CARRY_2.into());
        let fhe_s1 = FheString::encrypt(PlaintextString::new(s1.to_string()), &ck);
        let fhe_s2 = FheString::encrypt(PlaintextString::new(s2.to_string()), &ck);
        let fhe_res = sk.concat(&fhe_s1, &fhe_s2);
        let res = fhe_res.decrypt(&ck);
        assert_eq!(res, s1.to_owned() + s2);
    }

    #[test]
    fn test_repeat() {
        let s = "hi";
        let (ck, sk) = generate_keys(PARAM_MESSAGE_2_CARRY_2.into());
        let fhe_s = FheString::encrypt(PlaintextString::new(s.to_string()), &ck);
        // Using Clear count
        let clear_count = U16Arg::Clear(3);
        let res_clear = sk.repeat(&fhe_s, &clear_count);
        let res = res_clear.decrypt(&ck);
        assert_eq!(res.as_str(), "hihihi");

        // Using Encrypted count
        let max = 3; // Restricts the range of enc_n to 0..=max
        let enc_n = U16Arg::Enc(ck.encrypt_u16(3, Some(max)));
        let res_enc = sk.repeat(&fhe_s, &enc_n);
        let res = res_enc.decrypt(&ck);
        assert_eq!(res, "hihihi");
    }
}
