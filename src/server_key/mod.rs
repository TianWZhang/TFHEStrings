use std::{cmp::Ordering, ops::Range, u16};

use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use tfhe::integer::{
    bigint::StaticUnsignedBigInt, prelude::ServerKeyDefaultCMux, BooleanBlock, IntegerCiphertext,
    RadixCiphertext, ServerKey as TfheServerKey,
};

use crate::{
    client_key::{ClientKey, U16Arg},
    fhe_string::{FheString, GenericPattern, PlaintextString, N, NUM_BLOCKS},
};

pub mod comp;
pub mod contains;
pub mod find;
pub mod replace;
pub mod split;
pub mod strip;
pub mod trim;

const UP_LOWER_DIST: u8 = 32;

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct ServerKey {
    pub key: TfheServerKey,
}

pub enum FheStringLen {
    NoPadding(usize),
    Padding(RadixCiphertext),
}

pub enum FheStringIsEmpty {
    NoPadding(bool),
    Padding(BooleanBlock),
}

enum IsMatch {
    Clear(bool),
    Cipher(BooleanBlock),
    None,
}

impl ServerKey {
    pub fn new(key: &ClientKey) -> Self {
        Self {
            key: TfheServerKey::new_radix_server_key(key),
        }
    }

    // fn trim_ciphertexts_lsb(&self, lhs: &mut RadixCiphertext, rhs: &mut RadixCiphertext) {
    //     let lhs_blocks = lhs.blocks_mut().len();
    //     let rhs_blocks = rhs.blocks_mut().len();

    //     match lhs_blocks.cmp(&rhs_blocks) {
    //         Ordering::Less => {
    //             let diff = rhs_blocks - lhs_blocks;
    //             self.key.trim_radix_blocks_lsb_assign(rhs, diff);
    //         }
    //         Ordering::Greater => {
    //             let diff = lhs_blocks - rhs_blocks;
    //             self.key.trim_radix_blocks_lsb_assign(lhs, diff);
    //         }
    //         _ => (),
    //     }
    // }

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
        // N * 8 * NUM_BLOCKS is the maximum block length
        if lhs.blocks().len() < N * 8 * NUM_BLOCKS {
            let diff = N * 8 * NUM_BLOCKS - lhs.blocks().len();
            self.key
                .extend_radix_with_trivial_zero_blocks_lsb_assign(lhs, diff);
        }
        rhs_plaintext
    }

    fn pad_or_trim_ciphertext(&self, cipher: &mut RadixCiphertext, len: usize) {
        let cipher_len = cipher.blocks().len();

        match cipher_len.cmp(&len) {
            Ordering::Less => {
                let diff = len - cipher_len;
                self.key
                    .extend_radix_with_trivial_zero_blocks_msb_assign(cipher, diff);
            }
            Ordering::Greater => {
                let diff = cipher_len - len;
                self.key.trim_radix_blocks_msb_assign(cipher, diff);
            }
            _ => (),
        }
    }

    fn is_matched_early_checks(&self, str: &FheString, pattern: &FheString) -> IsMatch {
        let str_len = str.bytes.len();
        let pat_len = pattern.bytes.len();

        // If the pattern is empty, it will match any str.
        // Note that this doesn't handle the case where pattern is empty and has > 1 padding zeros.
        if pat_len == 0 || (pattern.padded && pat_len == 1) {
            return IsMatch::Clear(true);
        }

        if str_len == 0 || (str.padded && str_len == 1) {
            return match self.is_empty(pattern) {
                FheStringIsEmpty::Padding(enc_val) => IsMatch::Cipher(enc_val),
                _ => IsMatch::Clear(false),
            };
        }

        if !pattern.padded {
            // A pattern without padding cannot be contained in a shorter string without padding.
            if !str.padded && (str_len < pat_len) {
                return IsMatch::Clear(false);
            }

            // A pattern without padding cannot be contained in a string with padding that is shorter or of the same length.
            if str.padded && (str_len <= pat_len) {
                return IsMatch::Clear(false);
            }
        }
        IsMatch::None
    }

    /// The returned `Range<usize>` is the range of the `str` where the pattern can be found.
    fn contains_cases(
        &self,
        str: &FheString,
        pattern: &FheString,
    ) -> (FheString, FheString, Range<usize>) {
        let str_len = str.bytes.len();
        let pat_len = pattern.bytes.len();

        match (str.padded, pattern.padded) {
            (_, false) => {
                let diff = str_len - pat_len - if str.padded { 1 } else { 0 };
                (str.clone(), pattern.clone(), 0..diff + 1)
            }
            // str: abc0
            // pattern: abcd00
            (true, true) => {
                let pattern = FheString {
                    bytes: pattern.bytes[0..pat_len - 1].to_vec(),
                    padded: true, // now pattern is not necessarily padded
                };
                (str.clone(), pattern, 0..str_len - 1)
            }
            // str: abc
            // pattern: abcd00
            (false, true) => {
                let pattern = FheString {
                    bytes: pattern.bytes[0..pat_len - 1].to_vec(),
                    padded: true,
                };
                let mut str = str.clone();
                // Append a null at the end of str.bytes. Next we will call `starts_with_ignore_pat_pad`, where
                // the additional null (null denotes the end of `str`) will be used to check if `pattern` ends
                // earlier than `str`.
                str.bytes
                    .push(self.key.create_trivial_zero_radix(NUM_BLOCKS));
                str.padded = true;
                (str, pattern, 0..str_len)
            }
        }
    }

    fn starts_with_ignore_pattern_padding<'a>(
        &self,
        str_pat: impl ParallelIterator<Item = (&'a RadixCiphertext, &'a RadixCiphertext)>,
    ) -> BooleanBlock {
        let mut res = self.key.create_trivial_boolean_block(true);
        let eq_or_null_pattern: Vec<_> = str_pat
            .map(|(str_char, pat_char)| {
                let (is_eq, pattern_is_null) = rayon::join(
                    || self.key.eq_parallelized(str_char, pat_char),
                    || self.key.scalar_eq_parallelized(pat_char, 0u8),
                );
                self.key.boolean_bitor(&is_eq, &pattern_is_null)
            })
            .collect();
        for c in &eq_or_null_pattern {
            self.key.boolean_bitand_assign(&mut res, c);
        }
        res
    }

    fn clear_ends_with_cases(&self, str: &FheString, pattern: &str) -> (FheString, PlaintextString, Range<usize>) {
        let str_len = str.bytes.len();
        let pat_len = pattern.len();

        if str.padded {
            let diff = str_len - pat_len - 1;
            let str = FheString {
                bytes: str.bytes[0..str_len - 1].to_vec(),
                padded: true,
            };
            let mut pattern  = pattern.to_owned();
            pattern.push('\0');
            (str, PlaintextString {data: pattern}, 0..diff + 1)
        } else {
            let diff = str_len - pat_len;
            (str.clone(), PlaintextString {data: pattern.to_owned()}, diff..diff + 1)
        }
    }

    fn ends_with_cases(&self, str: &FheString, pattern: &FheString) -> (FheString, FheString, Range<usize>) {
        let str_len = str.bytes.len();
        let pat_len = pattern.bytes.len();

        match (str.padded, pattern.padded) {
            (true, true) => {
                (str.clone(), pattern.clone(), 0..str_len)
            }

            (true, false) => {
                let diff = str_len - pat_len - 1;
                let str = FheString {
                    bytes: str.bytes[0..str_len - 1].to_vec(),
                    padded: true,
                };
                let mut pattern = pattern.clone();
                pattern.bytes.push(self.key.create_trivial_zero_radix(NUM_BLOCKS));
                pattern.padded = true;
                (str, pattern, 0..diff + 1)
            }

            // str = "abc", pattern = "abcd\0", we have to pad str with a null at the end
            // to check if "abc\0" == pattern[..4]
            (false, true) => {
                let mut str = str.clone();
                    str.bytes.push(self.key.create_trivial_zero_radix(NUM_BLOCKS));
                    str.padded = true;
                if pat_len - 1 > str_len {
                    (str, pattern.clone(), 0..str_len + 1)
                } else {
                    let pattern = FheString {
                        bytes: pattern.bytes[0..pat_len - 1].to_vec(),
                        padded: true,
                    };
                    let diff = str_len - 1 - pat_len;
                    (str, pattern, diff..diff + pat_len)
                }
            }

            // If neither str nor pattern are padded, we can directly compare 
            // the last `pat_len` characters of `str` with `pattern`.
            (false, false) => {
                let diff = str_len - pat_len;
                (str.clone(), pattern.clone(), diff..diff + 1)
            }
        }
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

    fn left_shift_chars(&self, str: &FheString, shift: &RadixCiphertext) -> FheString {
        let uint = str.to_uint(self);
        let mut shift_bits = self.key.scalar_left_shift_parallelized(shift, 3);
        // `shift_bits` needs to have the same number of blocks as `uint` for tfhe.rs shift operations
        // necessary?
        self.pad_or_trim_ciphertext(&mut shift_bits, uint.blocks().len());

        let shifted_uint = self.key.left_shift_parallelized(&uint, &shift_bits);

        // If the shifting amount is >= the length of str, the result is 0, instead of wrapping
        // as in Rust and thfe.rs.
        let shift_ge_str_len = self
            .key
            .scalar_ge_parallelized(shift, str.bytes.len() as u32);
        FheString::from_uint(self.key.if_then_else_parallelized(
            &shift_ge_str_len,
            &self.key.create_trivial_zero_radix(uint.blocks().len()),
            &shifted_uint,
        ))
    }

    fn right_shift_chars(&self, str: &FheString, shift: &RadixCiphertext) -> FheString {
        let uint = str.to_uint(self);
        let mut shift_bits = self.key.scalar_left_shift_parallelized(shift, 3);
        // `shift_bits` needs to have the same number of blocks as `uint` for tfhe.rs shift operations
        self.pad_or_trim_ciphertext(&mut shift_bits, uint.blocks().len());

        let shifted_uint = self.key.right_shift_parallelized(&uint, &shift_bits);

        // If the shifting amount is >= the length of str, the result is 0, instead of wrapping
        // as in Rust and thfe.rs.
        let shift_ge_str_len = self
            .key
            .scalar_ge_parallelized(shift, str.bytes.len() as u32);
        FheString::from_uint(self.key.if_then_else_parallelized(
            &shift_ge_str_len,
            &self.key.create_trivial_zero_radix(uint.blocks().len()),
            &shifted_uint,
        ))
    }

    /// Returns a new encrypted string with all characters converted to lowercase.
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

    /// Returns a new encrypted string with all characters converted to uppercase.
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

    pub fn len(&self, str: &FheString) -> FheStringLen {
        let num_blocks = 32 / ((((self.key.message_modulus().0) as f64).log2()) as usize);
        if str.padded {
            let mut res = self.key.create_trivial_zero_radix(NUM_BLOCKS);
            for c in &str.bytes {
                let non_zero = self.key.scalar_ne_parallelized(c, 0u8);
                self.key
                    .add_assign_parallelized(&mut res, &non_zero.into_radix(num_blocks, &self.key));
            }
            FheStringLen::Padding(res)
        } else {
            FheStringLen::NoPadding(str.bytes.len())
        }
    }

    /// Returns whether an encrypted string is empty or not.
    pub fn is_empty(&self, str: &FheString) -> FheStringIsEmpty {
        if str.padded {
            if str.bytes.len() == 1 {
                return FheStringIsEmpty::Padding(self.key.create_trivial_boolean_block(true));
            }
            let uint = str.to_uint(self);
            let res = self.key.scalar_eq_parallelized(&uint, 0u8);
            FheStringIsEmpty::Padding(res)
        } else {
            FheStringIsEmpty::NoPadding(str.bytes.is_empty())
        }
    }

    /// Concatenates two encrypted strings and returns the result as a new encrypted string.
    ///
    /// This function is equivalent to using the `+` operator on standard strings.
    pub fn concat(&self, lhs: &FheString, rhs: &FheString) -> FheString {
        let mut res = lhs.clone();
        let num_blocks = 32 / ((((self.key.message_modulus().0) as f64).log2()) as usize);
        match self.len(lhs) {
            FheStringLen::NoPadding(_) => {
                res.bytes.extend_from_slice(&rhs.bytes);
                res.padded = rhs.padded;
            }
            // If lhs is padded we can shift it right such that all nulls move to the start, then
            // we append the rhs and shift it left again to move the nulls to the new end
            FheStringLen::Padding(len) => {
                let padded_len = self
                    .key
                    .create_trivial_radix(lhs.bytes.len() as u32, num_blocks);
                let nulls = self.key.sub_parallelized(&padded_len, &len);
                res = self.right_shift_chars(&res, &nulls);
                res.bytes.extend_from_slice(&rhs.bytes);
                res = self.left_shift_chars(&res, &nulls);
                res.padded = true;
            }
        }
        res
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
        if str_len == 0 || (str_len == 1 && str.padded) {
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
                // If str was not padded and n == max we don't get nulls at the end. However if
                // n < max we do, and as these conditions are unknown we have to ensure result is
                // actually padded
                if !str.padded {
                    res.append_null(self);
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

pub trait FheStringIterator {
    fn next(&mut self, sk: &ServerKey) -> (FheString, BooleanBlock);
}

#[cfg(test)]
mod tests {
    use tfhe::shortint::prelude::PARAM_MESSAGE_2_CARRY_2;

    use crate::{
        client_key::U16Arg,
        fhe_string::{GenericPattern, NUM_BLOCKS},
        generate_keys,
    };

    #[test]
    fn test_left_shift_chars() {
        let s = "aff";
        let (ck, sk) = generate_keys(PARAM_MESSAGE_2_CARRY_2);
        let fhe_s = ck.enc_str(s, 0);
        let shift = sk.key.create_trivial_radix(4, NUM_BLOCKS);
        let fhe_left_shift = sk.left_shift_chars(&fhe_s, &shift);
        let s_left_shift = ck.dec_str(&fhe_left_shift);
        assert_eq!(s_left_shift, "");
    }

    #[test]
    fn test_to_lowercase() {
        let s = "AF";
        let (ck, sk) = generate_keys(PARAM_MESSAGE_2_CARRY_2);
        let fhe_s = ck.enc_str(s, 0);
        let fhe_s_tolowercase = sk.to_lowercase(&fhe_s);
        let s_tolowercase = ck.dec_str(&fhe_s_tolowercase);
        assert_eq!(s_tolowercase, s.to_lowercase());
    }

    #[test]
    fn test_to_uppercase() {
        let s = "AaBcdE";
        let (ck, sk) = generate_keys(PARAM_MESSAGE_2_CARRY_2);
        let fhe_s = ck.enc_str(s, 0);
        let fhe_s_touppercase = sk.to_uppercase(&fhe_s);
        let s_touppercase = ck.dec_str(&fhe_s_touppercase);
        assert_eq!(s_touppercase, s.to_uppercase());
    }

    #[test]
    fn test_to_eq_ignore_case() {
        let s1 = "Hello";
        let s2 = "hello";
        let (ck, sk) = generate_keys(PARAM_MESSAGE_2_CARRY_2);
        let fhe_s1 = ck.enc_str(s1, 0);
        let fhe_s2 = GenericPattern::Enc(ck.enc_str(s2, 0));
        let fhe_res = sk.eq_ignore_case(&fhe_s1, &fhe_s2);
        let res = ck.key.decrypt_bool(&fhe_res);
        assert_eq!(res, s1.eq_ignore_ascii_case(s2));
    }

    #[test]
    fn test_concat() {
        let (s1, s2) = ("Hello, ", "world!");
        let (ck, sk) = generate_keys(PARAM_MESSAGE_2_CARRY_2);
        let fhe_s1 = ck.enc_str(s1, 0);
        let fhe_s2 = ck.enc_str(s2, 0);
        let fhe_res = sk.concat(&fhe_s1, &fhe_s2);
        let res = ck.dec_str(&fhe_res);
        assert_eq!(res, s1.to_owned() + s2);
    }

    #[test]
    fn test_repeat() {
        let s = "hi";
        let (ck, sk) = generate_keys(PARAM_MESSAGE_2_CARRY_2);
        let fhe_s = ck.enc_str(s, 0);
        // Using Clear count
        let clear_count = U16Arg::Clear(3);
        let res_clear = sk.repeat(&fhe_s, &clear_count);
        let res = ck.dec_str(&res_clear);
        assert_eq!(res.as_str(), "hihihi");

        // Using Encrypted count
        let max = 3; // Restricts the range of enc_n to 0..=max
        let enc_n = U16Arg::Enc(ck.encrypt_u16(3, Some(max)));
        let res_enc = sk.repeat(&fhe_s, &enc_n);
        let res = ck.dec_str(&res_enc);
        assert_eq!(res, "hihihi");
    }
}
