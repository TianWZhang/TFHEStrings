use std::ops::Range;

use super::{FheStringIsEmpty, FheStringLen, IsMatch, ServerKey};
use crate::fhe_string::{FheString, GenericPattern, PlaintextString};
use rayon::iter::{IntoParallelIterator, ParallelBridge, ParallelIterator};
use tfhe::integer::{prelude::ServerKeyDefaultCMux, BooleanBlock, RadixCiphertext};

impl ServerKey {
    // Compare `pattern` with `str`, with `pattern` shifted in range [l..=r].
    // Returns the first character index of the last match, or the first character index
    // of the first match if the range is reversed. If there's no match defaults to 0
    fn compare_range_index(
        &self,
        str: &FheString,
        pattern: &FheString,
        range: Range<usize>,
        ignore_pattern_pad: bool
    ) -> (RadixCiphertext, BooleanBlock) {
        let mut is_found = self.key.create_trivial_boolean_block(false);
        // We consider the index as u32.
        let num_blocks = 32 / ((((self.key.message_modulus().0) as f64).log2()) as usize);
        let mut last_match_index = self.key.create_trivial_zero_radix(num_blocks);

        let matched: Vec<_> = range
            .into_par_iter()
            .map(|start| {
                let is_matched = if ignore_pattern_pad {
                    let str_pat = str.bytes.iter().skip(start).zip(pattern.bytes.iter()).par_bridge();
                    self.starts_with_ignore_pattern_padding(str_pat)
                } else {
                    let substr = FheString {
                        bytes: str.bytes[start..].to_vec(),
                        padded: str.padded,
                    };
                    self.fhestrings_eq(&substr, pattern)
                };
                (start, is_matched)
            })
            .collect();

        for (i, is_matched) in matched {
            let index = self.key.create_trivial_radix(i as u32, num_blocks);
            rayon::join(
                || {
                    last_match_index =
                        self.key
                            .if_then_else_parallelized(&is_matched, &index, &last_match_index);
                },
                || self.key.boolean_bitor_assign(&mut is_found, &is_matched),
            );
        }
        last_match_index = self.key.if_then_else_parallelized(
            &is_found,
            &last_match_index,
            &self
                .key
                .create_trivial_radix(str.bytes.len() as u32, num_blocks),
        );
        (last_match_index, is_found)
    }

    fn compare_range_index_plaintext(
        &self,
        str: &FheString,
        pattern: &PlaintextString,
        range: Range<usize>,
    ) -> (RadixCiphertext, BooleanBlock) {
        let mut res = self.key.create_trivial_boolean_block(false);
        let num_blocks = 32 / ((((self.key.message_modulus().0) as f64).log2()) as usize);
        let mut last_match_index = self.key.create_trivial_zero_radix(num_blocks);
        let matched: Vec<_> = range
            .into_par_iter()
            .map(|start| {
                let substr = FheString {
                    bytes: str.bytes[start..].to_vec(),
                    padded: str.padded,
                };
                let is_matched = self.fhestring_eq_string(&substr, pattern.data.as_str());
                (start, is_matched)
            })
            .collect();

        for (i, is_matched) in matched {
            let index = self.key.create_trivial_radix(i as u32, num_blocks);
            rayon::join(
                || {
                    last_match_index =
                        self.key
                            .if_then_else_parallelized(&is_matched, &index, &last_match_index);
                },
                || self.key.boolean_bitor_assign(&mut res, &is_matched),
            );
        }
        last_match_index = self.key.if_then_else_parallelized(
            &res,
            &last_match_index,
            &self
                .key
                .create_trivial_radix(str.bytes.len() as u32, num_blocks),
        );
        (last_match_index, res)
    }

    /// Returns a tuple containing the byte index of the first character of this encrypted string
    /// that matches the given pattern (either encrypted or clear), and a boolean indicating if a
    /// match was found.
    ///
    /// If the pattern doesn’t match, the function returns a tuple where the boolean part is
    /// `false`, indicating the equivalent of `None`.
    ///
    /// The pattern to search for can be specified as either `GenericPattern::Clear` for a clear
    /// string or `GenericPattern::Enc` for an encrypted string.
    pub fn rfind(
        &self,
        str: &FheString,
        pattern: &GenericPattern,
    ) -> (RadixCiphertext, BooleanBlock) {
        let num_blocks = 32 / ((((self.key.message_modulus().0) as f64).log2()) as usize);
        let trivial_or_enc_pat = match pattern {
            GenericPattern::Clear(pattern) => FheString::enc_trivial(&pattern.data, self),
            GenericPattern::Enc(pattern) => pattern.clone(),
        };
        match self.is_matched_early_checks(str, &trivial_or_enc_pat) {
            IsMatch::Clear(val) => {
                let index = if val {
                    match self.len(str) {
                        FheStringLen::Padding(cipher_len) => cipher_len,
                        FheStringLen::NoPadding(len) => self.key.create_trivial_radix(len as u32, num_blocks)
                    }
                } else {
                    self.key.create_trivial_zero_radix(num_blocks)
                };
                return (index, self.key.create_trivial_boolean_block(val));
            }
            IsMatch::Cipher(val) => return (self.key.create_trivial_zero_radix(num_blocks), val),
            _ => (),
        }
        
        let ignore_pattern_padding = trivial_or_enc_pat.padded;
        let (str_rfind, pat_rfind, range) = self.contains_cases(str, &trivial_or_enc_pat);
        

        let ((mut last_match_index, res), option) = rayon::join(
            || match pattern {
                GenericPattern::Enc(_) => {
                    self.compare_range_index(&str_rfind, &pat_rfind, range, ignore_pattern_padding)
                }
                GenericPattern::Clear(pat) => {
                    self.compare_range_index_plaintext(&str_rfind, pat, range)
                }
            },
            || {
                // We have to check if pat is empty as in that case the returned index is str.len()
                // (the actual length) which doesn't correspond to our `last_match_index`
                if let FheStringIsEmpty::Padding(is_empty) = self.is_empty(&trivial_or_enc_pat) {
                    if str.padded {
                        let str_true_len = match self.len(str) {
                            FheStringLen::Padding(cipher_len) => cipher_len,
                            FheStringLen::NoPadding(len) => {
                                self.key.create_trivial_radix(len as u32, 16)
                            }
                        };
                        Some((is_empty, str_true_len))
                    } else {
                        None
                    }
                } else {
                    None
                }
            },
        );

        if let Some((pat_is_empty, str_true_len)) = option {
            last_match_index =
                self.key
                    .if_then_else_parallelized(&pat_is_empty, &str_true_len, &last_match_index);
        }
        (last_match_index, res)
    }

    /// Returns a tuple containing the byte index of the first character from the end of this
    /// encrypted string that matches the given pattern (either encrypted or clear), and a
    /// boolean indicating if a match was found.
    ///
    /// If the pattern doesn’t match, the function returns a tuple where the boolean part is
    /// `false`, indicating the equivalent of `None`.
    ///
    /// The pattern to search for can be specified as either `GenericPattern::Clear` for a clear
    /// string or `GenericPattern::Enc` for an encrypted string.
    pub fn find(
        &self,
        str: &FheString,
        pattern: &GenericPattern,
    ) -> (RadixCiphertext, BooleanBlock) {
        let num_blocks = 32 / ((((self.key.message_modulus().0) as f64).log2()) as usize);
        let trivial_or_enc_pat = match pattern {
            GenericPattern::Clear(pattern) => FheString::enc_trivial(&pattern.data, self),
            GenericPattern::Enc(pattern) => pattern.clone(),
        };
        match self.is_matched_early_checks(str, &trivial_or_enc_pat) {
            IsMatch::Clear(val) => return (self.key.create_trivial_zero_radix(num_blocks), self.key.create_trivial_boolean_block(val)),
            IsMatch::Cipher(val) => return (self.key.create_trivial_zero_radix(num_blocks), val),
            _ => (),
        }
        
        let ignore_pattern_padding = trivial_or_enc_pat.padded;
        let (str_find, pat_find, range) = self.contains_cases(str, &trivial_or_enc_pat);
        match pattern {
            GenericPattern::Enc(pat) => {
                if str.bytes.len() < pat.bytes.len() {
                    return (
                        self.key
                            .create_trivial_radix(str.bytes.len() as u32, num_blocks),
                        self.key.create_trivial_boolean_block(false),
                    );
                }
                self.compare_range_index(&str_find, &pat_find, range, ignore_pattern_padding)
            }
            GenericPattern::Clear(pat) => {
                self.compare_range_index_plaintext(
                    &str_find,
                    pat,
                    range,
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use tfhe::shortint::prelude::PARAM_MESSAGE_2_CARRY_2;

    use crate::{fhe_string::GenericPattern, generate_keys};

    #[test]
    fn test_find() {
        let (ck, sk) = generate_keys(PARAM_MESSAGE_2_CARRY_2);

        let (haystack, needle) = ("ell", "e");
        let enc_haystack = ck.enc_str(&haystack, 0);
        let enc_needle = GenericPattern::Enc(ck.enc_str(&needle, 3));
        let (index, found) = sk.find(&enc_haystack, &enc_needle);
        let index = ck.key.decrypt_radix::<u32>(&index);
        let found = ck.key.decrypt_bool(&found);
        assert!(found);
        assert_eq!(index, 0);

        let (haystack, needle) = ("ell", "le");
        let enc_haystack = ck.enc_str(&haystack, 0);
        let enc_needle = GenericPattern::Enc(ck.enc_str(&needle, 1));
        let (index, found) = sk.find(&enc_haystack, &enc_needle);
        let index = ck.key.decrypt_radix::<u32>(&index);
        let found = ck.key.decrypt_bool(&found);
        assert!(!found);
        assert_eq!(index, 3);
    }

    #[test]
    fn test_rfind() {
        let (ck, sk) = generate_keys(PARAM_MESSAGE_2_CARRY_2);
        let (haystack, needle) = ("ell", "l");

        let enc_haystack = ck.enc_str(&haystack, 0);
        let enc_needle = GenericPattern::Enc(ck.enc_str(&needle, 1));

        let (index, found) = sk.rfind(&enc_haystack, &enc_needle);
        let index = ck.key.decrypt_radix::<u32>(&index);
        let found = ck.key.decrypt_bool(&found);

        assert!(found);
        assert_eq!(index, 2);
    }

    #[test]
    fn test_find_trim_start() {
        let (ck, sk) = generate_keys(PARAM_MESSAGE_2_CARRY_2);
        let (haystack, needle) = ("  h", "h");

        let fhe_haystack = ck.enc_str(&haystack, 0);
        let fhe_needle = GenericPattern::Enc(ck.enc_str(&needle, 1));
        let fhe_s = sk.trim_start(&fhe_haystack);

        let (index, found) = sk.find(&fhe_s, &fhe_needle);
        let index = ck.key.decrypt_radix::<u32>(&index);
        let found = ck.key.decrypt_bool(&found);

        assert!(found);
        assert_eq!(index, 0);
    }
}
