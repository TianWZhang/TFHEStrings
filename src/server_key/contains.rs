use std::ops::Range;

use rayon::iter::{IntoParallelIterator, ParallelBridge, ParallelIterator};
use tfhe::{
    integer::{BooleanBlock, IntegerRadixCiphertext, RadixCiphertext},
    shortint::Ciphertext,
};

use crate::fhe_string::{FheString, GenericPattern, PlaintextString, NUM_BLOCKS};

use super::{IsMatch, ServerKey};

impl ServerKey {
    fn compare_range(
        &self,
        str: &FheString,
        pattern: &FheString,
        range: Range<usize>,
        ignore_pattern_padding: bool,
    ) -> BooleanBlock {
        let matched: Vec<_> = range
            .into_par_iter()
            .map(|start| {
                if ignore_pattern_padding {
                    // We can guarantee that `str` always ends with at least one padding zero.
                    let str_pat = str.bytes.iter().skip(start).zip(pattern.bytes.iter()).par_bridge();
                    self.starts_with_ignore_pattern_padding(str_pat)
                } else {
                    let substr = FheString {
                        bytes: str.bytes[start..start + pattern.bytes.len()].to_vec(),
                        padded: str.padded,
                    };
                    self.fhestrings_eq(&substr, pattern)
                }
            })
            .collect();

        let block_vec: Vec<_> = matched
            .into_iter()
            .map(|bool| {
                let radix: RadixCiphertext = bool.into_radix(1, &self.key);
                radix.into_blocks()[0].clone()
            })
            .collect();

        // This will be 0 if there was no match, non-zero otherwise
        let combined_radix = RadixCiphertext::from(block_vec);

        self.key.scalar_ne_parallelized(&combined_radix, 0)
    }

    fn compare_range_plaintext(
        &self,
        str: &FheString,
        pattern: &PlaintextString,
        range: Range<usize>,
    ) -> BooleanBlock {
        let matched: Vec<_> = range
            .into_par_iter()
            .map(|start| {
                let substr = FheString {
                    bytes: str.bytes[start..start + pattern.data.len()].to_vec(),
                    padded: str.padded,
                };
                self.fhestring_eq_string(&substr, pattern.data.as_str())
            })
            .collect();

        let block_vec: Vec<Ciphertext> = matched
            .into_par_iter()
            .map(|bool| {
                let radix: RadixCiphertext = bool.into_radix(1, &self.key);
                radix.into_blocks()[0].clone()
            })
            .collect();

        // This will be 0 if there was no match, non-zero otherwise
        let combined_radix = RadixCiphertext::from(block_vec);
        self.key.scalar_ne_parallelized(&combined_radix, 0)
    }

    /// Returns `true` if the given pattern (either encrypted or clear) matches a substring of this
    /// encrypted string.
    ///
    /// Returns `false` if the pattern does not match any substring.
    ///
    /// The pattern to search for can be specified as either `GenericPattern::Clear` for a clear
    /// string or `GenericPattern::Enc` for an encrypted string.
    pub fn contains(&self, str: &FheString, pattern: &GenericPattern) -> BooleanBlock {
        let trivial_or_enc_pat = match pattern {
            GenericPattern::Clear(pattern) => FheString::enc_trivial(&pattern.data, self),
            GenericPattern::Enc(pattern) => pattern.clone(),
        };
        match self.is_matched_early_checks(str, &trivial_or_enc_pat) {
            IsMatch::Clear(val) => return self.key.create_trivial_boolean_block(val),
            IsMatch::Cipher(val) => return val,
            _ => (),
        }

        let ignore_pattern_padding = trivial_or_enc_pat.padded;
        let (str_contains, pat_contains, range) = self.contains_cases(str, &trivial_or_enc_pat);
        match pattern {
            GenericPattern::Clear(pattern) => {
                self.compare_range_plaintext(&str_contains, &pattern, range)
            }
            GenericPattern::Enc(_) => {
                self.compare_range(&str_contains, &pat_contains, range, ignore_pattern_padding)
            }
        }
    }

    /// Returns `true` if the given pattern (either encrypted or clear) matches a prefix of this
    /// encrypted string.
    ///
    /// Returns `false` if the pattern does not match the prefix.
    ///
    /// The pattern to search for can be specified as either `GenericPattern::Clear` for a clear
    /// string or `GenericPattern::Enc` for an encrypted string.
    pub fn starts_with(&self, str: &FheString, pattern: &GenericPattern) -> BooleanBlock {
        let trivial_or_enc_pat = match pattern {
            GenericPattern::Clear(pattern) => FheString::enc_trivial(&pattern.data, self),
            GenericPattern::Enc(pattern) => pattern.clone(),
        };
        match self.is_matched_early_checks(str, &trivial_or_enc_pat) {
            IsMatch::Clear(val) => return self.key.create_trivial_boolean_block(val),
            IsMatch::Cipher(val) => return val,
            _ => (),
        }

        if !trivial_or_enc_pat.padded {
            return match pattern {
                GenericPattern::Clear(pattern) => self.compare_range_plaintext(str, &pattern, 0..1),
                GenericPattern::Enc(pattern) => self.compare_range(str, &pattern, 0..1, false),
            };
        }

        let str_len = str.bytes.len();
        let pat_len = trivial_or_enc_pat.bytes.len();
        // The pattern must be padded, hence we can remove the last char as it is always null
        let pat_chars = &trivial_or_enc_pat.bytes[0..pat_len - 1];

        let mut str_bytes = str.bytes.clone();
        if !str.padded && str_len < pat_len - 1 {
            str_bytes.push(self.key.create_trivial_zero_radix(NUM_BLOCKS));
        }
        let str_pat = str_bytes.iter().zip(pat_chars.iter()).par_bridge();
        self.starts_with_ignore_pattern_padding(str_pat)
    }

    /// Returns `true` if the given pattern (either encrypted or clear) matches a suffix of this
    /// encrypted string.
    ///
    /// Returns `false` if the pattern does not match the suffix.
    ///
    /// The pattern to search for can be specified as either `GenericPattern::Clear` for a clear
    /// string or `GenericPattern::Enc` for an encrypted string.
    pub fn ends_with(&self, str: &FheString, pattern: &GenericPattern) -> BooleanBlock {
        let trivial_or_enc_pat = match pattern {
            GenericPattern::Clear(pattern) => FheString::enc_trivial(&pattern.data, self),
            GenericPattern::Enc(pattern) => pattern.clone(),
        };
        match self.is_matched_early_checks(str, &trivial_or_enc_pat) {
            IsMatch::Clear(val) => return self.key.create_trivial_boolean_block(val),
            IsMatch::Cipher(val) => return val,
            _ => (),
        }
        
        match pattern {
            GenericPattern::Clear(pattern) => {
                let (str, pattern, range) = self.clear_ends_with_cases(str, &pattern.data);
                self.compare_range_plaintext(&str, &pattern, range)
            }
            GenericPattern::Enc(pattern) => {
                let (str, pattern, range) = self.ends_with_cases(str, pattern);
                self.compare_range(&str, &pattern, range, false)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use tfhe::shortint::prelude::PARAM_MESSAGE_2_CARRY_2;

    use crate::{
        fhe_string::{GenericPattern, PlaintextString},
        generate_keys,
    };

    #[test]
    fn test_contains() {
        let s = "AaBcdE";
        let pat1 = "cd";
        let pat2 = "ef";
        let (ck, sk) = generate_keys(PARAM_MESSAGE_2_CARRY_2);
        let fhe_s = ck.enc_str(s, 0);
        let fhe_pat1 = GenericPattern::Enc(ck.enc_str(pat1, 0));

        let res1 = sk.contains(&fhe_s, &fhe_pat1);
        let dec1 = ck.key.decrypt_bool(&res1);
        assert_eq!(dec1, s.contains(pat1));

        let fhe_pat2 = GenericPattern::Enc(ck.enc_str(pat2, 0));
        let res2 = sk.contains(&fhe_s, &fhe_pat2);
        let dec2 = ck.key.decrypt_bool(&res2);
        assert_eq!(dec2, s.contains(pat2));

        let clear_pat1 = GenericPattern::Clear(PlaintextString::new(pat1.to_string()));
        let res3 = sk.contains(&fhe_s, &clear_pat1);
        let dec3 = ck.key.decrypt_bool(&res3);
        assert_eq!(dec3, s.contains(pat1));
    }

    #[test]
    fn test_starts_with() {
        let s = "AaBcdE";
        let pat = "AaB";
        let (ck, sk) = generate_keys(PARAM_MESSAGE_2_CARRY_2);
        let fhe_s = ck.enc_str(s, 0);
        let fhe_pat = GenericPattern::Enc(ck.enc_str(pat, 2));

        let res = sk.starts_with(&fhe_s, &fhe_pat);
        let dec = ck.key.decrypt_bool(&res);
        assert_eq!(dec, s.starts_with(pat));

        let clear_pat = GenericPattern::Clear(PlaintextString::new(pat.to_string()));
        let res = sk.starts_with(&fhe_s, &clear_pat);
        let dec = ck.key.decrypt_bool(&res);
        assert_eq!(dec, s.starts_with(pat));
    }

    #[test]
    fn test_ends_with() {
        let s = "AaBcdE";
        let pat = "dH";
        let (ck, sk) = generate_keys(PARAM_MESSAGE_2_CARRY_2);
        let fhe_s = ck.enc_str(s, 0);
        let fhe_pat = GenericPattern::Enc(ck.enc_str(pat, 1));

        let res = sk.ends_with(&fhe_s, &fhe_pat);
        let dec = ck.key.decrypt_bool(&res);
        assert_eq!(dec, s.ends_with(pat));

        let clear_pat = GenericPattern::Clear(PlaintextString::new(pat.to_string()));
        let res = sk.ends_with(&fhe_s, &clear_pat);
        let dec = ck.key.decrypt_bool(&res);
        assert_eq!(dec, s.ends_with(pat));
    }
}
