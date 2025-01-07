use rayon::iter::{IntoParallelRefMutIterator, ParallelIterator};
use tfhe::integer::{prelude::ServerKeyDefaultCMux, BooleanBlock};

use crate::fhe_string::{FheString, GenericPattern, PlaintextString, NUM_BLOCKS};

use super::{IsMatch, ServerKey};

impl ServerKey {
    // We only use this function in `strip_suffix` function.
    fn compare_range_strip(
        &self,
        striped_str: &mut FheString,
        str: &FheString,
        pattern: &FheString,
        range: impl Iterator<Item = usize>,
    ) -> BooleanBlock {
        let mut res = self.key.create_trivial_boolean_block(false);
        for start in range {
            let suffix = FheString {
                bytes: str.bytes[start..].to_vec(),
                padded: str.padded,
            };
            let is_matched = self.fhestrings_eq(&suffix, pattern);
            let mut mask = is_matched.clone().into_radix(NUM_BLOCKS, &self.key);
            // If mask == 0u8, it will become 255u8. If it was 1u8, it will become 0u8.
            self.key.scalar_sub_assign_parallelized(&mut mask, 1);

            let mutate_str = if start + pattern.bytes.len() < str.bytes.len() {
                &mut striped_str.bytes[start..start + pattern.bytes.len()]
            } else {
                &mut striped_str.bytes[start..]
            };

            rayon::join(
                || {
                    mutate_str.par_iter_mut().for_each(|c| {
                        self.key.bitand_assign_parallelized(c, &mask);
                    })
                },
                || self.key.boolean_bitor_assign(&mut res, &is_matched),
            );
        }
        res
    }

    fn compare_range_strip_plaintext(
        &self,
        striped_str: &mut FheString,
        str: &FheString,
        pattern: &PlaintextString,
        range: impl Iterator<Item = usize>,
    ) -> BooleanBlock {
        let mut res = self.key.create_trivial_boolean_block(false);
        for start in range {
            let substr = FheString {
                bytes: str.bytes[start..].to_vec(),
                padded: str.padded,
            };
            let is_matched = self.fhestring_eq_string(&substr, pattern.data.as_str());

            let mut mask = is_matched.clone().into_radix(NUM_BLOCKS, &self.key);
            self.key.scalar_sub_assign_parallelized(&mut mask, 1);

            let mutate_str = if start + pattern.data.len() < str.bytes.len() {
                &mut striped_str.bytes[start..start + pattern.data.len()]
            } else {
                &mut striped_str.bytes[start..]
            };

            rayon::join(
                || {
                    mutate_str.par_iter_mut().for_each(|c| {
                        self.key.bitand_assign_parallelized(c, &mask);
                    })
                },
                || self.key.boolean_bitor_assign(&mut res, &is_matched),
            );
        }
        res
    }

    /// Returns a new encrypted string with the specified pattern (either encrypted or clear)
    /// removed from the start of this encrypted string, if it matches. Also returns a boolean
    /// indicating if the pattern was found and removed.
    ///
    /// If the pattern does not match the start of the string, returns the original encrypted
    /// string and a boolean set to `false`.
    ///
    /// The pattern to search for can be specified as either `GenericPattern::Clear` for a clear
    /// string or `GenericPattern::Enc` for an encrypted string.
    pub fn strip_prefix(
        &self,
        str: &FheString,
        pattern: &GenericPattern,
    ) -> (FheString, BooleanBlock) {
        let mut res = str.clone();
        let trivial_or_enc_pat = match pattern {
            GenericPattern::Clear(pattern) => FheString::enc_trivial(&pattern, self),
            GenericPattern::Enc(pattern) => pattern.clone(),
        };
        match self.is_matched_early_checks(str, &trivial_or_enc_pat) {
            // IsMatch::Clear(true) means `pattern` is empty, so we can just return the original
            IsMatch::Clear(val) => return (res, self.key.create_trivial_boolean_block(val)),
            // IsMatch::Cipher(val) means `str` is empty, so we can just return the original
            IsMatch::Cipher(val) => return (res, val),
            _ => (),
        }

        let num_blocks = 32 / ((((self.key.message_modulus().0) as f64).log2()) as usize);
        let (is_striped, pattern_len) = rayon::join(
            || self.starts_with(str, pattern),
            || self.len_enc(&trivial_or_enc_pat),
        );

        let shift_left = self.key.if_then_else_parallelized(
            &is_striped,
            &pattern_len,
            &self.key.create_trivial_zero_radix(num_blocks),
        );
        res = self.left_shift_chars(str, &shift_left);

        // If `str` is not padded, we don't know if `res` has nulls at the end or not because
        // we don't know if `str` is left shifted or not. Therefore we ensure `res` is padded in
        // order to use it in other functions safely.
        if str.padded {
            res.padded = true;
        } else {
            res.append_null(self);
        }
        (res, is_striped)
    }

    /// Returns a new encrypted string with the specified pattern (either encrypted or clear)
    /// removed from the end of this encrypted string, if it matches. Also returns a boolean
    /// indicating if the pattern was found and removed.
    ///
    /// If the pattern does not match the end of the string, returns the original encrypted string
    /// and a boolean set to `false`.
    ///
    /// The pattern to search for can be specified as either `GenericPattern::Clear` for a clear
    /// string or `GenericPattern::Enc` for an encrypted string.
    pub fn strip_suffix(
        &self,
        str: &FheString,
        pattern: &GenericPattern,
    ) -> (FheString, BooleanBlock) {
        let mut res = str.clone();
        let trivial_or_enc_pat = match pattern {
            GenericPattern::Clear(pattern) => FheString::enc_trivial(&pattern, self),
            GenericPattern::Enc(pattern) => pattern.clone(),
        };
        match self.is_matched_early_checks(str, &trivial_or_enc_pat) {
            // IsMatch::Clear(true) means `pattern` is empty, so we can just return the original
            IsMatch::Clear(val) => return (res, self.key.create_trivial_boolean_block(val)),
            // IsMatch::Cipher(val) means `str` is empty, so we can just return the original
            IsMatch::Cipher(val) => return (res, val),
            _ => (),
        }

        let is_striped = match pattern {
            GenericPattern::Clear(pattern) => {
                let (str_strip, pat_strip, range) = self.clear_ends_with_cases(str, pattern);
                self.compare_range_strip_plaintext(&mut res, &str_strip, &pat_strip, range)
            }
            GenericPattern::Enc(pattern) => {
                let (str_strip, pat_strip, range) = self.ends_with_cases(str, pattern);
                self.compare_range_strip(&mut res, &str_strip, &pat_strip, range)
            }
        };

        // If `str` is not padded, `res` is now potentially padded as we may have made the last chars null.
        // We ensure `res` is padded in order to use it in other functions safely.
        if !str.padded {
            res.append_null(self);
        }
        (res, is_striped)
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
    fn test_strip_prefix() {
        let (ck, sk) = generate_keys(PARAM_MESSAGE_2_CARRY_2);

        let (haystack, needle) = ("hello", "he");
        let enc_haystack = ck.enc_str(haystack, 0);
        let enc_needle = GenericPattern::Enc(ck.enc_str(needle, 1));
        let (enc_res, enc_is_striped) = sk.strip_prefix(&enc_haystack, &enc_needle);
        let is_striped = ck.key.decrypt_bool(&enc_is_striped);
        assert!(is_striped);
        assert_eq!(ck.dec_str(&enc_res), "llo".to_string());

        let (haystack, needle) = ("hello", "el");
        let enc_haystack = ck.enc_str(haystack, 2);
        let enc_needle = GenericPattern::Enc(ck.enc_str(needle, 1));
        let (enc_res, enc_is_striped) = sk.strip_prefix(&enc_haystack, &enc_needle);
        let is_striped = ck.key.decrypt_bool(&enc_is_striped);
        assert!(!is_striped);
        assert_eq!(ck.dec_str(&enc_res), haystack);
    }

    #[test]
    fn test_strip_suffix() {
        let (ck, sk) = generate_keys(PARAM_MESSAGE_2_CARRY_2);

        let (haystack, needle) = ("h", "he");
        let enc_haystack = ck.enc_str(haystack, 2);
        let enc_needle = GenericPattern::Enc(ck.enc_str(needle, 1));
        let (enc_res, enc_is_striped) = sk.strip_suffix(&enc_haystack, &enc_needle);
        let is_striped = ck.key.decrypt_bool(&enc_is_striped);
        assert!(!is_striped);
        assert_eq!(ck.dec_str(&enc_res), haystack);

        let (haystack, needle) = ("ello", "o");
        let enc_haystack = ck.enc_str(haystack, 0);
        let enc_needle = GenericPattern::Enc(ck.enc_str(needle, 2));
        let (enc_res, enc_is_striped) = sk.strip_suffix(&enc_haystack, &enc_needle);
        let is_striped = ck.key.decrypt_bool(&enc_is_striped);
        assert!(is_striped);
        assert_eq!(ck.dec_str(&enc_res), "ell");

        let (haystack, needle) = ("ellohe", "he");
        let enc_haystack = ck.enc_str(haystack, 1);
        let enc_needle = GenericPattern::Clear(PlaintextString::new(needle.to_string()));
        let (enc_res, enc_is_striped) = sk.strip_suffix(&enc_haystack, &enc_needle);
        let is_striped = ck.key.decrypt_bool(&enc_is_striped);
        assert!(is_striped);
        assert_eq!(ck.dec_str(&enc_res), "ello");
    }
}
