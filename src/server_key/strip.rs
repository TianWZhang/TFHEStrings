use rayon::iter::{IntoParallelRefMutIterator, ParallelIterator};
use tfhe::integer::BooleanBlock;

use crate::fhe_string::{FheString, GenericPattern, PlaintextString, NUM_BLOCKS};

use super::ServerKey;

impl ServerKey {
    fn compare_shifted_strip(
        &self,
        str: &mut FheString,
        pattern: &FheString,
        range: impl Iterator<Item = usize>,
    ) -> BooleanBlock {
        let mut res = self.key.create_trivial_boolean_block(false);
        for start in range {
            let substr = &str.clone().bytes[start..];
            let pattern_slice = &pattern.clone().bytes[..];
            let is_matched = self.fhestrings_eq(substr, pattern_slice);

            let mut mask = is_matched.clone().into_radix(NUM_BLOCKS, &self.key);
            // If mask == 0u8, it will become 255u8. If it was 1u8, it will become 0u8.
            self.key.scalar_sub_assign_parallelized(&mut mask, 1);

            let mutate_str = if start + pattern.bytes.len() < str.bytes.len() {
                &mut str.bytes[start..start + pattern.bytes.len()]
            } else {
                &mut str.bytes[start..]
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

    fn compare_shifted_strip_plaintext(
        &self,
        str: &mut FheString,
        pattern: &PlaintextString,
        range: impl Iterator<Item = usize>,
    ) -> BooleanBlock {
        let mut res = self.key.create_trivial_boolean_block(false);
        for start in range {
            let substr = &str.clone().bytes[start..];
            let is_matched = self.fhestring_eq_string(&substr, pattern.data.as_str());

            let mut mask = is_matched.clone().into_radix(NUM_BLOCKS, &self.key);
            self.key.scalar_sub_assign_parallelized(&mut mask, 1);

            let mutate_str = if start + pattern.data.len() < str.bytes.len() {
                &mut str.bytes[start..start + pattern.data.len()]
            } else {
                &mut str.bytes[start..]
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
        let mut resulted_str = str.clone();
        let is_striped = match pattern {
            GenericPattern::Clear(pattern) => {
                self.compare_shifted_strip_plaintext(&mut resulted_str, pattern, 0..=0)
            }
            GenericPattern::Enc(pattern) => {
                self.compare_shifted_strip(&mut resulted_str, pattern, 0..=0)
            }
        };
        (resulted_str, is_striped)
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
        let mut resulted_str = str.clone();
        let is_striped = match pattern {
            GenericPattern::Clear(pattern) => {
                if str.bytes.len() < pattern.data.len() {
                    return (resulted_str, self.key.create_trivial_boolean_block(false));
                }
                let diff = str.bytes.len() - pattern.data.len();
                self.compare_shifted_strip_plaintext(&mut resulted_str, pattern, diff..=diff)
            }
            GenericPattern::Enc(pattern) => {
                if str.bytes.len() < pattern.bytes.len() {
                    return (resulted_str, self.key.create_trivial_boolean_block(false));
                }
                let diff = str.bytes.len() - pattern.bytes.len();
                self.compare_shifted_strip(&mut resulted_str, pattern, diff..=diff)
            }
        };
        (resulted_str, is_striped)
    }
}

#[cfg(test)]
mod tests {
    use tfhe::shortint::prelude::PARAM_MESSAGE_2_CARRY_2;

    use crate::{
        fhe_string::{FheString, GenericPattern, PlaintextString},
        generate_keys,
    };

    #[test]
    fn test_strip_prefix() {
        let (ck, sk) = generate_keys(PARAM_MESSAGE_2_CARRY_2.into());
        let (haystack, needle) = ("hello", "he");

        let enc_haystack = FheString::encrypt(PlaintextString::new(haystack.to_string()), &ck);
        let enc_needle = GenericPattern::Enc(FheString::encrypt(
            PlaintextString::new(needle.to_string()),
            &ck,
        ));

        let (enc_res, enc_is_striped) = sk.strip_prefix(&enc_haystack, &enc_needle);
        let is_striped = ck.key.decrypt_bool(&enc_is_striped);

        assert!(is_striped);
        assert_eq!(enc_res.decrypt(&ck), "llo".to_string());
    }

    #[test]
    fn test_strip_suffix() {
        let (ck, sk) = generate_keys(PARAM_MESSAGE_2_CARRY_2.into());
        let (haystack, needle) = ("h", "he");

        let enc_haystack = FheString::encrypt(PlaintextString::new(haystack.to_string()), &ck);
        let enc_needle = GenericPattern::Enc(FheString::encrypt(
            PlaintextString::new(needle.to_string()),
            &ck,
        ));

        let (enc_res, enc_is_striped) = sk.strip_suffix(&enc_haystack, &enc_needle);
        let is_striped = ck.key.decrypt_bool(&enc_is_striped);

        assert!(!is_striped);
        assert_eq!(enc_res.decrypt(&ck), "llo".to_string());
    }
}
