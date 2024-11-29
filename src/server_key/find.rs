use super::ServerKey;
use crate::fhe_string::{FheString, GenericPattern, PlaintextString};
use tfhe::integer::{prelude::ServerKeyDefaultCMux, BooleanBlock, RadixCiphertext};

impl ServerKey {
    // Compare `pattern` with `str`, with `pattern` shifted in range [l..=r].
    // Returns the first character index of the last match, or the first character index
    // of the first match if the range is reversed. If there's no match defaults to 0
    fn compare_shifted_index(
        &self,
        str: &FheString,
        pattern: &FheString,
        range: impl Iterator<Item = usize>,
    ) -> (RadixCiphertext, BooleanBlock) {
        let mut is_found = self.key.create_trivial_boolean_block(false);
        // We consider the index as u32.
        let num_blocks = 32 / ((((self.key.message_modulus().0) as f64).log2()) as usize);
        let mut last_match_index = self.key.create_trivial_zero_radix(num_blocks);

        let matched: Vec<_> = range
            .map(|start| {
                let substr = &str.clone().bytes[start..];
                let pattern_slice = &pattern.clone().bytes[..];
                let is_matched = self.fhestrings_eq(substr, pattern_slice);
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

    fn compare_shifted_index_plaintext(
        &self,
        str: &FheString,
        pattern: &PlaintextString,
        range: impl Iterator<Item = usize>,
    ) -> (RadixCiphertext, BooleanBlock) {
        let mut res = self.key.create_trivial_boolean_block(false);
        let num_blocks = 32 / ((((self.key.message_modulus().0) as f64).log2()) as usize);
        let mut last_match_index = self.key.create_trivial_zero_radix(num_blocks);
        let matched: Vec<_> = range
            .map(|start| {
                let substr = &str.clone().bytes[start..];
                let is_matched = self.fhestring_eq_string(substr, pattern.data.as_str());
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
        match pattern {
            GenericPattern::Enc(pat) => {
                if str.bytes.len() < pat.bytes.len() {
                    return (
                        self.key
                            .create_trivial_radix(str.bytes.len() as u32, num_blocks),
                        self.key.create_trivial_boolean_block(false),
                    );
                }
                self.compare_shifted_index(str, pat, 0..=(str.bytes.len() - pat.bytes.len()))
            }
            GenericPattern::Clear(pat) => {
                if str.bytes.len() < pat.data.len() {
                    return (
                        self.key
                            .create_trivial_radix(str.bytes.len() as u32, num_blocks),
                        self.key.create_trivial_boolean_block(false),
                    );
                }
                self.compare_shifted_index_plaintext(
                    str,
                    pat,
                    0..=(str.bytes.len() - pat.data.len()),
                )
            }
        }
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
        match pattern {
            GenericPattern::Enc(pat) => {
                if str.bytes.len() < pat.bytes.len() {
                    return (
                        self.key
                            .create_trivial_radix(str.bytes.len() as u32, num_blocks),
                        self.key.create_trivial_boolean_block(false),
                    );
                }
                self.compare_shifted_index(
                    str,
                    pat,
                    (0..=(str.bytes.len() - pat.bytes.len())).rev(),
                )
            }
            GenericPattern::Clear(pat) => {
                if str.bytes.len() < pat.data.len() {
                    return (
                        self.key
                            .create_trivial_radix(str.bytes.len() as u32, num_blocks),
                        self.key.create_trivial_boolean_block(false),
                    );
                }
                self.compare_shifted_index_plaintext(
                    str,
                    pat,
                    (0..=(str.bytes.len() - pat.data.len())).rev(),
                )
            }
        }
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
    fn test_find() {
        let (ck, sk) = generate_keys(PARAM_MESSAGE_2_CARRY_2.into());

        let (haystack, needle) = ("ell", "e");
        let enc_haystack = FheString::encrypt(PlaintextString::new(haystack.to_string()), &ck);
        let enc_needle = GenericPattern::Enc(FheString::encrypt(
            PlaintextString::new(needle.to_string()),
            &ck,
        ));
        let (index, found) = sk.find(&enc_haystack, &enc_needle);
        let index = ck.key.decrypt_radix::<u32>(&index);
        let found = ck.key.decrypt_bool(&found);
        assert!(found);
        assert_eq!(index, 0);

        let (haystack, needle) = ("ell", "le");
        let enc_haystack = FheString::encrypt(PlaintextString::new(haystack.to_string()), &ck);
        let enc_needle = GenericPattern::Enc(FheString::encrypt(
            PlaintextString::new(needle.to_string()),
            &ck,
        ));
        let (index, found) = sk.find(&enc_haystack, &enc_needle);
        let index = ck.key.decrypt_radix::<u32>(&index);
        let found = ck.key.decrypt_bool(&found);
        assert!(!found);
        assert_eq!(index, 3);
    }

    #[test]
    fn test_rfind() {
        let (ck, sk) = generate_keys(PARAM_MESSAGE_2_CARRY_2.into());
        let (haystack, needle) = ("ell", "l");

        let enc_haystack = FheString::encrypt(PlaintextString::new(haystack.to_string()), &ck);
        let enc_needle = GenericPattern::Enc(FheString::encrypt(
            PlaintextString::new(needle.to_string()),
            &ck,
        ));

        let (index, found) = sk.rfind(&enc_haystack, &enc_needle);
        let index = ck.key.decrypt_radix::<u32>(&index);
        let found = ck.key.decrypt_bool(&found);

        assert!(found);
        assert_eq!(index, 2);
    }
}
