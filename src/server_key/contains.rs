use tfhe::{
    integer::{BooleanBlock, IntegerRadixCiphertext, RadixCiphertext},
    shortint::Ciphertext,
};

use crate::fhe_string::{FheString, GenericPattern, PlaintextString};

use super::ServerKey;

impl ServerKey {
    fn compare_shifted(
        &self,
        str: &FheString,
        pattern: &FheString,
        l: usize,
        r: usize,
    ) -> BooleanBlock {
        let matched: Vec<_> = (l..=r)
            .map(|start| {
                let substr = &str.clone().bytes[start..];
                let pattern_slice = &pattern.clone().bytes[..];
                self.fhestrings_eq(substr, pattern_slice)
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

    fn compare_shifted_plaintext(
        &self,
        str: &FheString,
        pattern: &PlaintextString,
        l: usize,
        r: usize,
    ) -> BooleanBlock {
        let matched: Vec<_> = (l..=r)
            .map(|start| {
                let substr = &str.clone().bytes[start..];
                self.fhestring_eq_string(substr, pattern.data.as_str())
            })
            .collect();

        let block_vec: Vec<Ciphertext> = matched
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

    /// Returns `true` if the given pattern (either encrypted or clear) matches a substring of this
    /// encrypted string.
    ///
    /// Returns `false` if the pattern does not match any substring.
    ///
    /// The pattern to search for can be specified as either `GenericPattern::Clear` for a clear
    /// string or `GenericPattern::Enc` for an encrypted string.
    pub fn contains(&self, str: &FheString, pattern: &GenericPattern) -> BooleanBlock {
        match pattern {
            GenericPattern::Clear(pattern) => {
                if str.bytes.len() < pattern.data.len() {
                    return self.key.create_trivial_boolean_block(false);
                }
                let diff = str.bytes.len() - pattern.data.len();
                self.compare_shifted_plaintext(
                    str,
                    &pattern,
                    0,
                    diff,
                )
            }
            GenericPattern::Enc(pattern) => {
                if str.bytes.len() < pattern.bytes.len() {
                    return self.key.create_trivial_boolean_block(false);
                }
                let diff = str.bytes.len() - pattern.bytes.len();
                self.compare_shifted(str, &pattern, 0, diff)
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
        match pattern {
            GenericPattern::Clear(pattern) => self.compare_shifted_plaintext(str, &pattern, 0, 0),
            GenericPattern::Enc(pattern) => self.compare_shifted(str, &pattern, 0, 0),
        }
    }

    /// Returns `true` if the given pattern (either encrypted or clear) matches a suffix of this
    /// encrypted string.
    ///
    /// Returns `false` if the pattern does not match the suffix.
    ///
    /// The pattern to search for can be specified as either `GenericPattern::Clear` for a clear
    /// string or `GenericPattern::Enc` for an encrypted string.
    pub fn ends_with(&self, str: &FheString, pattern: &GenericPattern) -> BooleanBlock {
        match pattern {
            GenericPattern::Clear(pattern) => {
                if str.bytes.len() < pattern.data.len() {
                    return self.key.create_trivial_boolean_block(false);
                }
                let diff = str.bytes.len() - pattern.data.len();
                self.compare_shifted_plaintext(
                    str,
                    &pattern,
                    diff,
                    diff,
                )
            }
            GenericPattern::Enc(pattern) => {
                if str.bytes.len() < pattern.bytes.len() {
                    return self.key.create_trivial_boolean_block(false);
                }
                let diff = str.bytes.len() - pattern.bytes.len();
                self.compare_shifted(
                    str,
                    &pattern,
                    diff,
                    diff,
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
    fn test_contains() {
        let s = "AaBcdE";
        let pat1 = "cd";
        let pat2 = "ef";
        let (ck, sk) = generate_keys(PARAM_MESSAGE_2_CARRY_2.into());
        let fhe_s = FheString::encrypt(PlaintextString::new(s.to_string()), &ck);
        let fhe_pat1 = GenericPattern::Enc(FheString::encrypt(
            PlaintextString::new(pat1.to_string()),
            &ck,
        ));

        let res1 = sk.contains(&fhe_s, &fhe_pat1);
        let dec1 = ck.key.decrypt_bool(&res1);
        assert_eq!(dec1, s.contains(pat1));

        let fhe_pat2 = GenericPattern::Enc(FheString::encrypt(
            PlaintextString::new(pat2.to_string()),
            &ck,
        ));
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
        let (ck, sk) = generate_keys(PARAM_MESSAGE_2_CARRY_2.into());
        let fhe_s = FheString::encrypt(PlaintextString::new(s.to_string()), &ck);
        let fhe_pat = GenericPattern::Enc(FheString::encrypt(
            PlaintextString::new(pat.to_string()),
            &ck,
        ));

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
        let (ck, sk) = generate_keys(PARAM_MESSAGE_2_CARRY_2.into());
        let fhe_s = FheString::encrypt(PlaintextString::new(s.to_string()), &ck);
        let fhe_pat = GenericPattern::Enc(FheString::encrypt(
            PlaintextString::new(pat.to_string()),
            &ck,
        ));

        let res = sk.ends_with(&fhe_s, &fhe_pat);
        let dec = ck.key.decrypt_bool(&res);
        assert_eq!(dec, s.ends_with(pat));

        let clear_pat = GenericPattern::Clear(PlaintextString::new(pat.to_string()));
        let res = sk.ends_with(&fhe_s, &clear_pat);
        let dec = ck.key.decrypt_bool(&res);
        assert_eq!(dec, s.ends_with(pat));
    }
}
