use super::ServerKey;
use crate::fhe_string::{FheString, GenericPattern, PlaintextString, NUM_BLOCKS};
use tfhe::{
    integer::{prelude::ServerKeyDefaultCMux, BooleanBlock, IntegerCiphertext, RadixCiphertext},
    shortint::Ciphertext,
};

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
        let mut res = self.key.create_trivial_boolean_block(false);
        // We consider the index as u32.
        let mut last_match_index = self.key.create_trivial_zero_radix(4 * NUM_BLOCKS);

        let matched: Vec<_> = range
            .map(|start| {
                let substr = &str.clone().bytes[start..];
                let pattern_slice = &pattern.clone().bytes[..];
                let is_matched = self.string_eq(substr, pattern_slice);
                (start, is_matched)
            })
            .collect();

        for (i, is_matched) in matched {
            let index = self.key.create_trivial_radix(i as u32, 4 * NUM_BLOCKS);
            rayon::join(
                || {
                    last_match_index =
                        self.key
                            .if_then_else_parallelized(&is_matched, &index, &last_match_index);
                },
                || self.key.boolean_bitor_assign(&mut res, &is_matched),
            );
        }
        (last_match_index, res)
    }

    fn compare_shifted_index_plaintext(
        &self,
        str: &FheString,
        pattern: &PlaintextString,
        range: impl Iterator<Item = usize>,
    ) -> (RadixCiphertext, BooleanBlock) {
        let mut res = self.key.create_trivial_boolean_block(false);
        let mut last_match_index = self.key.create_trivial_zero_radix(4 * NUM_BLOCKS);
        let matched: Vec<_> = range
            .map(|start| {
                let substr = &str.clone().bytes[start..];
                let blocks_substr: Vec<Ciphertext> = substr
                    .into_iter()
                    .rev()
                    .flat_map(|c| c.blocks().to_owned())
                    .collect();
                let blocks_substr_len = blocks_substr.len();
                let mut substr = RadixCiphertext::from_blocks(blocks_substr);

                let mut pattern_plaintext = pattern.data.as_str();
                if blocks_substr_len < pattern.data.len() * NUM_BLOCKS {
                    pattern_plaintext = &pattern_plaintext[..blocks_substr_len / NUM_BLOCKS];
                } else if blocks_substr_len > pattern.data.len() * NUM_BLOCKS {
                    let diff = blocks_substr_len - pattern.data.len() * NUM_BLOCKS;
                    self.key.trim_radix_blocks_lsb_assign(&mut substr, diff);
                }
                let pattern_plaintext_uint =
                    self.pad_cipher_and_plaintext_lsb(&mut substr, pattern_plaintext);
                let is_matched = self
                    .key
                    .scalar_eq_parallelized(&substr, pattern_plaintext_uint);
                (start, is_matched)
            })
            .collect();

        for (i, is_matched) in matched {
            let index = self.key.create_trivial_radix(i as u32, 4 * NUM_BLOCKS);
            rayon::join(
                || {
                    last_match_index =
                        self.key
                            .if_then_else_parallelized(&is_matched, &index, &last_match_index);
                },
                || self.key.boolean_bitor_assign(&mut res, &is_matched),
            );
        }
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
        match pattern {
            GenericPattern::Enc(pat) => {
                self.compare_shifted_index(str, pat, 0..=(str.bytes.len() - pat.bytes.len()))
            }
            GenericPattern::Clear(pat) => self.compare_shifted_index_plaintext(
                str,
                pat,
                0..=(str.bytes.len() - pat.data.len()),
            ),
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
        match pattern {
            GenericPattern::Enc(pat) => self.compare_shifted_index(
                str,
                pat,
                (0..=(str.bytes.len() - pat.bytes.len())).rev(),
            ),
            GenericPattern::Clear(pat) => self.compare_shifted_index_plaintext(
                str,
                pat,
                (0..=(str.bytes.len() - pat.data.len())).rev(),
            ),
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
        let (haystack, needle) = ("ell", "l");

        let enc_haystack = FheString::encrypt(PlaintextString::new(haystack.to_string()), &ck);
        let enc_needle = GenericPattern::Enc(FheString::encrypt(
            PlaintextString::new(needle.to_string()),
            &ck,
        ));

        let (index, found) = sk.find(&enc_haystack, &enc_needle);
        let index = ck.key.decrypt_radix::<u32>(&index);
        let found = ck.key.decrypt_bool(&found);

        assert!(found);
        assert_eq!(index, 1);
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
