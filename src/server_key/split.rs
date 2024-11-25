use tfhe::integer::{BooleanBlock, RadixCiphertext};

use crate::fhe_string::{FheString, GenericPattern};

use super::{FheStringIterator, ServerKey};

enum SplitType {
    SplitT,
    RSplitT,
    SplitInclusiveT,
}

pub struct Split {
    split_type: SplitType,
    state: FheString,
    pat: GenericPattern,
    prev_was_some: BooleanBlock,
    counter: u16,
    max_counter: RadixCiphertext,
    counter_lt_max: BooleanBlock,
}

impl FheStringIterator for Split {
    fn next(&mut self, sk: &ServerKey) -> (FheString, BooleanBlock) {
        todo!()
    }
}

impl ServerKey {
    fn split_pattern_at_index(
        &self,
        str: &FheString,
        pattern: &GenericPattern,
        idx: RadixCiphertext,
    ) -> (FheString, FheString) {
        let str_len = self.key.create_trivial_radix(
            str.bytes.len() as u32,
            32 / ((((self.key.message_modulus().0) as f64).log2()) as usize),
        );
        let (shift_right, pattern_len) = rayon::join(
            || self.key.sub_parallelized(&str_len, &idx),
            || {
                let pattern_len = match pattern {
                    GenericPattern::Clear(s) => s.len(),
                    GenericPattern::Enc(s) => s.bytes.len(),
                };
                self.key.create_trivial_radix(
                    pattern_len as u32,
                    32 / ((((self.key.message_modulus().0) as f64).log2()) as usize),
                )
            },
        );
        rayon::join(
            || {
                let lhs = self.right_shift_chars(str, &shift_right);
                self.left_shift_chars(&lhs, &shift_right)
            },
            || {
                let shift_left = self.key.add_parallelized(&pattern_len, &idx);
                self.left_shift_chars(str, &shift_left)
            },
        )
    }

    /// Splits the encrypted string into two substrings at the first occurrence of the pattern
    /// (either encrypted or clear) and returns a tuple of the two substrings along with a boolean
    /// indicating if the split occurred.
    ///
    /// If the pattern is not found returns `false`, indicating the equivalent of `None`.
    ///
    /// The pattern to search for can be specified as either `GenericPattern::Clear` for a clear
    /// string or `GenericPattern::Enc` for an encrypted string.
    pub fn split_once(
        &self,
        str: &FheString,
        pat: &GenericPattern,
    ) -> (FheString, FheString, BooleanBlock) {
        let (enc_idx, enc_is_found) = self.find(str, pat);
        let (lhs, rhs) = self.split_pattern_at_index(str, pat, enc_idx);
        (lhs, rhs, enc_is_found)
    }

    /// Splits the encrypted string into two substrings at the last occurrence of the pattern
    /// (either encrypted or clear) and returns a tuple of the two substrings along with a boolean
    /// indicating if the split occurred.
    ///
    /// If the pattern is not found returns `false`, indicating the equivalent of `None`.
    ///
    /// The pattern to search for can be specified as either `GenericPattern::Clear` for a clear
    /// string or `GenericPattern::Enc` for an encrypted string.
    pub fn rsplit_once(
        &self,
        str: &FheString,
        pat: &GenericPattern,
    ) -> (FheString, FheString, BooleanBlock) {
        let (enc_idx, enc_is_found) = self.rfind(str, pat);
        let (lhs, rhs) = self.split_pattern_at_index(str, pat, enc_idx);
        (lhs, rhs, enc_is_found)
    }

    /// Creates an iterator of encrypted substrings by splitting the original encrypted string based
    /// on a specified pattern (either encrypted or clear).
    ///
    /// The iterator, of type `Split`, can be used to sequentially retrieve the substrings. Each
    /// call to `next` on the iterator returns a tuple with the next split substring as an encrypted
    /// string and a boolean indicating `Some` (true) or `None` (false).
    ///
    /// The pattern to search for can be specified as either `GenericPattern::Clear` for a clear
    /// string or `GenericPattern::Enc` for an encrypted string.
    pub fn split(&self, str: &FheString, pat: &GenericPattern) -> Split {
        let num_blocks = 32 / ((((self.key.message_modulus().0) as f64).log2()) as usize);
        let max_counter = self.key.create_trivial_radix(str.bytes.len() as u32, num_blocks);

        Split {
            split_type: SplitType::SplitT,
            state: str.clone(),
            pat: pat.clone(),
            prev_was_some: self.key.create_trivial_boolean_block(true),
            counter: 0,
            max_counter,
            counter_lt_max: self.key.create_trivial_boolean_block(true),
        }
    }

    /// Creates an iterator of encrypted substrings by splitting the original encrypted string from the end
    /// based on a specified pattern (either encrypted or clear).
    ///
    /// The iterator, of type `Split`, can be used to sequentially retrieve the substrings in reverse order. Each
    /// call to `next` on the iterator returns a tuple with the next split substring as an encrypted
    /// string and a boolean indicating `Some` (true) or `None` (false).
    ///
    /// The pattern to search for can be specified as either `GenericPattern::Clear` for a clear
    /// string or `GenericPattern::Enc` for an encrypted string.
    pub fn rsplit(&self, str: &FheString, pat: &GenericPattern) -> Split {
        let num_blocks = 32 / ((((self.key.message_modulus().0) as f64).log2()) as usize);
        let max_counter = self.key.create_trivial_radix(str.bytes.len() as u32, num_blocks);

        Split {
            split_type: SplitType::RSplitT,
            state: str.clone(),
            pat: pat.clone(),
            prev_was_some: self.key.create_trivial_boolean_block(true),
            counter: 0,
            max_counter,
            counter_lt_max: self.key.create_trivial_boolean_block(true),
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
    fn test_split_once_non_occurred() {
        let (ck, sk) = generate_keys(PARAM_MESSAGE_2_CARRY_2.into());

        let (s, pat) = ("hel", "x");
        let fhe_s = FheString::encrypt(PlaintextString::new(s.to_string()), &ck);
        let fhe_pat = GenericPattern::Enc(FheString::encrypt(
            PlaintextString::new(pat.to_string()),
            &ck,
        ));
        let (lhs, rhs, split_occurred) = sk.split_once(&fhe_s, &fhe_pat);
        let lhs_decrypted = lhs.decrypt(&ck);
        let rhs_decrypted = rhs.decrypt(&ck);
        let split_occurred = ck.key.decrypt_bool(&split_occurred);
        assert_eq!(lhs_decrypted, "hel");
        assert_eq!(rhs_decrypted, "");
        assert!(!split_occurred);
    }

    #[test]
    fn test_split_once_occurred() {
        let (ck, sk) = generate_keys(PARAM_MESSAGE_2_CARRY_2.into());

        let (s, pat) = ("helelo", "el");
        let fhe_s = FheString::encrypt(PlaintextString::new(s.to_string()), &ck);
        let fhe_pat = GenericPattern::Enc(FheString::encrypt(
            PlaintextString::new(pat.to_string()),
            &ck,
        ));
        let (lhs, rhs, split_occurred) = sk.split_once(&fhe_s, &fhe_pat);
        let lhs_decrypted = lhs.decrypt(&ck);
        let rhs_decrypted = rhs.decrypt(&ck);
        let split_occurred = ck.key.decrypt_bool(&split_occurred);
        assert_eq!(lhs_decrypted, "h");
        assert_eq!(rhs_decrypted, "elo");
        assert!(split_occurred);
    }

    #[test]
    fn test_rsplit_once_non_occurred() {
        println!("{:?}", "hello".rfind(""));
        let (ck, sk) = generate_keys(PARAM_MESSAGE_2_CARRY_2.into());
        let (s, pat) = ("h", "xx");
        let fhe_s = FheString::encrypt(PlaintextString::new(s.to_string()), &ck);
        let fhe_pat = GenericPattern::Enc(FheString::encrypt(
            PlaintextString::new(pat.to_string()),
            &ck,
        ));
        let (lhs, rhs, split_occurred) = sk.rsplit_once(&fhe_s, &fhe_pat);
        let lhs_decrypted = lhs.decrypt(&ck);
        let rhs_decrypted = rhs.decrypt(&ck);
        let split_occurred = ck.key.decrypt_bool(&split_occurred);
        assert_eq!(lhs_decrypted, "h");
        assert_eq!(rhs_decrypted, "");
        assert!(!split_occurred);
    }

    #[test]
    fn test_rsplit_once_occurred() {
        let (ck, sk) = generate_keys(PARAM_MESSAGE_2_CARRY_2.into());

        let (s, pat) = ("helelo", "el");
        let fhe_s = FheString::encrypt(PlaintextString::new(s.to_string()), &ck);
        let fhe_pat = GenericPattern::Enc(FheString::encrypt(
            PlaintextString::new(pat.to_string()),
            &ck,
        ));
        let (lhs, rhs, split_occurred) = sk.rsplit_once(&fhe_s, &fhe_pat);
        let lhs_decrypted = lhs.decrypt(&ck);
        let rhs_decrypted = rhs.decrypt(&ck);
        let split_occurred = ck.key.decrypt_bool(&split_occurred);
        assert_eq!(lhs_decrypted, "hel");
        assert_eq!(rhs_decrypted, "o");
        assert!(split_occurred);
    }
}
