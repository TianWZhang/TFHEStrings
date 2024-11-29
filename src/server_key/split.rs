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
    counter_le_max: BooleanBlock,
}

impl FheStringIterator for Split {
    fn next(&mut self, sk: &ServerKey) -> (FheString, BooleanBlock) {
        let num_blocks = 32 / ((((sk.key.message_modulus().0) as f64).log2()) as usize);
        let ((mut idx, mut is_some), pat_is_empty) = rayon::join(
            || {
                if let SplitType::RSplitT = self.split_type {
                    sk.rfind(&self.state, &self.pat)
                } else {
                    sk.find(&self.state, &self.pat)
                }
            }, 
            || match &self.pat {
                GenericPattern::Clear(s) => sk.key.create_trivial_radix(s.data.is_empty() as u32, num_blocks),
                GenericPattern::Enc(s) => sk.is_empty(s).into_radix(num_blocks, &sk.key)
            },
        );

        if self.counter > 0 {
            // If pattern is empty and we aren't in the first next call, we add (in the Split case)
            // or subtract (in the RSplit case) 1 to the index at which we split the str.
            //
            // This is because "ab".split("") returns ["", "a", "b", ""] and, in our case, we have
            // to manually advance the match index as an empty pattern always matches at the very
            // start (or end in the rsplit case)
            if let SplitType::RSplitT = self.split_type {
                sk.key.sub_assign_parallelized(&mut idx, &pat_is_empty);
            } else {
                sk.key.add_assign_parallelized(&mut idx, &pat_is_empty);
            }
        }

        let (lhs, rhs) = if let SplitType::SplitInclusiveT = self.split_type {
            sk.split_pattern_at_index(&self.state, &self.pat, idx, true)
        } else {
            sk.split_pattern_at_index(&self.state, &self.pat, idx, false)
        };

        let res = if let SplitType::RSplitT = self.split_type {
            let res = sk.conditional_fhestring(&is_some, &rhs, &self.state);
            self.state = sk.conditional_fhestring(&is_some, &lhs, &FheString::empty());
            res
        } else {
            self.state = rhs;
            lhs
        };

        let curr_is_some = is_some.clone();
        // Even if there isn't match, we return Some if there was a match in the previous `next` call,
        // as we are returning the remaining state wrapped in Some
        sk.key.boolean_bitor_assign(&mut is_some, &self.prev_was_some);
        // If pattern is empty, `is_found` is always true, so we make it false when we have reached the 
        // last possible counter value
        sk.key.boolean_bitand_assign(&mut is_some, &self.counter_le_max);
        self.prev_was_some = curr_is_some;
        self.counter_le_max = sk.key.scalar_ge_parallelized( &self.max_counter, self.counter);
        self.counter += 1; 
        (res, is_some)
    }
}

impl ServerKey {
    fn split_pattern_at_index(
        &self,
        str: &FheString,
        pattern: &GenericPattern,
        idx: RadixCiphertext,
        inclusive: bool
    ) -> (FheString, FheString) {
        let num_blocks = 32 / ((((self.key.message_modulus().0) as f64).log2()) as usize);
        let str_len = self.key.create_trivial_radix(
            str.bytes.len() as u32,
            num_blocks,
        );
        // lhs = str[:idx], pattern = str[idx:idx+pattern_len], rhs = str[idx+pattern_len:]
        let (mut shift_right, pattern_len) = rayon::join(
            || self.key.sub_parallelized(&str_len, &idx),
            || {
                let pattern_len = match pattern {
                    GenericPattern::Clear(s) => s.len(),
                    GenericPattern::Enc(s) => s.bytes.len(),
                };
                self.key.create_trivial_radix(
                    pattern_len as u32,
                    num_blocks,
                )
            },
        );
        rayon::join(
            || {
                if inclusive { // pattern is included in lhs
                    self.key.sub_assign_parallelized(&mut shift_right, &pattern_len);
                }
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
        let (lhs, rhs) = self.split_pattern_at_index(str, pat, enc_idx, false);
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
        let (lhs, rhs) = self.split_pattern_at_index(str, pat, enc_idx, false);
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
            counter_le_max: self.key.create_trivial_boolean_block(true),
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
            counter_le_max: self.key.create_trivial_boolean_block(true),
        }
    }
}

#[cfg(test)]
mod tests {
    use tfhe::shortint::prelude::PARAM_MESSAGE_2_CARRY_2;

    use crate::{
        fhe_string::{FheString, GenericPattern, PlaintextString},
        generate_keys, server_key::FheStringIterator,
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

    #[test]
    fn test_split_with_empty_pattern() {
        let (ck, sk) = generate_keys(PARAM_MESSAGE_2_CARRY_2.into());

        // ["", "h", "e", "l", ""]
        let (s, pat) = ("hel", "");

        let fhe_s = FheString::encrypt(PlaintextString::new(s.to_string()), &ck);
        let fhe_pat = GenericPattern::Enc(FheString::encrypt(
            PlaintextString::new(pat.to_string()),
            &ck,
        ));
        let mut split_iter = sk.split(&fhe_s, &fhe_pat);

        let (enc_first_item, enc_first_is_some) = split_iter.next(&sk);
        let first_item = enc_first_item.decrypt(&ck);
        let first_is_some = ck.key.decrypt_bool(&enc_first_is_some);
        assert_eq!(first_item.as_str(), "");
        assert!(first_is_some);

        let (enc_second_item, enc_second_is_some) = split_iter.next(&sk);
        let second_item = enc_second_item.decrypt(&ck);
        let second_is_some = ck.key.decrypt_bool(&enc_second_is_some);
        assert_eq!(second_item.as_str(), "h");
        assert!(second_is_some);

        let (enc_third_item, enc_third_is_some) = split_iter.next(&sk);
        let third_item = enc_third_item.decrypt(&ck);
        let third_is_some = ck.key.decrypt_bool(&enc_third_is_some);
        assert_eq!(third_item.as_str(), "e");
        assert!(third_is_some);

        let (enc_fourth_item, enc_fourth_is_some) = split_iter.next(&sk);
        let fourth_item = enc_fourth_item.decrypt(&ck);
        let fourth_is_some = ck.key.decrypt_bool(&enc_fourth_is_some);
        assert_eq!(fourth_item.as_str(), "l");
        assert!(fourth_is_some);

        let (enc_fifth_item, enc_fifth_is_some) = split_iter.next(&sk);
        let fifth_item = enc_fifth_item.decrypt(&ck);
        let fifth_is_some = ck.key.decrypt_bool(&enc_fifth_is_some);
        assert_eq!(fifth_item.as_str(), "");
        assert!(fifth_is_some);

        let (enc_sixth_item, enc_sixth_is_some) = split_iter.next(&sk);
        let sixth_item = enc_sixth_item.decrypt(&ck);
        let sixth_is_some = ck.key.decrypt_bool(&enc_sixth_is_some);
        assert_eq!(sixth_item.as_str(), "");
        assert!(!sixth_is_some);
    }


    #[test]
    fn test_split_with_nonempty_pattern() {
        let (ck, sk) = generate_keys(PARAM_MESSAGE_2_CARRY_2.into());

        // ["hel", ""]
        let (s, pat) = ("hel ", " ");
        let fhe_s = FheString::encrypt(PlaintextString::new(s.to_string()), &ck);
        let fhe_pat = GenericPattern::Clear(PlaintextString::new(pat.to_string()));
        let mut split_iter = sk.split(&fhe_s, &fhe_pat);

        let (enc_first_item, enc_first_is_some) = split_iter.next(&sk);
        let first_item = enc_first_item.decrypt(&ck);
        let first_is_some = ck.key.decrypt_bool(&enc_first_is_some);
        assert_eq!(first_item.as_str(), "hel");
        assert!(first_is_some);

        let (enc_second_item, enc_second_is_some) = split_iter.next(&sk);
        let second_item = enc_second_item.decrypt(&ck);
        let second_is_some = ck.key.decrypt_bool(&enc_second_is_some);
        assert_eq!(second_item.as_str(), "");
        assert!(second_is_some);

        let (enc_third_item, enc_third_is_some) = split_iter.next(&sk);
        let third_item = enc_third_item.decrypt(&ck);
        let third_is_some = ck.key.decrypt_bool(&enc_third_is_some);
        assert_eq!(third_item.as_str(), "");
        assert!(!third_is_some);
    }
}
