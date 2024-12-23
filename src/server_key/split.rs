use tfhe::integer::{prelude::ServerKeyDefaultCMux, BooleanBlock, RadixCiphertext};

use crate::{
    client_key::U16Arg,
    fhe_string::{FheString, GenericPattern},
};

use super::{FheStringIsEmpty, FheStringIterator, ServerKey};

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

pub struct SplitN {
    internal: Split,
    n: U16Arg,
    not_exceeded: BooleanBlock,
}

pub struct SplitNoTrailing {
    internal: Split,
}

pub struct SplitNoLeading {
    internal: Split,
    prev_return: (FheString, BooleanBlock),
    leading_empty_str: BooleanBlock,
}

impl FheStringIterator for Split {
    fn next(&mut self, sk: &ServerKey) -> (FheString, BooleanBlock) {
        let num_blocks = 32 / ((((sk.key.message_modulus().0) as f64).log2()) as usize);
        let trivial_or_enc_pat = match &self.pat {
            GenericPattern::Clear(pattern) => FheString::enc_trivial(&pattern.data, sk),
            GenericPattern::Enc(pattern) => pattern.clone(),
        };
        let ((mut idx, mut is_some), pat_is_empty) = rayon::join(
            || {
                if let SplitType::RSplitT = self.split_type {
                    sk.rfind(&self.state, &self.pat)
                } else {
                    sk.find(&self.state, &self.pat)
                }
            },
            || match sk.is_empty(&trivial_or_enc_pat) {
                FheStringIsEmpty::Padding(enc) => enc.into_radix(num_blocks, &sk.key),
                FheStringIsEmpty::NoPadding(clear) => sk.key.create_trivial_radix(clear as u32, num_blocks),
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
        sk.key
            .boolean_bitor_assign(&mut is_some, &self.prev_was_some);
        // If pattern is empty, `is_found` is always true, so we make it false when we have reached the
        // last possible counter value
        sk.key
            .boolean_bitand_assign(&mut is_some, &self.counter_le_max);
        self.prev_was_some = curr_is_some;
        self.counter_le_max = sk
            .key
            .scalar_ge_parallelized(&self.max_counter, self.counter);
        self.counter += 1;
        (res, is_some)
    }
}

impl FheStringIterator for SplitNoTrailing {
    fn next(&mut self, sk: &ServerKey) -> (FheString, BooleanBlock) {
        let (res, mut is_some) = self.internal.next(sk);
        // It's possible that the returned value is Some but it's wrapping the remaining state
        // (if prev_was_some is false). If this is the case and we have a trailing empty
        // string, we return None to remove it.
        let (res_is_empty, prev_was_none) = rayon::join(
            || match sk.is_empty(&res) {
                FheStringIsEmpty::Padding(enc) => enc,
                FheStringIsEmpty::NoPadding(clear) => sk.key.create_trivial_boolean_block(clear),
            },
            || sk.key.boolean_bitnot(&self.internal.prev_was_some),
        );
        let trailing_empty = sk.key.boolean_bitand(&res_is_empty, &prev_was_none);
        let not_trailling_empty = sk.key.boolean_bitnot(&trailing_empty);
        // If there's no empty trailing string we get the previous `is_some`,
        // else we get false (None)
        sk.key
            .boolean_bitand_assign(&mut is_some, &not_trailling_empty);
        (res, is_some)
    }
}

impl FheStringIterator for SplitNoLeading {
    fn next(&mut self, sk: &ServerKey) -> (FheString, BooleanBlock) {
        // Note that self.internal.next() has been called once in the `rsplit_terminator` function.
        let (res, is_some) = self.internal.next(sk);
        let (return_res, return_is_some) = rayon::join(
            || sk.conditional_fhestring(&self.leading_empty_str, &res, &self.prev_return.0),
            || {
                sk.key.if_then_else_parallelized(
                    &self.leading_empty_str,
                    &is_some,
                    &self.prev_return.1,
                )
            },
        );
        self.prev_return = (res, is_some);
        (return_res, return_is_some)
    }
}

impl FheStringIterator for SplitN {
    fn next(&mut self, sk: &ServerKey) -> (FheString, BooleanBlock) {
        let state = self.internal.state.clone();
        let (mut res, mut is_some) = self.internal.next(sk);
        // This keeps the original `is_some` value unless we have exceeded n
        sk.key
            .boolean_bitand_assign(&mut is_some, &self.not_exceeded);

        match &self.n {
            U16Arg::Clear(n) => {
                // The moment counter is at least one less than n, we return the remaining state
                // and set `not_exceeded` to false.
                if self.internal.counter >= *n {
                    res = state;
                    self.not_exceeded = sk.key.create_trivial_boolean_block(false);
                }
            }
            U16Arg::Enc(n) => {
                let cur_not_exceeded = sk
                    .key
                    .scalar_gt_parallelized(&n.cipher, self.internal.counter);
                rayon::join(
                    || res = sk.conditional_fhestring(&cur_not_exceeded, &res, &state),
                    || {
                        sk.key
                            .boolean_bitand_assign(&mut self.not_exceeded, &cur_not_exceeded)
                    },
                );
            }
        }
        (res, is_some)
    }
}

impl ServerKey {
    fn split_pattern_at_index(
        &self,
        str: &FheString,
        pattern: &GenericPattern,
        idx: RadixCiphertext,
        inclusive: bool,
    ) -> (FheString, FheString) {
        let num_blocks = 32 / ((((self.key.message_modulus().0) as f64).log2()) as usize);
        let str_len = self
            .key
            .create_trivial_radix(str.bytes.len() as u32, num_blocks);
        // lhs = str[:idx], pattern = str[idx:idx+pattern_len], rhs = str[idx+pattern_len:]
        let (mut shift_right, pattern_len) = rayon::join(
            || self.key.sub_parallelized(&str_len, &idx),
            || {
                let pattern_len = match pattern {
                    GenericPattern::Clear(s) => s.len(),
                    GenericPattern::Enc(s) => s.bytes.len(),
                };
                self.key
                    .create_trivial_radix(pattern_len as u32, num_blocks)
            },
        );
        rayon::join(
            || {
                if inclusive {
                    // pattern is included in lhs
                    self.key
                        .sub_assign_parallelized(&mut shift_right, &pattern_len);
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
        let max_counter = self
            .key
            .create_trivial_radix(str.bytes.len() as u32, num_blocks);

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
        let max_counter = self
            .key
            .create_trivial_radix(str.bytes.len() as u32, num_blocks);

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

    /// Creates an iterator of encrypted substrings by splitting the original encrypted string based
    /// on a specified pattern (either encrypted or clear), where each substring includes the
    /// delimiter. If the string ends with the delimiter, it does not create a trailing empty
    /// substring.
    ///
    /// The iterator, of type `SplitInclusive`, can be used to sequentially retrieve the substrings.
    /// Each call to `next` on the iterator returns a tuple with the next split substring as an
    /// encrypted string and a boolean indicating `Some` (true) or `None` (false).
    ///
    /// The pattern to search for can be specified as either `GenericPattern::Clear` for a clear
    /// string or `GenericPattern::Enc` for an encrypted string.
    /// "".split_inclusive("x").collect() yields []
    /// "hel".split_inclusive("").collect() yields ["", "h", "e", "l"]
    pub fn split_inclusive(&self, str: &FheString, pat: &GenericPattern) -> SplitNoTrailing {
        let num_blocks = 32 / ((((self.key.message_modulus().0) as f64).log2()) as usize);
        let max_counter = self
            .key
            .create_trivial_radix(str.bytes.len() as u32, num_blocks);

        SplitNoTrailing {
            internal: Split {
                split_type: SplitType::SplitInclusiveT,
                state: str.clone(),
                pat: pat.clone(),
                prev_was_some: self.key.create_trivial_boolean_block(true),
                counter: 0,
                max_counter,
                counter_le_max: self.key.create_trivial_boolean_block(true),
            },
        }
    }

    /// Creates an iterator of encrypted substrings by splitting the original encrypted string based
    /// on a specified pattern (either encrypted or clear), excluding trailing empty substrings.
    ///
    /// The iterator, of type `SplitTerminator`, can be used to sequentially retrieve the
    /// substrings. Each call to `next` on the iterator returns a tuple with the next split
    /// substring as an encrypted string and a boolean indicating `Some` (true) or `None` (false).
    ///
    /// The pattern to search for can be specified as either `GenericPattern::Clear` for a clear
    /// string or `GenericPattern::Enc` for an encrypted string.
    /// " hel w ".split_terminator(" ") yields ["", "hel", "w"]
    pub fn split_terminator(&self, str: &FheString, pat: &GenericPattern) -> SplitNoTrailing {
        let num_blocks = 32 / ((((self.key.message_modulus().0) as f64).log2()) as usize);
        let max_counter = self
            .key
            .create_trivial_radix(str.bytes.len() as u32, num_blocks);

        SplitNoTrailing {
            internal: Split {
                split_type: SplitType::SplitT,
                state: str.clone(),
                pat: pat.clone(),
                prev_was_some: self.key.create_trivial_boolean_block(true),
                counter: 0,
                max_counter,
                counter_le_max: self.key.create_trivial_boolean_block(true),
            },
        }
    }

    /// Creates an iterator of encrypted substrings by splitting the original encrypted string from
    /// the end based on a specified pattern (either encrypted or clear), excluding leading empty
    /// substrings in the reverse order.
    ///
    /// The iterator, of type `RSplitTerminator`, can be used to sequentially retrieve the
    /// substrings in reverse order, ignoring any leading empty substring that would result from
    /// splitting at the end of the string. Each call to `next` on the iterator returns a tuple with
    /// the next split substring as an encrypted string and a boolean indicating `Some` (true) or
    /// `None` (false).
    ///
    /// The pattern to search for can be specified as either `GenericPattern::Clear` for a clear
    /// string or `GenericPattern::Enc` for an encrypted string.
    /// " hel w ".rsplit_terminator(" ") yields ["w", "hel", ""]
    pub fn rsplit_terminator(&self, str: &FheString, pat: &GenericPattern) -> SplitNoLeading {
        let mut internal = self.rsplit(str, pat);
        let prev_return = internal.next(self);
        let leading_empty_str = match self.is_empty(&prev_return.0) {
            FheStringIsEmpty::Padding(enc) => enc,
            FheStringIsEmpty::NoPadding(clear) => self.key.create_trivial_boolean_block(clear),
        };
        SplitNoLeading {
            internal,
            prev_return,
            leading_empty_str,
        }
    }

    fn splitn_internal(
        &self,
        str: &FheString,
        pat: &GenericPattern,
        n: &U16Arg,
        split_type: SplitType,
    ) -> SplitN {
        let n_not_0 = match n {
            U16Arg::Clear(n) => self.key.create_trivial_boolean_block(*n != 0),
            U16Arg::Enc(n) => self.key.scalar_ne_parallelized(&n.cipher, 0),
        };

        let num_blocks = 32 / ((((self.key.message_modulus().0) as f64).log2()) as usize);
        let max_counter = self
            .key
            .create_trivial_radix(str.bytes.len() as u32, num_blocks);
        let internal = Split {
            split_type,
            state: str.clone(),
            pat: pat.clone(),
            prev_was_some: self.key.create_trivial_boolean_block(true),
            counter: 0,
            max_counter,
            counter_le_max: self.key.create_trivial_boolean_block(true),
        };
        SplitN {
            internal,
            n: n.clone(),
            not_exceeded: n_not_0,
        }
    }

    /// Creates an iterator of encrypted substrings by splitting the original encrypted string based
    /// on a specified pattern (either encrypted or clear), limited to at most `n` results.
    ///
    /// The `n` is specified by a `U16Arg`, which can be either `Clear` or `Enc`. The iterator, of
    /// type `SplitN`, can be used to sequentially retrieve the substrings. Each call to `next` on
    /// the iterator returns a tuple with the next split substring as an encrypted string and a
    /// boolean indicating `Some` (true) or `None` (false).
    ///
    /// The pattern to search for can be specified as either `GenericPattern::Clear` for a clear
    /// string or `GenericPattern::Enc` for an encrypted string.
    pub fn splitn(&self, str: &FheString, pat: &GenericPattern, n: &U16Arg) -> SplitN {
        self.splitn_internal(str, pat, n, SplitType::SplitT)
    }

    /// Creates an iterator of encrypted substrings by splitting the original encrypted string from
    /// the end based on a specified pattern (either encrypted or clear), limited to at most `n`
    /// results.
    ///
    /// The `n` is specified by a `U16Arg`, which can be either `Clear` or `Enc`. The iterator, of
    /// type `RSplitN`, can be used to sequentially retrieve the substrings in reverse order. Each
    /// call to `next` on the iterator returns a tuple with the next split substring as an encrypted
    /// string and a boolean indicating `Some` (true) or `None` (false).
    ///
    /// The pattern to search for can be specified as either `GenericPattern::Clear` for a clear
    /// string or `GenericPattern::Enc` for an encrypted string.
    pub fn rsplitn(&self, str: &FheString, pat: &GenericPattern, n: &U16Arg) -> SplitN {
        self.splitn_internal(str, pat, n, SplitType::RSplitT)
    }
}

#[cfg(test)]
mod tests {
    use tfhe::shortint::prelude::PARAM_MESSAGE_2_CARRY_2;

    use crate::{
        client_key::U16Arg,
        fhe_string::{GenericPattern, PlaintextString},
        generate_keys,
        server_key::FheStringIterator,
    };

    #[test]
    fn test_split_once_non_occurred() {
        let (ck, sk) = generate_keys(PARAM_MESSAGE_2_CARRY_2);

        let (s, pat) = ("hel", "x");
        let fhe_s = ck.enc_str(s, 0);
        let fhe_pat = GenericPattern::Enc(ck.enc_str(pat, 0));
        let (lhs, rhs, split_occurred) = sk.split_once(&fhe_s, &fhe_pat);
        let lhs_decrypted = ck.dec_str(&lhs);
        let rhs_decrypted = ck.dec_str(&rhs);
        let split_occurred = ck.key.decrypt_bool(&split_occurred);
        assert_eq!(lhs_decrypted, "hel");
        assert_eq!(rhs_decrypted, "");
        assert!(!split_occurred);
    }

    #[test]
    fn test_split_once_occurred() {
        let (ck, sk) = generate_keys(PARAM_MESSAGE_2_CARRY_2);

        let (s, pat) = ("helelo", "el");
        let fhe_s = ck.enc_str(s, 0);
        let fhe_pat = GenericPattern::Enc(ck.enc_str(pat, 0));
        let (lhs, rhs, split_occurred) = sk.split_once(&fhe_s, &fhe_pat);
        let lhs_decrypted = ck.dec_str(&lhs);
        let rhs_decrypted = ck.dec_str(&rhs);
        let split_occurred = ck.key.decrypt_bool(&split_occurred);
        assert_eq!(lhs_decrypted, "h");
        assert_eq!(rhs_decrypted, "elo");
        assert!(split_occurred);
    }

    #[test]
    fn test_rsplit_once_non_occurred() {
        let (ck, sk) = generate_keys(PARAM_MESSAGE_2_CARRY_2);
        let (s, pat) = ("h", "xx");
        let fhe_s = ck.enc_str(s, 0);
        let fhe_pat = GenericPattern::Enc(ck.enc_str(pat, 0));
        let (lhs, rhs, split_occurred) = sk.rsplit_once(&fhe_s, &fhe_pat);
        let lhs_decrypted = ck.dec_str(&lhs);
        let rhs_decrypted = ck.dec_str(&rhs);
        let split_occurred = ck.key.decrypt_bool(&split_occurred);
        assert_eq!(lhs_decrypted, "h");
        assert_eq!(rhs_decrypted, "");
        assert!(!split_occurred);
    }

    #[test]
    fn test_rsplit_once_occurred() {
        let (ck, sk) = generate_keys(PARAM_MESSAGE_2_CARRY_2);

        let (s, pat) = ("helelo", "el");
        let fhe_s = ck.enc_str(s, 0);
        let fhe_pat = GenericPattern::Enc(ck.enc_str(pat, 0));
        let (lhs, rhs, split_occurred) = sk.rsplit_once(&fhe_s, &fhe_pat);
        let lhs_decrypted = ck.dec_str(&lhs);
        let rhs_decrypted = ck.dec_str(&rhs);
        let split_occurred = ck.key.decrypt_bool(&split_occurred);
        assert_eq!(lhs_decrypted, "hel");
        assert_eq!(rhs_decrypted, "o");
        assert!(split_occurred);
    }

    #[test]
    fn test_split_with_empty_pattern() {
        let (ck, sk) = generate_keys(PARAM_MESSAGE_2_CARRY_2);

        // ["", "h", "e", "l", ""]
        let (s, pat) = ("hel", "");
        let fhe_s = ck.enc_str(s, 0);
        let fhe_pat = GenericPattern::Enc(ck.enc_str(pat, 0));
        let mut split_iter = sk.split(&fhe_s, &fhe_pat);

        let (enc_first_item, enc_first_is_some) = split_iter.next(&sk);
        let first_item = ck.dec_str(&enc_first_item);
        let first_is_some = ck.key.decrypt_bool(&enc_first_is_some);
        assert_eq!(first_item.as_str(), "");
        assert!(first_is_some);

        let (enc_second_item, enc_second_is_some) = split_iter.next(&sk);
        let second_item = ck.dec_str(&enc_second_item);
        let second_is_some = ck.key.decrypt_bool(&enc_second_is_some);
        assert_eq!(second_item.as_str(), "h");
        assert!(second_is_some);

        let (enc_third_item, enc_third_is_some) = split_iter.next(&sk);
        let third_item = ck.dec_str(&enc_third_item);
        let third_is_some = ck.key.decrypt_bool(&enc_third_is_some);
        assert_eq!(third_item.as_str(), "e");
        assert!(third_is_some);

        let (enc_fourth_item, enc_fourth_is_some) = split_iter.next(&sk);
        let fourth_item = ck.dec_str(&enc_fourth_item);
        let fourth_is_some = ck.key.decrypt_bool(&enc_fourth_is_some);
        assert_eq!(fourth_item.as_str(), "l");
        assert!(fourth_is_some);

        let (enc_fifth_item, enc_fifth_is_some) = split_iter.next(&sk);
        let fifth_item = ck.dec_str(&enc_fifth_item);
        let fifth_is_some = ck.key.decrypt_bool(&enc_fifth_is_some);
        assert_eq!(fifth_item.as_str(), "");
        assert!(fifth_is_some);

        let (enc_sixth_item, enc_sixth_is_some) = split_iter.next(&sk);
        let sixth_item = ck.dec_str(&enc_sixth_item);
        let sixth_is_some = ck.key.decrypt_bool(&enc_sixth_is_some);
        assert_eq!(sixth_item.as_str(), "");
        assert!(!sixth_is_some);
    }

    #[test]
    fn test_split_with_nonempty_pattern() {
        let (ck, sk) = generate_keys(PARAM_MESSAGE_2_CARRY_2);

        // ["hel", ""]
        let (s, pat) = ("hel ", " ");
        let fhe_s = ck.enc_str(s, 0);
        let fhe_pat = GenericPattern::Clear(PlaintextString::new(pat.to_string()));
        let mut split_iter = sk.split(&fhe_s, &fhe_pat);

        let (enc_first_item, enc_first_is_some) = split_iter.next(&sk);
        let first_item = ck.dec_str(&enc_first_item);
        let first_is_some = ck.key.decrypt_bool(&enc_first_is_some);
        assert_eq!(first_item.as_str(), "hel");
        assert!(first_is_some);

        let (enc_second_item, enc_second_is_some) = split_iter.next(&sk);
        let second_item = ck.dec_str(&enc_second_item);
        let second_is_some = ck.key.decrypt_bool(&enc_second_is_some);
        assert_eq!(second_item.as_str(), "");
        assert!(second_is_some);

        let (enc_third_item, enc_third_is_some) = split_iter.next(&sk);
        let third_item = ck.dec_str(&enc_third_item);
        let third_is_some = ck.key.decrypt_bool(&enc_third_is_some);
        assert_eq!(third_item.as_str(), "");
        assert!(!third_is_some);
    }

    #[test]
    fn test_split_inclusive() {
        let (ck, sk) = generate_keys(PARAM_MESSAGE_2_CARRY_2);

        let (s, pat) = ("h el ", " ");
        let fhe_s = ck.enc_str(s, 0);
        let fhe_pat = GenericPattern::Clear(PlaintextString::new(pat.to_string()));
        let mut iter = sk.split_inclusive(&fhe_s, &fhe_pat);

        let (enc_first_item, enc_first_is_some) = iter.next(&sk);
        let first_item = ck.dec_str(&enc_first_item);
        let first_is_some = ck.key.decrypt_bool(&enc_first_is_some);
        assert_eq!(first_item.as_str(), "h ");
        assert!(first_is_some);

        let (enc_second_item, enc_second_is_some) = iter.next(&sk);
        let second_item = ck.dec_str(&enc_second_item);
        let second_is_some = ck.key.decrypt_bool(&enc_second_is_some);
        assert_eq!(second_item.as_str(), "el ");
        assert!(second_is_some);

        let (_, enc_third_is_some) = iter.next(&sk);
        let third_is_some = ck.key.decrypt_bool(&enc_third_is_some);
        assert!(!third_is_some);
    }

    #[test]
    fn test_split_terminator() {
        let (ck, sk) = generate_keys(PARAM_MESSAGE_2_CARRY_2);

        let (s, pat) = (" h el ", " ");
        let fhe_s = ck.enc_str(s, 0);
        let fhe_pat = GenericPattern::Clear(PlaintextString::new(pat.to_string()));
        let mut iter = sk.split_terminator(&fhe_s, &fhe_pat);

        let (enc_first_item, enc_first_is_some) = iter.next(&sk);
        let first_item = ck.dec_str(&enc_first_item);
        let first_is_some = ck.key.decrypt_bool(&enc_first_is_some);
        assert_eq!(first_item.as_str(), "");
        assert!(first_is_some);

        let (enc_second_item, enc_second_is_some) = iter.next(&sk);
        let second_item = ck.dec_str(&enc_second_item);
        let second_is_some = ck.key.decrypt_bool(&enc_second_is_some);
        assert_eq!(second_item.as_str(), "h");
        assert!(second_is_some);

        let (enc_third_item, enc_third_is_some) = iter.next(&sk);
        let third_item = ck.dec_str(&enc_third_item);
        let third_is_some = ck.key.decrypt_bool(&enc_third_is_some);
        assert_eq!(third_item.as_str(), "el");
        assert!(third_is_some);

        let (_, enc_fourth_is_some) = iter.next(&sk);
        let fourth_is_some = ck.key.decrypt_bool(&enc_fourth_is_some);
        assert!(!fourth_is_some);
    }

    #[test]
    fn test_rsplit_terminator() {
        let (ck, sk) = generate_keys(PARAM_MESSAGE_2_CARRY_2);

        let (s, pat) = (" h el ", " ");
        let fhe_s = ck.enc_str(s, 0);
        let fhe_pat = GenericPattern::Clear(PlaintextString::new(pat.to_string()));
        let mut iter = sk.rsplit_terminator(&fhe_s, &fhe_pat);

        let (enc_first_item, enc_first_is_some) = iter.next(&sk);
        let first_item = ck.dec_str(&enc_first_item);
        let first_is_some = ck.key.decrypt_bool(&enc_first_is_some);
        assert_eq!(first_item.as_str(), "el");
        assert!(first_is_some);

        let (enc_second_item, enc_second_is_some) = iter.next(&sk);
        let second_item = ck.dec_str(&enc_second_item);
        let second_is_some = ck.key.decrypt_bool(&enc_second_is_some);
        assert_eq!(second_item.as_str(), "h");
        assert!(second_is_some);

        let (enc_third_item, enc_third_is_some) = iter.next(&sk);
        let third_item = ck.dec_str(&enc_third_item);
        let third_is_some = ck.key.decrypt_bool(&enc_third_is_some);
        assert_eq!(third_item.as_str(), "");
        assert!(third_is_some);

        let (_, enc_fourth_is_some) = iter.next(&sk);
        let fourth_is_some = ck.key.decrypt_bool(&enc_fourth_is_some);
        assert!(!fourth_is_some);
    }

    #[test]
    fn test_splitn() {
        let (ck, sk) = generate_keys(PARAM_MESSAGE_2_CARRY_2);

        let (s, pat) = ("h el", " ");
        let fhe_s = ck.enc_str(s, 0);
        let fhe_pat = GenericPattern::Clear(PlaintextString::new(pat.to_string()));

        let n = U16Arg::Clear(1);
        let mut iter = sk.splitn(&fhe_s, &fhe_pat, &n);
        let (enc_first_item, enc_first_is_some) = iter.next(&sk);
        let first_item = ck.dec_str(&enc_first_item);
        let first_is_some = ck.key.decrypt_bool(&enc_first_is_some);
        assert_eq!(first_item.as_str(), "h el");
        assert!(first_is_some);
        let (_, enc_second_is_some) = iter.next(&sk);
        let second_is_some = ck.key.decrypt_bool(&enc_second_is_some);
        assert!(!second_is_some);

        let n = U16Arg::Enc(ck.encrypt_u16(2, Some(3)));
        let mut iter = sk.splitn(&fhe_s, &fhe_pat, &n);
        let (enc_first_item, enc_first_is_some) = iter.next(&sk);
        let first_item = ck.dec_str(&enc_first_item);
        let first_is_some = ck.key.decrypt_bool(&enc_first_is_some);
        assert_eq!(first_item.as_str(), "h");
        assert!(first_is_some);

        let (enc_second_item, enc_second_is_some) = iter.next(&sk);
        let second_item = ck.dec_str(&enc_second_item);
        let second_is_some = ck.key.decrypt_bool(&enc_second_is_some);
        assert_eq!(second_item.as_str(), "el");
        assert!(!second_is_some);
        let (_, enc_third_is_some) = iter.next(&sk);
        let third_is_some = ck.key.decrypt_bool(&enc_third_is_some);
        assert!(!third_is_some);
    }

    #[test]
    fn test_rsplitn() {
        let (ck, sk) = generate_keys(PARAM_MESSAGE_2_CARRY_2);

        let (s, pat) = ("h el", " ");
        let fhe_s = ck.enc_str(s, 0);
        let fhe_pat = GenericPattern::Clear(PlaintextString::new(pat.to_string()));
        let n = U16Arg::Enc(ck.encrypt_u16(2, Some(3)));
        let mut iter = sk.rsplitn(&fhe_s, &fhe_pat, &n);

        let (enc_first_item, enc_first_is_some) = iter.next(&sk);
        let first_item = ck.dec_str(&enc_first_item);
        let first_is_some = ck.key.decrypt_bool(&enc_first_is_some);
        assert_eq!(first_item.as_str(), "el");
        assert!(first_is_some);

        let (enc_second_item, enc_second_is_some) = iter.next(&sk);
        let second_item = ck.dec_str(&enc_second_item);
        let second_is_some = ck.key.decrypt_bool(&enc_second_is_some);
        assert_eq!(second_item.as_str(), "h");
        assert!(!second_is_some);

        let (_, enc_third_is_some) = iter.next(&sk);
        let third_is_some = ck.key.decrypt_bool(&enc_third_is_some);
        assert!(!third_is_some);
    }
}
