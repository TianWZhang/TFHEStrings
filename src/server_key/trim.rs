use rayon::iter::{ParallelBridge, ParallelIterator};
use tfhe::integer::{prelude::ServerKeyDefaultCMux, BooleanBlock, RadixCiphertext};

use crate::fhe_string::{FheString, NUM_BLOCKS};

use super::{FheStringIterator, ServerKey};

pub struct SplitAsciiWhitespace {
    state: FheString,
}

impl FheStringIterator for SplitAsciiWhitespace {
    fn next(&mut self, sk: &ServerKey) -> FheString {
        let str_len = self.state.bytes.len();
        if str_len == 0 || (self.state.padded && str_len == 1) {
            return FheString::empty();
        }

        // create the mask
        let mut mask = self.state.clone();
        let mut prev_is_ws = sk.key.create_trivial_boolean_block(false);
        for enc_c in &mut mask.bytes {
            let mut is_ws = sk.is_whitespace(enc_c, false);
            sk.key.boolean_bitor_assign(&mut is_ws, &prev_is_ws);
            let mut is_ws_u8 = is_ws.clone().into_radix(NUM_BLOCKS, &sk.key);
            // if is_ws_u8 is an encryption of 1, then we set the mask to 0
            // if is_ws_u8 is an encryption of 0, then we set the mask to 255u8
            sk.key.scalar_sub_assign_parallelized(&mut is_ws_u8, 1);
            *enc_c = is_ws_u8;
            prev_is_ws = is_ws;
        }

        // apply the mask to obtain the next item
        // Inplace operation is necessary here, otherwise parallel iterator will not guarantee the order of
        // the elements in the resulting vector.
        let mut enc_item_bytes = self.state.clone().bytes;
        enc_item_bytes
            .iter_mut()
            .zip(mask.bytes.iter())
            .par_bridge()
            .for_each(|(enc_c, mask_u8)| sk.key.bitand_assign_parallelized(enc_c, mask_u8));
        let enc_item = FheString {
            bytes: enc_item_bytes,
            padded: self.state.padded,
        };

        // update state
        // item_len is `u32`
        let mut enc_item_len = sk.key.create_trivial_zero_radix(
            32 / ((((sk.key.message_modulus().0) as f64).log2()) as usize),
        );
        for enc_c in &mask.bytes {
            let not_zero = sk.key.scalar_ne_parallelized(enc_c, 0u8);
            sk.key
                .add_assign_parallelized(&mut enc_item_len, &not_zero.into_radix(1, &sk.key));
        }
        let state_shift = sk.left_shift_chars(&self.state, &enc_item_len);
        self.state = sk.trim_start(&state_shift);
        enc_item
    }
}

impl ServerKey {
    fn is_whitespace(&self, c: &RadixCiphertext, or_null: bool) -> BooleanBlock {
        let mut is_space = self.key.create_trivial_boolean_block(false);
        let mut is_tab = self.key.create_trivial_boolean_block(false);
        let mut is_newline = self.key.create_trivial_boolean_block(false);
        let mut is_formfeed = self.key.create_trivial_boolean_block(false);
        let mut is_carriage_return = self.key.create_trivial_boolean_block(false);
        let mut op_is_null = None;
        rayon::scope(|s| {
            s.spawn(|_| {
                is_space = self.key.scalar_eq_parallelized(c, 0x20u8);
            });
            s.spawn(|_| {
                is_tab = self.key.scalar_eq_parallelized(c, 0x09u8);
            });
            s.spawn(|_| {
                is_newline = self.key.scalar_eq_parallelized(c, 0x0Au8);
            });
            s.spawn(|_| {
                is_formfeed = self.key.scalar_eq_parallelized(c, 0x0Cu8);
            });
            s.spawn(|_| {
                is_carriage_return = self.key.scalar_eq_parallelized(c, 0x0Du8);
            });
            s.spawn(|_| {
                op_is_null = or_null.then_some(self.key.scalar_eq_parallelized(c, 0u8));
            });
        });

        let mut res = self.key.boolean_bitor(&is_space, &is_tab);
        self.key.boolean_bitor_assign(&mut res, &is_newline);
        self.key.boolean_bitor_assign(&mut res, &is_formfeed);
        self.key.boolean_bitor_assign(&mut res, &is_carriage_return);
        if let Some(is_null) = op_is_null {
            self.key.boolean_bitor_assign(&mut res, &is_null);
        }
        res
    }

    fn compare_trim(&self, str: &[RadixCiphertext], starts_with_null: bool) -> FheString {
        let mut prev_was_ws = self.key.create_trivial_boolean_block(true);
        let bytes = str
            .into_iter()
            .map(|c| {
                let mut is_ws = self.is_whitespace(c, starts_with_null);
                self.key.boolean_bitand_assign(&mut is_ws, &prev_was_ws);
                let new_c = self.key.if_then_else_parallelized(
                    &is_ws,
                    &self.key.create_trivial_zero_radix(NUM_BLOCKS),
                    c,
                );
                prev_was_ws = is_ws;
                new_c
            })
            .collect();
        FheString {
            bytes,
            padded: false,
        }
    }

    /// Returns a new encrypted string with whitespace removed from the start.
    pub fn trim_start(&self, str: &FheString) -> FheString {
        if str.bytes.is_empty() || (str.padded && str.bytes.len() == 1) {
            return str.clone();
        }
        self.compare_trim(&str.bytes, false)
    }

    /// Returns a new encrypted string with whitespace removed from the end.
    pub fn trim_end(&self, str: &FheString) -> FheString {
        if str.bytes.is_empty() || (str.padded && str.bytes.len() == 1) {
            return str.clone();
        }
        let bytes: Vec<_> = str.bytes.iter().rev().cloned().collect();
        let mut bytes = self.compare_trim(&bytes, str.padded).bytes;
        bytes.reverse();
        FheString {
            bytes,
            padded: str.padded,
        }
    }

    /// Returns a new encrypted string with whitespace removed from both the start and end.
    pub fn trim(&self, str: &FheString) -> FheString {
        if str.bytes.is_empty() || (str.padded && str.bytes.len() == 1) {
            return str.clone();
        }
        let res = self.trim_start(str);
        self.trim_end(&res)
    }

    /// Creates an iterator over the substrings of this encrypted string, separated by any amount of
    /// whitespace.
    ///
    /// Each call to `next` on the iterator returns a tuple with the next encrypted substring and a
    /// boolean indicating `Some` (true) or `None` (false) when no more substrings are available.
    ///
    /// When the boolean is `true`, the iterator will yield non-empty encrypted substrings. When the
    /// boolean is `false`, the returned encrypted string is always empty.
    pub fn split_ascii_whitespace(&self, str: &FheString) -> SplitAsciiWhitespace {
        SplitAsciiWhitespace { state: str.clone() }
    }
}

#[cfg(test)]
mod tests {
    use tfhe::shortint::prelude::PARAM_MESSAGE_2_CARRY_2;

    use crate::{
        fhe_string::{FheString, PlaintextString},
        generate_keys,
        server_key::FheStringIterator,
    };

    #[test]
    fn test_trim_start() {
        let (ck, sk) = generate_keys(PARAM_MESSAGE_2_CARRY_2.into());
        let s = "  hello world  ";
        let enc_s = FheString::encrypt(PlaintextString::new(s.to_string()), &ck);
        let enc_res = sk.trim_start(&enc_s);
        assert_eq!(enc_res.decrypt(&ck).as_str(), "hello world  ");
    }

    #[test]
    fn test_trim_end() {
        let (ck, sk) = generate_keys(PARAM_MESSAGE_2_CARRY_2.into());
        let s = "  hello world  ";
        let enc_s = FheString::encrypt(PlaintextString::new(s.to_string()), &ck);
        let enc_res = sk.trim_end(&enc_s);
        assert_eq!(enc_res.decrypt(&ck).as_str(), "  hello world");
    }

    #[test]
    fn test_trim() {
        let (ck, sk) = generate_keys(PARAM_MESSAGE_2_CARRY_2.into());
        let s = "  hello world  ";
        let enc_s = FheString::encrypt(PlaintextString::new(s.to_string()), &ck);
        let enc_res = sk.trim(&enc_s);
        assert_eq!(enc_res.decrypt(&ck).as_str(), "hello world");
    }

    #[test]
    fn test_split_ascii_whitespace() {
        let (ck, sk) = generate_keys(PARAM_MESSAGE_2_CARRY_2.into());
        let s = "hello \t\nworld";
        let enc_s = FheString::encrypt(PlaintextString::new(s.to_string()), &ck);
        let mut iter = sk.split_ascii_whitespace(&enc_s);

        let enc_first_item = iter.next(&sk);
        let first_item = enc_first_item.decrypt(&ck);
        assert_eq!(first_item.as_str(), "hello");

        let enc_second_item = iter.next(&sk);
        let second_item = enc_second_item.decrypt(&ck);
        assert_eq!(second_item.as_str(), "world");

        let enc_third_item = iter.next(&sk);
        let third_item = enc_third_item.decrypt(&ck);
        assert_eq!(third_item.as_str(), "");
    }
}
