use tfhe::integer::{prelude::ServerKeyDefaultCMux, BooleanBlock, RadixCiphertext};

use crate::fhe_string::{FheString, NUM_BLOCKS};

use super::ServerKey;

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
}

#[cfg(test)]
mod tests {
    use tfhe::shortint::prelude::PARAM_MESSAGE_2_CARRY_2;

    use crate::{fhe_string::{FheString, PlaintextString}, generate_keys};

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
}