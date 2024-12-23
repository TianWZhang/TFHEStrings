use tfhe::integer::BooleanBlock;

use crate::fhe_string::{FheString, GenericPattern};

use super::{FheStringIsEmpty, ServerKey};

impl ServerKey {
    // `eq_early_checks` is a helper function that allows us to return early in the `eq` function.
    fn eq_early_checks(&self, lhs: &FheString, rhs: &FheString) -> Option<BooleanBlock> {
        let lhs_len = lhs.bytes.len();
        let rhs_len = rhs.bytes.len();

        // If lhs is empty, rhs must also be empty in order to be equal (the case where lhs is
        // empty with > 1 padding zeros is handled next)
        if lhs_len == 0 || (lhs.padded && lhs_len == 1) {
            return match self.is_empty(rhs) {
                FheStringIsEmpty::Padding(enc_val) => Some(enc_val),
                FheStringIsEmpty::NoPadding(val) => {
                    Some(self.key.create_trivial_boolean_block(val))
                }
            };
        }

        // If rhs is empty, lhs must also be empty in order to be equal (only case remaining is if
        // lhs padding zeros > 1)
        if rhs_len == 0 || (rhs.padded && rhs_len == 1) {
            return match self.is_empty(lhs) {
                FheStringIsEmpty::Padding(enc_val) => Some(enc_val),
                _ => Some(self.key.create_trivial_boolean_block(false)),
            };
        }

        // Two strings without padding that have different lengths cannot be equal
        if (!lhs.padded && !rhs.padded) && (lhs_len != rhs_len) {
            return Some(self.key.create_trivial_boolean_block(false));
        }

        // A string without padding cannot be equal to a string with padding that has the same or
        // lower length
        if (!lhs.padded && rhs.padded) && (rhs_len <= lhs_len)
            || (!rhs.padded && lhs.padded) && (lhs_len <= rhs_len)
        {
            return Some(self.key.create_trivial_boolean_block(false));
        }

        None
    }

    pub(crate) fn fhestrings_eq(&self, lhs: &FheString, rhs: &FheString) -> BooleanBlock {
        let mut lhs_uint = lhs.to_uint(self);
        let mut rhs_uint = rhs.to_uint(self);
        self.pad_ciphertexts_lsb(&mut lhs_uint, &mut rhs_uint);
        self.key.eq_parallelized(&lhs_uint, &rhs_uint)
    }

    pub(crate) fn fhestring_eq_string(&self, lhs: &FheString, rhs: &str) -> BooleanBlock {
        let mut lhs_uint = lhs.to_uint(self);
        let rhs_uint = self.pad_cipher_and_plaintext_lsb(&mut lhs_uint, rhs);
        self.key.scalar_eq_parallelized(&lhs_uint, rhs_uint)
    }

    /// Returns `true` if an encrypted string and a pattern (either encrypted or clear) are equal.
    ///
    /// Returns `false` if they are not equal.
    ///
    /// The pattern for comparison (`rhs`) can be specified as either `GenericPattern::Clear` for a
    /// clear string or `GenericPattern::Enc` for an encrypted string.
    pub fn eq(&self, lhs: &FheString, rhs: &GenericPattern) -> BooleanBlock {
        let early_return = match rhs {
            GenericPattern::Enc(rhs) => self.eq_early_checks(lhs, rhs),
            GenericPattern::Clear(rhs) => {
                self.eq_early_checks(lhs, &FheString::enc_trivial(&rhs.data, self))
            }
        };
        if let Some(val) = early_return {
            return val;
        }

        match rhs {
            GenericPattern::Enc(pat) => self.fhestrings_eq(&lhs, &pat),
            GenericPattern::Clear(pat) => self.fhestring_eq_string(&lhs, &pat.data),
        }
    }

    /// Returns `true` if an encrypted string and a pattern (either encrypted or clear) are not
    /// equal.
    ///
    /// Returns `false` if they are equal.
    ///
    /// The pattern for comparison (`rhs`) can be specified as either `GenericPattern::Clear` for a
    /// clear string or `GenericPattern::Enc` for an encrypted string.
    pub fn ne(&self, lhs: &FheString, rhs: &GenericPattern) -> BooleanBlock {
        let eq = self.eq(lhs, rhs);
        self.key.boolean_bitnot(&eq)
    }

    /// Returns `true` if the first encrypted string is less than the second encrypted string.
    ///
    /// Returns `false` otherwise.
    pub fn lt(&self, lhs: &FheString, rhs: &FheString) -> BooleanBlock {
        let mut lhs_uint = lhs.to_uint(self);
        let mut rhs_uint = rhs.to_uint(self);
        self.pad_ciphertexts_lsb(&mut lhs_uint, &mut rhs_uint);
        self.key.lt_parallelized(&lhs_uint, &rhs_uint)
    }

    /// Returns `true` if the first encrypted string is greater than the second encrypted string.
    ///
    /// Returns `false` otherwise.
    pub fn gt(&self, lhs: &FheString, rhs: &FheString) -> BooleanBlock {
        let mut lhs_uint = lhs.to_uint(self);
        let mut rhs_uint = rhs.to_uint(self);
        self.pad_ciphertexts_lsb(&mut lhs_uint, &mut rhs_uint);
        self.key.gt_parallelized(&lhs_uint, &rhs_uint)
    }

    /// Returns `true` if the first encrypted string is less than or equal to the second encrypted string.
    ///
    /// Returns `false` otherwise.
    pub fn le(&self, lhs: &FheString, rhs: &FheString) -> BooleanBlock {
        let mut lhs_uint = lhs.to_uint(self);
        let mut rhs_uint = rhs.to_uint(self);
        // According to the lexigraphical comparison of the strings, "ayy" is less than "b".
        // Therefore, the shorter string should be padded with nulls at the end.
        // LSB: yya :MSB
        // LSB: 00b :MSB
        self.pad_ciphertexts_lsb(&mut lhs_uint, &mut rhs_uint);
        self.key.le_parallelized(&lhs_uint, &rhs_uint)
    }

    /// Returns `true` if the first encrypted string is greater than or equal to the second encrypted string.
    ///
    /// Returns `false` otherwise.
    pub fn ge(&self, lhs: &FheString, rhs: &FheString) -> BooleanBlock {
        let mut lhs_uint = lhs.to_uint(self);
        let mut rhs_uint = rhs.to_uint(self);
        self.pad_ciphertexts_lsb(&mut lhs_uint, &mut rhs_uint);
        self.key.ge_parallelized(&lhs_uint, &rhs_uint)
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
    fn test_lt() {
        let (s1, s2) = ("apple", "banana");
        let (ck, sk) = generate_keys(PARAM_MESSAGE_2_CARRY_2);
        let fhe_s1 = ck.enc_str(s1, 0);
        let fhe_s2 = ck.enc_str(s2, 0);
        let fhe_res = sk.lt(&fhe_s1, &fhe_s2);
        let res = ck.key.decrypt_bool(&fhe_res);
        assert_eq!(res, s1.lt(s2));
    }

    #[test]
    fn test_eq() {
        let (s1, s2) = ("apple", "apple");
        let (ck, sk) = generate_keys(PARAM_MESSAGE_2_CARRY_2);
        let fhe_s1 = ck.enc_str(s1, 2);
        let fhe_res = sk.eq(
            &fhe_s1,
            &GenericPattern::Clear(PlaintextString::new(s2.to_string())),
        );
        let res = ck.key.decrypt_bool(&fhe_res);
        assert_eq!(res, s1 == s2);
    }
}
