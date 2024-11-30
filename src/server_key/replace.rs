use crate::{
    client_key::{FheU16, U16Arg},
    fhe_string::{FheString, GenericPattern},
};

use super::{FheStringIterator, ServerKey};

impl ServerKey {
    fn max_matches(&self, str: &FheString, pat: &FheString) -> u16 {
        let str_len: u16 = str.bytes.len().try_into().expect("str should be shorter");
        let pat_len: u16 = pat
            .bytes
            .len()
            .try_into()
            .expect("pattern should be shorter");

        // The max number of matches can be computed as
        // str_len - pat_len + 1. For instance "xx" matches "xxxx" at most 4 - 2 + 1 = 3 times.
        // This works as long as str_len >= pat_len (guaranteed due to the outer length checks)
        str_len - pat_len + 1
    }

    /// Returns a new encrypted string with a specified number of non-overlapping occurrences of a
    /// pattern (either encrypted or clear) replaced by another specified encrypted pattern.
    ///
    /// The number of replacements to perform is specified by a `U16Arg`, which can be either
    /// `Clear` or `Enc`. In the `Clear` case, the function uses a plain `u16` value for the count.
    /// In the `Enc` case, the count is an encrypted `u16` value, encrypted with `ck.encrypt_u16`.
    ///
    /// If the pattern to be replaced is not found or the count is zero, returns the original
    /// encrypted string unmodified.
    ///
    /// The pattern to search for can be either `GenericPattern::Clear` for a clear string or
    /// `GenericPattern::Enc` for an encrypted string, while the replacement pattern is always
    /// encrypted.
    pub fn replacen(
        &self,
        str: &FheString,
        from: &GenericPattern,
        to: &FheString,
        n: &U16Arg,
    ) -> FheString {
        let pat_len = match from {
            GenericPattern::Clear(pat) => pat.data.len(),
            GenericPattern::Enc(pat) => pat.bytes.len(),
        };
        if pat_len > str.bytes.len() {
            return str.clone();
        }

        // We need to split the string into `n + 1` parts, hence we have to call splitn with n + 1. 
        let n = match n {
            U16Arg::Clear(n) => U16Arg::Clear(*n + 1),
            U16Arg::Enc(n) => U16Arg::Enc(FheU16 {
                cipher: self.key.scalar_add_parallelized(&n.cipher, 1),
                max: n.max,
            }),
        };
        let mut iter = self.splitn(str, from, &n);

        let (first_item, mut concated) = iter.next(self);
        let mut res = first_item;
        match n {
            U16Arg::Clear(n) => {
                for _ in 0..n - 1 {
                    let (item, is_some) = iter.next(self);
                    self.key.boolean_bitand_assign(&mut concated, &is_some);
                    let mut concated_str = self.concat(&res, to);
                    concated_str = self.concat(&concated_str, &item);
                    res = self.conditional_fhestring(&concated, &concated_str, &res);
                }
            }
            U16Arg::Enc(_) => {
                let pattern = match from {
                    GenericPattern::Clear(pat) => FheString::enc_trivial(pat, self),
                    GenericPattern::Enc(pat) => pat.clone(),
                };
                let max_matches = self.max_matches(str, &pattern);
                
                for _ in 0..max_matches - 1 {
                    let (item, is_some) = iter.next(self);
                    self.key.boolean_bitand_assign(&mut concated, &is_some);
                    let mut concated_str = self.concat(&res, to);
                    concated_str = self.concat(&concated_str, &item);
                    res = self.conditional_fhestring(&concated, &concated_str, &res);
                }
            }
        }
        res
    }

    /// Returns a new encrypted string with all non-overlapping occurrences of a pattern (either
    /// encrypted or clear) replaced by another specified encrypted pattern.
    ///
    /// If the pattern to be replaced is not found, returns the original encrypted string
    /// unmodified.
    ///
    /// The pattern to search for can be either `GenericPattern::Clear` for a clear string or
    /// `GenericPattern::Enc` for an encrypted string, while the replacement pattern is always
    /// encrypted.
    pub fn replace(&self, str: &FheString, from: &GenericPattern, to: &FheString) -> FheString {
        let pattern = match from {
            GenericPattern::Clear(pat) => FheString::enc_trivial(pat, self),
            GenericPattern::Enc(pat) => pat.clone(),
        };
        let max_matches = self.max_matches(str, &pattern);
        self.replacen(str, from, to, &U16Arg::Clear(max_matches))
    }
}


#[cfg(test)]
mod tests {
    use tfhe::shortint::prelude::PARAM_MESSAGE_2_CARRY_2;

    use crate::{client_key::U16Arg, fhe_string::{FheString, GenericPattern, PlaintextString}, generate_keys};

    #[test]
    fn test_replacen() {
        let (ck, sk) = generate_keys(PARAM_MESSAGE_2_CARRY_2.into());

        let (s, from, to) = ("hello", "l", "r");
        let fhe_s = FheString::encrypt(PlaintextString::new(s.to_string()), &ck);
        let fhe_from = GenericPattern::Clear(PlaintextString::new(from.to_string()));
        let fhe_to = FheString::encrypt(PlaintextString::new(to.to_string()), &ck);
        let n = U16Arg::Clear(1);

        let enc_res = sk.replacen(&fhe_s, &fhe_from, &fhe_to, &n);
        let res = enc_res.decrypt(&ck);
        assert_eq!(res, "herlo");
    }

    #[test]
    fn test_replace() {
        let (ck, sk) = generate_keys(PARAM_MESSAGE_2_CARRY_2.into());

        let (s, from, to) = ("hello", "l", "r");
        let fhe_s = FheString::encrypt(PlaintextString::new(s.to_string()), &ck);
        let fhe_from = GenericPattern::Enc(FheString::encrypt(PlaintextString::new(from.to_string()), &ck));
        let fhe_to = FheString::encrypt(PlaintextString::new(to.to_string()), &ck);

        let enc_res = sk.replace(&fhe_s, &fhe_from, &fhe_to);
        let res = enc_res.decrypt(&ck);
        assert_eq!(res, "herro");
    }
}