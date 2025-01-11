use crate::{
    client_key::{FheU16, U16Arg},
    fhe_string::{FheString, GenericPattern},
};

use super::{FheStringIterator, IsMatch, ServerKey};

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
        if let U16Arg::Clear(0) = n {
            return str.clone();
        }
        let trivial_or_enc_from = match from {
            GenericPattern::Clear(from) => FheString::enc_trivial(from, self),
            GenericPattern::Enc(from) => from.clone(),
        };
        match self.is_matched_early_checks(str, &trivial_or_enc_from) {
            IsMatch::Clear(false) => return str.clone(),
            // This happens when `from` is empty.
            IsMatch::Clear(true) => {
                // If `from` and `str` are both empty, there is only one match and one replacement.
                if str.bytes.is_empty() || (str.padded && str.bytes.len() == 1) {
                    match n {
                        U16Arg::Clear(_) => return to.clone(),
                        U16Arg::Enc(enc_n) => {
                            let n_is_zero = self.key.scalar_eq_parallelized(&enc_n.cipher, 0);
                            return self.conditional_fhestring(&n_is_zero, str, to);
                        }
                    }
                }
            }
            // This happens when `str` is empty, so it's again one replacement if 
            // there is a match or `str` if there is no match.
            IsMatch::Cipher(matched) => {
                match n {
                    U16Arg::Clear(_) => {
                        return self.conditional_fhestring(&matched, to, str);
                    }
                    U16Arg::Enc(enc_n) => {
                        let n_not_zero = self.key.scalar_ne_parallelized(&enc_n.cipher, 0);
                        let replaced = self.key.boolean_bitand(&n_not_zero, &matched);
                        return self.conditional_fhestring(&replaced, to, str);
                    }
                }
            }
            IsMatch::None => (),
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

        let (first_item, _) = iter.next(self);
        let mut res = first_item;

        let nexts = match n {
            U16Arg::Clear(n) => n - 1,
            U16Arg::Enc(_) => self.max_matches(str, &trivial_or_enc_from) - 1,
        };
        for _ in 0..nexts {
            let (item, is_some) = iter.next(self);
            let mut concated_str = self.concat(&res, to);
            concated_str = self.concat(&concated_str, &item);
            res = self.conditional_fhestring(&is_some, &concated_str, &res);
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

    use crate::{
        client_key::U16Arg,
        fhe_string::{GenericPattern, PlaintextString},
        generate_keys,
    };

    #[test]
    fn test_replacen() {
        let (ck, sk) = generate_keys(PARAM_MESSAGE_2_CARRY_2);

        let (s, from, to) = ("hello", "l", "r");
        let fhe_s = ck.enc_str(s, 2);
        let fhe_from = GenericPattern::Clear(PlaintextString::new(from.to_string()));
        let fhe_to = ck.enc_str(to, 1);
        let n = U16Arg::Clear(1);

        let enc_res = sk.replacen(&fhe_s, &fhe_from, &fhe_to, &n);
        let res = ck.dec_str(&enc_res);
        assert_eq!(res, "herlo");
    }

    #[test]
    fn test_replacen_with_empty_from() {
        let (ck, sk) = generate_keys(PARAM_MESSAGE_2_CARRY_2);

        let (s, from, to) = ("abc", "", "x");
        let fhe_s = ck.enc_str(s, 2);
        let fhe_from = GenericPattern::Enc(ck.enc_str(from, 2));
        let fhe_to = ck.enc_str(to, 1);
        let n = 2;
        let n_arg = U16Arg::Clear(n);

        let enc_res = sk.replacen(&fhe_s, &fhe_from, &fhe_to, &n_arg);
        let res = ck.dec_str(&enc_res);
        // "xaxbc"
        println!("{}", res);
        assert_eq!(res, s.replacen(from, to, n.into()));
    }

    #[test]
    fn test_replace() {
        let (ck, sk) = generate_keys(PARAM_MESSAGE_2_CARRY_2);

        let (s, from, to) = ("hello", "l", "r");
        let fhe_s = ck.enc_str(s, 0);
        let fhe_from = GenericPattern::Enc(ck.enc_str(from, 2));
        let fhe_to = ck.enc_str(to, 0);
        let enc_res = sk.replace(&fhe_s, &fhe_from, &fhe_to);
        let res = ck.dec_str(&enc_res);
        assert_eq!(res, "herro");

        let (s, from, to) = ("hello", "x", "r");
        let fhe_s = ck.enc_str(s, 0);
        let fhe_from = GenericPattern::Enc(ck.enc_str(from, 2));
        let fhe_to = ck.enc_str(to, 0);
        let enc_res = sk.replace(&fhe_s, &fhe_from, &fhe_to);
        let res = ck.dec_str(&enc_res);
        assert_eq!(res, "hello");
    }
}
