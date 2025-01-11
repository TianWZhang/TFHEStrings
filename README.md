# FHE Strings

This repo contains the implementation of a str API in FHE, featuring 30 methods. This API allows the user to:
* Encrypt the `str` 
* Encrypt any kind of pattern (`pat`, `from`, `to`, `rhs`)
* Encrypt the number of repetitions `n`, allowing to provide a clear `max` to restrict the range of the encrypted `n`
* Provide a plaintext pattern when algorithms can run faster. Otherwise, it's possible to trivially encrypt the pattern with `FheString::trivial`

TODO: Modify `trim_start`, `replace` to support multi-hop FHE. 
Just like the clear str API, any encrypted string returned by a function can be used as input to other functions. For instance when `trim_start` is executed, or a `Split` iterator instance is advanced with `next`, the result will only have nulls at the end. The decryption function `decrypt` will panic if it encounters with malformed encrypted strings, including padding inconsistencies.

### Example

```rust
use tfhe::shortint::prelude::PARAM_MESSAGE_2_CARRY_2;
use crate::{fhe_string::{FheString, PlaintextString}, generate_keys, set_server_key};

let s = "AF";
let (ck, sk) = generate_keys(PARAM_MESSAGE_2_CARRY_2);
set_server_key(sk);
let fhe_s = FheString::encrypt(PlaintextString::new(s.to_string()), &ck);
let fhe_s_tolowercase = fhe_s.to_lowercase();
let s_tolowercase = fhe_s_tolowercase.decrypt(&ck);
assert_eq!(s_tolowercase, s.to_lowercase());
```

## Technical Details

Inspired by [1], we take a similar approach to implement conversions between encrypted strings (`FheString`) and UInts (`RadixCiphertext`). This is useful for:

- Speeding up comparisons and pattern matching: We perform a _single comparison_ between two numbers. This is more efficient than many u8 comparisons.
- Shifting by an encrypted number of characters: By treating the string as a `RadixCiphertext` we can use the tfhe-rs shifting operations, and then convert back to `FheString`.

The encrypted strings (`FheString`) support the encryption of `\0`-padded plaintext strings. Padding allows us to hide the length of the plaintext string. Furthermore, padding is necessary in some cases such as strip, split and trim. For example, `trim()` returns a new encrypted string with whitespace removed from both the start and end. Instead of actually removing whitespace, we replace them with `\0` to remove them logically. Even if the original `FheString` is not padded, after some homomorphic string operations, it will inevitably become padded.

TODO: pesudo code of split, replace

```rust
    /// Returns a tuple containing the byte index of the first character from the end of this
    /// encrypted string that matches the given pattern (either encrypted or clear), and a
    /// boolean indicating if a match was found.
    ///
    /// If the pattern doesn’t match, the function returns a tuple where the boolean part is
    /// `false`, indicating the equivalent of `None`.
    pub fn find(
        &self,
        str: &FheString,
        pattern: &GenericPattern,
    ) -> (RadixCiphertext, BooleanBlock) {
        // check special cases and early return, e.g. if `pattern` is not padded and the length of `str` is less than that of `pattern`, then `pattern` cannot be found in `str`.
        // If `pattern` is padded, we should compare `pattern` with all the suffixs of `str` instead of `str[i..i+pattern.len()]` because we are not sure 
        // what is the true length of `pattern`.
        // We need to compare `pattern` with a substring of `str` `str[i..]`. In the comparision, the padding of `pattern` should be ignored. In other words, if a character of `pattern` is `\0`, no matter what the corresponding character of the substring is, we think these two characters are equal. However, we have to take care of a specical case where `pattern` is padded and `str` is not padded, we will pad a null at the end of `str`.
        // We use zip in the comparision and in rust, zip will stop as soon as one of iterators stops producing values. 
        // For example, str = abc, pattern = abcd00, without padding, str.zip(pattern) becomes [('a', 'a'), ('b', 'b'), ('c', 'c')], hence we will think `str` matches `pattern` at the start, which is wrong. With padding, str = "abc\0", str.zip(pattern) becomes [('a', 'a'), ('b', 'b'), ('c', 'c'), ('\0', 'd')], hence these two are not equal.
        // If `pattern` is not padded, we should compare `pattern` with all the substrings of `str` of length `pattern.len()`.
    }
```

```rust
    /// Returns a new encrypted string with whitespace removed from the start.
    pub fn trim_start(&self, str: &FheString) -> FheString {
        // if `str` is empty, return.
        // Replace the leading whitespace of `str` with `\0`.
        // The result has potential `\0` in the leftmost chars, so we compute the length difference
        // before and after the trimming, and use that amount to left shift the `res`. This
        // makes the nulls be at the end of `res`.
        // If str was not padded originally we don't know if `res` has nulls at the end or not (we
        // don't know if str was shifted or not) so we ensure it's padded in order to be
        // used in other functions safely
    }
```

```rust
impl FheStringIterator for SplitAsciiWhitespace {
    // The `is_some` of type `BooleanBlock` determines whether the result is `None`. If `is_some` is
    // false, we ignore the value of `item`.
    fn next(&mut self, sk: &ServerKey) -> (FheString, BooleanBlock) {
        let str_len = self.state.bytes.len();

        // `self.state` stores the remaining string.
        // Every time we call `next()`, we first remove the leading whitespace of `self.state`.
        self.state = sk.trim_start(&self.state);
        let cur_state = self.state.clone();

        // create the mask
        // `mask` is 1 until we encounter the first whitespace, then it becomes 0. For example,
        // if `self.state` is "aaa\n bbc", then mask is [255, 255, 255, 0, 0, 0, 0, 0].
        
        // Then we apply the mask to obtain the next item. Using the above example again,
        // `item` becomes "aaa\0\0\0\0\0"

        // update state
        // we left shift `self.state` by the length of `item`.
        // If `self.state` was not padded before, we cannot know if it is still not padded because of 
        // the left shift operation, so we ensure it's padded in order to be used in other functions safely.
    }
}
```

```rust
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
        // We need to split the string into `n + 1` parts, hence we have to call splitn with n + 1.
        let mut iter = self.splitn(str, from, &n);

        let (first_item, mut concated) = iter.next(self);
        let mut res = first_item;

        // If `n` is plaintext, we will call `next()` `n` times.
        // If `n` is encrypted, we have to compute the maximal possible times that `str` match `to` and then
        // call `next()` `max_matches-1` times.
        // If  `is_some` returned from `next()` is true, we will concat `res`, `to` and `item` (also returned from `next`) together.
                for _ in 0..max_matches - 1 {
                    let (item, is_some) = iter.next(self);
                    self.key.boolean_bitand_assign(&mut concated, &is_some);
                    let mut concated_str = self.concat(&res, to);
                    concated_str = self.concat(&concated_str, &item);
                    res = self.conditional_fhestring(&concated, &concated_str, &res);
                }
        res
    }
```

## Test Cases

We have handled corner cases like empty strings and empty patterns (with and without padding), the number of repetitions `n` (clear and encrypted) being zero, etc.

## Usage

without padding nulls (i.e. encrypted `0u8`s at the end of the string), which serve to obfuscate the length but are ignored by algorithms

Wrapper the methods in FheString with thread_local.

## Reference

[1]: https://github.com/JoseSK999/fhe_strings
[2]: ZAMA tfhe.rs doc
