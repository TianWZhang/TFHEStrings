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

TODO: pesudo code of split, find, trim_start, replace

## Test Cases

We have handled corner cases like empty strings and empty patterns (with and without padding), the number of repetitions `n` (clear and encrypted) being zero, etc.

## Usage

without padding nulls (i.e. encrypted `0u8`s at the end of the string), which serve to obfuscate the length but are ignored by algorithms

Wrapper the methods in FheString with thread_local.

## Reference

[1]: https://github.com/JoseSK999/fhe_strings
[2]: ZAMA tfhe.rs doc