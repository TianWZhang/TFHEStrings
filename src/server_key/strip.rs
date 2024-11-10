use rayon::iter::{IntoParallelRefMutIterator, ParallelIterator};
use tfhe::integer::BooleanBlock;

use crate::fhe_string::{FheString, NUM_BLOCKS};

use super::ServerKey;

impl ServerKey {
    fn compare_shifted_strip(
        &self,
        str: &mut FheString,
        pattern: &FheString,
        range: impl Iterator<Item = usize>,
    ) -> BooleanBlock {
        let mut res = self.key.create_trivial_boolean_block(false);
        for start in range {
            let substr = &str.clone().bytes[start..];
            let pattern_slice = &pattern.clone().bytes[..];
            let is_matched = self.string_eq(substr, pattern_slice);

            let mut mask = is_matched.clone().into_radix(NUM_BLOCKS, &self.key);
            // If mask == 0u8, it will become 255u8. If it was 1u8, it will become 0u8.
            self.key.scalar_sub_assign_parallelized(&mut mask, 1);

            let mutate_str = if start + pattern.bytes.len() < str.bytes.len() {
                &mut str.bytes[start..start + pattern.bytes.len()]
            } else {
                &mut str.bytes[start..]
            };

            rayon::join(
                || {
                    mutate_str.par_iter_mut().for_each(|c| {
                        self.key.bitand_assign_parallelized(c, &mask);
                    })
                },
                || self.key.boolean_bitor_assign(&mut res, &is_matched),
            );
        }
        res
    }
}
