use super::{Key, KeyIterator};

/// Represents a key whose basic unit is the bit. This is meant to be
/// used at the key in binary trees.
///
/// Bits are stored inside an array of bytes, and are read left to
/// right. The structure also contains the start and end offset of
/// the bit field. The end offset points at the first byte _outside_
/// of the bitfield.
///
/// # Example structure
///
/// The following code will create a bit field with 6 bits spread
/// over two integers.
///
/// ```
/// use multiproof_rs::keys::BinaryKey;
/// let bitkey = BinaryKey::new(vec![0x55; 2], 3, 9);
/// ```
///
/// The internal representation is therefore:
///
/// ```text
/// byte #    |     1        2
/// bit  #    | 01234567 89012345
/// ----------+------------------
/// bit value | 01010101 01010101
/// offsets   |    ^      ^
///           |  start   end
/// ```
#[derive(Debug, PartialEq, Clone)]
pub struct BinaryKey(Vec<u8>, usize, usize); // (key data, offset in first byte, offset in last byte)

impl BinaryKey {
    pub fn new(data: Vec<u8>, start: usize, end: usize) -> Self {
        BinaryKey(data, start, end)
    }
}

impl From<Vec<u8>> for BinaryKey {
    fn from(bytes: Vec<u8>) -> Self {
        let bitlen = bytes.len() * 8;
        BinaryKey(bytes, 0usize, bitlen)
    }
}

impl From<&[u8]> for BinaryKey {
    fn from(nibbles: &[u8]) -> Self {
        BinaryKey::from(nibbles.to_vec())
    }
}

impl Key<bool> for BinaryKey {
    fn len(&self) -> usize {
        if self.1 > self.2 {
            0
        } else {
            self.2 - self.1
        }
    }

    fn is_empty(&self) -> bool {
        self.0.len() == 0 || (self.2 <= self.1)
    }
}

impl std::ops::Index<usize> for BinaryKey {
    type Output = bool;

    #[inline]
    fn index(&self, i: usize) -> &Self::Output {
        // Check bounds, after this then the condition self.1 > i
        // determines if the bit is to be fetched in the first byte
        // or not.
        if i >= self.len() {
            panic!(format!("Invalid index {} into key {:?}", i, self.0));
        }

        let pos = self.1 + i;
        let byte = pos / 8;
        let offset = 7 - pos % 8;

        match (self.0[byte] >> offset) & 1 {
            0 => &false,
            _ => &true,
        }
    }
}

impl<'a> From<KeyIterator<'a, bool, BinaryKey>> for BinaryKey {
    fn from(it: KeyIterator<'a, bool, BinaryKey>) -> Self {
        BinaryKey(
            it.container.0[..].to_vec(),
            it.container.1 + it.item_num,
            it.container.2,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_iterate_over_one_byte() {
        let key = BinaryKey::from(vec![0xFFu8]);

        assert_eq!(key.len(), 8);
        assert_eq!(key.iter().count(), 8);
    }

    #[test]
    fn test_iterate_over_two_bytes() {
        let key = BinaryKey::from(vec![0xFFu8, 0xFFu8]);

        assert_eq!(key.len(), 16);
        assert_eq!(key.iter().count(), 16);
    }

    #[test]
    fn test_iterate_over_zero_bytes() {
        let key = BinaryKey::from(vec![]);

        assert_eq!(key.len(), 0);
        assert_eq!(key.iter().count(), 0);
    }

    #[test]
    fn test_iterate_endianness() {
        let key = BinaryKey::from(vec![0x55u8, 0x55u8]);

        for (i, b) in key.iter().enumerate() {
            assert_eq!(b, (key.len() - i) % 2 == 1);
        }
    }

    #[test]
    fn test_unaligned_bitfield() {
        // 8 bit total:
        // offset   | 01234567 89012345
        // ---------+------------------
        // bit      | 01011111 11110101
        // pointers |     ^        ^
        let key = BinaryKey(vec![0x5Fu8, 0xF5u8], 4, 12);

        assert_eq!(key.len(), 8);
        assert_eq!(key.iter().count(), 8);
    }

    #[test]
    fn test_unaligned_bitfield_one_byte() {
        // 4 bit total:
        // offset   | 01234567
        // ---------+---------
        // bit      | 10000111
        // pointers |  ^  ^
        let key = BinaryKey(vec![0x87u8], 3, 7);

        assert_eq!(key.len(), 4);
        assert_eq!(key.iter().count(), 4);
    }

    #[test]
    fn test_bit_index_one_byte() {
        let val = 0xFu8;
        let key = BinaryKey(vec![val], 0, 8);

        for i in 0..8 {
            let bit = (0xF0u8 >> i) & 1 == 1;
            assert_eq!(key[i], bit);
        }
    }

    #[test]
    fn test_bit_index_one_byte_partial() {
        // 4 bit total:
        // offset   | 01234567
        // ---------+---------
        // bit      | 01010101
        // pointers |  ^  ^
        let key = BinaryKey(vec![0x55u8], 1, 4);

        for i in 0..3 {
            let bit = (5u8 >> i) & 1 == 1;
            assert_eq!(key[i], bit);
        }
    }

    #[test]
    fn test_bit_index_two_bytes() {
        // 7 bit total:
        // offset   | 01234567 01234567
        // ---------+------------------
        // bit      | 00001111 00001111
        // pointers | ^                ^
        let key = BinaryKey(vec![0xFu8; 2], 0, 16);

        for i in 0..16 {
            let bit = (i % 8) >= 4;
            assert_eq!(key[i], bit);
        }
    }

    #[test]
    fn test_bit_index_three_bytes() {
        let key = BinaryKey(vec![0xFu8; 3], 0, 24);

        for i in 0..24 {
            let bit = ((0xF0F0F0u32 >> i) & 1) == 1;
            assert_eq!(key[i], bit);
        }
    }

    #[test]
    fn test_bit_index_one_bit() {
        let key = BinaryKey(vec![0xFu8], 4, 5);
        assert_eq!(key[0], true);
    }

    #[test]
    #[should_panic(expected = "Invalid index 0 into key")]
    fn test_bit_index_no_bits() {
        let key = BinaryKey(vec![0xFu8], 3, 3);

        key[0];
    }
}
