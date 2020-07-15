use super::Key;

pub struct BinaryKeyIterator<'a>(&'a BinaryKey, usize);

impl<'a> Iterator for BinaryKeyIterator<'a> {
    type Item = u8;

    fn next(&mut self) -> Option<u8> {
        if self.1 >= self.0.len() {
            None
        } else {
            let idx = self.1;
            self.1 += 1;
            Some(self.0[idx])
        }
    }
}

/// Represents a key whose basic unit is the bit. This is meant to be
/// used at the key in binary trees.
///
/// Bits are stored inside an array of bytes, and are read left to
/// right. The structure also contains the start and end offset of
/// the bit field.
///
/// # Example structure
///
/// The following code will create a bit field with 6 bits spread
/// over two integers.
///
/// ```
/// use multiproof_rs::keys::BinaryKey;
/// let bitkey = BinaryKey::new(vec![0x55; 2], 3, 6);
/// ```
///
/// The internal representation is therefore:
///
/// ```text
/// byte #    |     1        2
/// bit  #    | 76543210 76543210
/// ----------+------------------
/// bit value | 01010101 01010101
/// offsets   |     ^     ^
///           |   start  end
/// ```
#[derive(Debug, PartialEq, Clone)]
pub struct BinaryKey(Vec<u8>, usize, usize); // (key data, offset in first byte, offset in last byte)

impl BinaryKey {
    pub fn new(data: Vec<u8>, start: usize, end: usize) -> Self {
        BinaryKey(data, start, end)
    }

    pub fn iter(&self) -> BinaryKeyIterator {
        BinaryKeyIterator(&self, 0)
    }
}

impl From<Vec<u8>> for BinaryKey {
    fn from(bytes: Vec<u8>) -> Self {
        BinaryKey(bytes, 7usize, 0usize)
    }
}

impl From<&[u8]> for BinaryKey {
    fn from(nibbles: &[u8]) -> Self {
        BinaryKey::from(nibbles.to_vec())
    }
}

impl Key<u8> for BinaryKey {
    fn tail(&self) -> Self {
        if self.0.is_empty() {
            return BinaryKey(vec![], 7, 0);
        }

        // Last bit in the byte?
        if self.1 == 0usize {
            BinaryKey(self.0[1..].to_vec(), 7usize, self.2)
        } else {
            BinaryKey(self.0.clone(), self.1 - 1, self.2)
        }
    }

    fn len(&self) -> usize {
        match self.0.len() {
            0 => 0,
            _ => (self.0.len() - 1) * 8 + self.1 + 1 - self.2,
        }
    }

    fn is_empty(&self) -> bool {
        self.0.len() == 0 || (self.0.len() == 1 && self.1 < self.2)
    }
}

impl std::ops::Index<usize> for BinaryKey {
    type Output = u8;

    #[inline]
    fn index(&self, i: usize) -> &Self::Output {
        // Check bounds, after this then the condition self.1 > i
        // determines if the bit is to be fetched in the first byte
        // or not.
        if i >= self.len() {
            panic!(format!("Invalid index {} into key {:?}", i, self.0));
        }

        let shift = 7 - self.1;
        let pos = shift + i;
        let byte = pos / 8;
        let offset = 7 - pos % 8;

        match (self.0[byte] >> offset) & 1 {
            0 => &0u8,
            _ => &1u8,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_iterate_over_one_byte() {
        let mut key = BinaryKey::from(vec![0xFFu8]);

        assert_eq!(key.len(), 8);

        let mut count = 0u32;
        loop {
            let tail = key.tail();
            key = tail;
            count += 1;
            if key.is_empty() {
                break;
            }
            assert!(count < 8);
        }
        assert_eq!(count, 8);
    }

    #[test]
    fn test_iterate_over_two_bytes() {
        let mut key = BinaryKey::from(vec![0xFFu8, 0xFFu8]);

        assert_eq!(key.len(), 16);

        let mut count = 0u32;
        loop {
            let tail = key.tail();
            key = tail;
            count += 1;
            if key.is_empty() {
                break;
            }
            assert!(count < 16);
        }
        assert_eq!(count, 16);
    }

    #[test]
    fn test_iterate_over_zero_bytes() {
        let mut key = BinaryKey::from(vec![]);

        assert_eq!(key.len(), 0);

        let mut count = 0u32;
        loop {
            let tail = key.tail();
            assert_eq!(key.len(), 0);
            key = tail;
            count += 1;
            if key.is_empty() {
                break;
            }
            assert!(count < 2);
        }
        assert_eq!(count, 1);
    }

    #[test]
    fn test_iterate_endianness() {
        let mut key = BinaryKey::from(vec![0x55u8, 0x55u8]);

        assert_eq!(key.len(), 16);

        let mut count = 0u32;
        loop {
            let tail = key.tail();
            key = tail;
            count += 1;
            if key.is_empty() {
                break;
            }
            assert!(count < 16);
        }
        assert_eq!(count, 16);
    }

    #[test]
    fn test_unaligned_bitfield() {
        // 8 bit total:
        // offset   | 76543210 76543210
        // ---------+------------------
        // bit      | 01011111 11110101
        // pointers |     ^       ^
        let mut key = BinaryKey(vec![0x5Fu8, 0xF5u8], 3, 4);

        assert_eq!(key.len(), 8);

        let mut count = 0u32;
        loop {
            let tail = key.tail();
            key = tail;
            count += 1;
            if key.is_empty() {
                break;
            }
            assert!(count < 8);
        }
        assert_eq!(count, 8);
    }

    #[test]
    fn test_unaligned_bitfield_one_byte() {
        // 4 bit total:
        // offset   | 76543210
        // ---------+---------
        // bit      | 10000111
        // pointers |  ^  ^
        let mut key = BinaryKey(vec![0x87u8], 6, 3);

        assert_eq!(key.len(), 4);

        let mut count = 0u32;
        loop {
            let tail = key.tail();
            key = tail;
            count += 1;
            if key.is_empty() {
                break;
            }
            assert!(count < 4);
        }
        assert_eq!(count, 4);
    }

    #[test]
    fn test_bit_index_one_byte() {
        let val = 0xFu8;
        let key = BinaryKey(vec![val], 7, 0);

        for i in 0..8 {
            let bit = (0xF0u8 >> i) & 1;
            assert_eq!(key[i], bit);
        }
    }

    #[test]
    fn test_bit_index_one_byte_partial() {
        // 4 bit total:
        // offset   | 76543210
        // ---------+---------
        // bit      | 01010101
        // pointers |  ^  ^
        let key = BinaryKey(vec![0x55u8], 6, 3);

        for i in 0..3 {
            let bit = (5u8 >> i) & 1;
            assert_eq!(key[i], bit);
        }
    }

    #[test]
    fn test_bit_index_two_bytes() {
        let key = BinaryKey(vec![0xFu8; 2], 7, 0);

        for i in 0..16 {
            let bit = ((0xF0F0u16 >> i) & 1) as u8;
            assert_eq!(key[i], bit);
        }
    }

    #[test]
    fn test_bit_index_three_bytes() {
        let key = BinaryKey(vec![0xFu8; 3], 7, 0);

        for i in 0..24 {
            let bit = ((0xF0F0F0u32 >> i) & 1) as u8;
            assert_eq!(key[i], bit);
        }
    }

    #[test]
    fn test_bit_index_one_bit() {
        let key = BinaryKey(vec![0xFu8], 3, 3);
        assert_eq!(key[0], 1);
    }

    #[test]
    #[should_panic(expected = "Invalid index 0 into key")]
    fn test_bit_index_no_bits() {
        let key = BinaryKey(vec![0xFu8], 3, 4);

        key[0];
    }
}
