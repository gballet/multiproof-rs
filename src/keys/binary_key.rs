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
#[derive(Debug, Clone)]
pub struct BinaryKey(Vec<u8>, usize, usize); // (key data, start offset, end offset)

impl BinaryKey {
    pub fn new(data: Vec<u8>, start: usize, end: usize) -> Self {
        BinaryKey(data, start, end)
    }

    pub fn iter(&self) -> BinaryKeyIterator {
        BinaryKeyIterator(&self, 0)
    }

    pub fn split(&self, idx: usize) -> (BinaryKey, BinaryKey) {
        let old_end = self.2;

        (
            BinaryKey(self.0[..].to_vec(), self.1, self.1 + idx),
            BinaryKey(self.0[..].to_vec(), self.1 + idx + 1, old_end),
        )
    }

    pub fn suffix(&self, idx: usize) -> BinaryKey {
        BinaryKey(self.0[..].to_vec(), self.1 + idx + 1, self.2)
    }
}

impl PartialEq for BinaryKey {
    fn eq(&self, other: &Self) -> bool {
        if self.len() != other.len() {
            return false;
        }

        for (i, b) in self.iter().enumerate() {
            if b != other[i] {
                return false;
            }
        }
        return true;
    }
}

impl From<Vec<u8>> for BinaryKey {
    fn from(bytes: Vec<u8>) -> Self {
        let bitlen = 8 * bytes.len();
        BinaryKey(bytes, 0usize, bitlen as usize)
    }
}

impl From<&[u8]> for BinaryKey {
    fn from(nibbles: &[u8]) -> Self {
        BinaryKey::from(nibbles.to_vec())
    }
}

impl Key<u8> for BinaryKey {
    fn tail(&self) -> Self {
        BinaryKey(self.0[..].to_vec(), self.1 + 1, self.2)
    }

    fn len(&self) -> usize {
        if self.0.len() == 0 || self.2 <= self.1 {
            return 0;
        } else {
            return self.2 - self.1;
        }
    }

    fn is_empty(&self) -> bool {
        self.len() == 0
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

        let offset = 7 - self.1 % 8;
        let byte = i / 8;

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
    #[should_panic(expected = "Invalid index 0 into key")]
    fn test_bit_index_no_bits() {
        let key = BinaryKey(vec![0xFu8], 3, 3);

        key[0];
    }

    #[test]
    fn test_equality() {
        assert_eq!(
            BinaryKey(vec![0, 0, 1, 2, 3, 0], 16, 41),
            BinaryKey(vec![0, 1, 2, 3, 0, 0], 8, 33)
        );
    }

    #[test]
    fn test_alignment() {
        assert_eq!(BinaryKey(vec![5], 0, 8), BinaryKey(vec![2, 128], 1, 9));
    }

    #[test]
    fn test_suffix() {
        let k = BinaryKey(vec![0x55], 0, 8);
        let s = k.suffix(2);
        assert_eq!(BinaryKey(vec![0x55], 3, 8), s);
    }
    #[test]
    fn test_split() {
        let k = BinaryKey(vec![0x55], 0, 8);
        let (p, s) = k.split(4);
        assert_eq!(BinaryKey(vec![0x55], 5, 8), s);
        assert_eq!(BinaryKey(vec![0x55], 0, 4), p);
    }
}
