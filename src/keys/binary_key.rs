use super::Key;

#[derive(Debug, PartialEq, Clone)]
pub struct BinaryKey(Vec<u8>, usize, usize); // (key data, offset in first byte, offset in last byte)

impl From<Vec<u8>> for BinaryKey {
    fn from(bytes: Vec<u8>) -> Self {
        BinaryKey(bytes, 7usize, 0usize)
    }
}

impl Key<u8> for BinaryKey {
    fn head_and_tail(&self) -> (Option<u8>, Self) {
        if self.0.is_empty() {
            return (None, BinaryKey(vec![], 7, 0));
        }

        // Last bit in the byte?
        if self.1 == 0usize {
            let next_bit = self.0[0] & (1 << self.1);
            (
                Some(next_bit),
                BinaryKey(self.0[1..].to_vec(), 7usize, self.2),
            )
        } else {
            let next_bit = self.0[0] & (1 << self.1);
            (
                Some(next_bit),
                BinaryKey(self.0.clone(), self.1 - 1, self.2),
            )
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_iterate_over_one_byte() {
        let mut key = BinaryKey::from(vec![0xFFu8]);

        assert_eq!(key.len(), 8);

        let mut count = 0u32;
        loop {
            let (head, tail) = key.head_and_tail();
            assert!(head.unwrap() != 0);
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
            let (head, tail) = key.head_and_tail();
            assert!(head.unwrap() != 0);
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
            let (head, tail) = key.head_and_tail();
            assert_eq!(head, None);
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
            let (head, tail) = key.head_and_tail();
            if count % 2 == 0 {
                assert_eq!(head.unwrap(), 0);
            } else {
                assert!(head.unwrap() != 0);
            }
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
            let (head, tail) = key.head_and_tail();
            assert!(head.unwrap() != 0);
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
            let (head, tail) = key.head_and_tail();
            assert!(head.unwrap() == 0);
            key = tail;
            count += 1;
            if key.is_empty() {
                break;
            }
            assert!(count < 4);
        }
        assert_eq!(count, 4);
    }
}
