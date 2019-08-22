#[derive(Debug, PartialEq, Clone)]
pub struct NibbleKey(Vec<u8>);
#[derive(Debug, PartialEq, Clone)]
pub struct ByteKey(Vec<u8>);

impl From<ByteKey> for NibbleKey {
    fn from(address: ByteKey) -> Self {
        let mut nibbles = Vec::new();
        for nibble in 0..2 * address.0.len() {
            let nibble_shift = (1 - nibble % 2) * 4;

            nibbles.push((address.0[nibble / 2] >> nibble_shift) & 0xF);
        }
        NibbleKey(nibbles)
    }
}

impl From<NibbleKey> for ByteKey {
    fn from(key: NibbleKey) -> Self {
        let mut result = Vec::<u8>::new();
        let mut saved = 0u8;
        for (i, nibble) in key.0.iter().enumerate() {
            if i % 2 == 0 {
                saved = nibble << 4;
            } else {
                result.push(saved | (nibble & 0xF));
            }
        }
        // Add the odd byte
        if key.0.len() % 2 != 0 {
            result.push(saved);
        }
        ByteKey(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nibble2bytes() {
        let bytes = ByteKey(vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(
            bytes,
            ByteKey::from(NibbleKey(vec![0xd, 0xe, 0xa, 0xd, 0xb, 0xe, 0xe, 0xf]))
        );
    }

    #[test]
    fn test_bytes2nibbles() {
        let nibbles = NibbleKey(vec![0xd, 0xe, 0xa, 0xd, 0xb, 0xe, 0xe, 0xf]);
        let bytes = ByteKey(vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(nibbles, NibbleKey::from(bytes));
    }
}
