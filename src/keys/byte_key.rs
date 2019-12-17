use super::super::NibbleKey;
use super::Key;

#[derive(Debug, PartialEq, Clone)]
pub struct ByteKey(pub Vec<u8>);

impl From<Vec<u8>> for ByteKey {
    fn from(bytes: Vec<u8>) -> Self {
        ByteKey(bytes)
    }
}

impl From<ByteKey> for NibbleKey {
    fn from(address: ByteKey) -> Self {
        let mut nibbles = Vec::new();
        for nibble in 0..2 * address.0.len() {
            let nibble_shift = (1 - nibble % 2) * 4;

            nibbles.push((address.0[nibble / 2] >> nibble_shift) & 0xF);
        }
        NibbleKey::from(nibbles)
    }
}

impl Key<u8> for ByteKey {
    fn tail(&self) -> Self {
        if self.0.is_empty() {
            return ByteKey(self.0.clone());
        }

        ByteKey::from(self.0[1..].to_vec())
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::ops::Index<usize> for ByteKey {
    type Output = u8;

    fn index(&self, i: usize) -> &Self::Output {
        &self.0[i]
    }
}
