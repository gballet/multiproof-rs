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

impl From<Vec<u8>> for NibbleKey {
    fn from(nibbles: Vec<u8>) -> Self {
        NibbleKey(nibbles)
    }
}

impl NibbleKey {
    pub fn new(nibbles: Vec<u8>) -> Self {
        for nibble in nibbles.iter() {
            if *nibble >= 16 {
                panic!("Nibble value is higher than 15");
            }
        }
        NibbleKey(nibbles.clone())
    }

    pub fn remove_prefix(&self, prefix_length: usize) -> Self {
        NibbleKey(self.0[prefix_length + 1..].to_vec())
    }

    pub fn prefix(&self, prefix_length: usize) -> Self {
        NibbleKey(self.0[..prefix_length].to_vec())
    }

    pub fn suffix(&self, suffix_length: usize) -> Self {
        NibbleKey(self.0[self.0.len() - suffix_length..].to_vec())
    }

    // Find the length of the common prefix of two keys
    pub fn factor_length(&self, other: &Self) -> usize {
        let (ref longuest, ref shortest) = if self.0.len() > other.0.len() {
            (&self.0, &other.0)
        } else {
            (&other.0, &self.0)
        };

        let mut firstdiffindex = shortest.len();
        for (i, &n) in shortest.iter().enumerate() {
            if n != longuest[i] {
                firstdiffindex = i as usize;
                break;
            }
        }

        assert!(firstdiffindex <= other.0.len());
        assert!(firstdiffindex <= self.0.len());

        firstdiffindex
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl rlp::Encodable for NibbleKey {
    fn rlp_append(&self, s: &mut rlp::RlpStream) {
        s.append(&self.0);
    }
}

impl Into<Vec<u8>> for NibbleKey {
    fn into(self) -> Vec<u8> {
        self.0.clone()
    }
}

impl std::ops::Index<usize> for NibbleKey {
    type Output = u8;

    fn index(&self, i: usize) -> &u8 {
        &self.0[i]
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
