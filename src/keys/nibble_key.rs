use super::byte_key::ByteKey;
use super::Key;

/// Represents a key whose unit is nibbles, i.e. 4-byte long values.
///
/// Internally, nibbles are stored in a byte array, with each byte
/// having its most significant nibble set to 0.
#[derive(Debug, PartialEq, Clone)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct NibbleKey(Vec<u8>);

impl Default for NibbleKey {
    fn default() -> Self {
        NibbleKey(vec![0u8; 64])
    }
}

impl From<Vec<u8>> for NibbleKey {
    fn from(nibbles: Vec<u8>) -> Self {
        for nibble in nibbles.iter() {
            if *nibble >= 16 {
                panic!("Nibble value is higher than 15");
            }
        }
        NibbleKey(nibbles)
    }
}

impl std::fmt::Display for NibbleKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for nibble in self.0.iter() {
            write!(f, "{:x}", nibble)?;
        }
        Ok(())
    }
}

impl From<&[u8]> for NibbleKey {
    fn from(nibbles: &[u8]) -> Self {
        NibbleKey::from(nibbles.to_vec())
    }
}

impl Key<u8> for NibbleKey {
    fn tail(&self) -> Self {
        if self.0.is_empty() {
            return NibbleKey(self.0.clone());
        }

        NibbleKey::from(self.0[1..].to_vec())
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl NibbleKey {
    /// Finds the length of the common prefix of two keys.
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

    /// Encodes a nibble key to its hex prefix. The output
    /// is byte-encoded, so as to be stored immediately.
    pub fn with_hex_prefix(&self, is_terminator: bool) -> Vec<u8> {
        let ft = if is_terminator { 2 } else { 0 };
        let mut output = vec![0u8; self.0.len() / 2 + 1];

        // add indicator nibbles to leaf key
        output[0] = if self.0.len() % 2 == 1 {
            16 * (ft + 1) + self.0[0]
        } else {
            16 * ft
        };

        // Turn the list of nibbles into a list of bytes
        for i in 0..output.len() - 1 {
            let base = self.0.len() % 2;
            output[i + 1] = (16 * self.0[base + 2 * i]) | self.0[base + 1 + 2 * i];
        }

        output
    }

    /// Rebuilds the hex prefix from a `&[u8]` slice assumed to
    /// be hex prefix-encoded.
    pub fn remove_hex_prefix(payload: &[u8]) -> NibbleKey {
        if payload.is_empty() {
            return NibbleKey::from(payload);
        }
        match payload[0] {
            x if x & 16 == 16 => {
                // Odd payload.len()
                let mut out = vec![0u8; (payload.len() - 1) * 2 + 1];
                out[0] = x & 0xF;
                for i in 1..payload.len() {
                    out[2 * i - 1] = payload[i] >> 4;
                    out[2 * i] = payload[i] & 0xF;
                }
                NibbleKey(out)
            }
            _ => {
                // Even payload.len()
                let mut out = vec![0u8; (payload.len() - 1) * 2];
                for i in 1..payload.len() {
                    out[2 * (i - 1)] = payload[i] >> 4;
                    out[2 * (i - 1) + 1] = payload[i] & 0xF;
                }
                NibbleKey(out)
            }
        }
    }
}

impl rlp::Encodable for NibbleKey {
    fn rlp_append(&self, s: &mut rlp::RlpStream) {
        s.append(&self.0);
    }
}

impl Into<Vec<u8>> for NibbleKey {
    fn into(self) -> Vec<u8> {
        self.0
    }
}

impl std::ops::Index<usize> for NibbleKey {
    type Output = u8;

    #[inline]
    fn index(&self, i: usize) -> &u8 {
        &self.0[i]
    }
}

impl std::ops::Index<std::ops::RangeFrom<usize>> for NibbleKey {
    type Output = [u8];

    #[inline]
    fn index(&self, r: std::ops::RangeFrom<usize>) -> &[u8] {
        &self.0[r]
    }
}

impl std::ops::Index<std::ops::RangeTo<usize>> for NibbleKey {
    type Output = [u8];

    #[inline]
    fn index(&self, r: std::ops::RangeTo<usize>) -> &[u8] {
        &self.0[r]
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

    #[test]
    fn test_suffix() {
        let nibbles = NibbleKey(vec![0xd, 0xe, 0xa, 0xd, 0xb, 0xe, 0xe, 0xf]);
        assert_eq!(nibbles[nibbles.len() - 2..], vec![0xeu8, 0xf][..]);
    }

    #[test]
    fn test_empty_suffix() {
        let nibbles = NibbleKey(vec![0xd, 0xe, 0xa, 0xd, 0xb, 0xe, 0xe, 0xf]);
        assert_eq!(nibbles[nibbles.len()..], vec![0u8; 0][..]);
    }

    #[test]
    fn test_prefix() {
        let nibbles = NibbleKey(vec![0xd, 0xe, 0xa, 0xd, 0xb, 0xe, 0xe, 0xf]);
        assert_eq!(nibbles[..3], vec![0xdu8, 0xe, 0xa][..]);
    }

    #[test]
    fn test_empty_prefix() {
        let nibbles = NibbleKey(vec![0xd, 0xe, 0xa, 0xd, 0xb, 0xe, 0xe, 0xf]);
        assert_eq!(nibbles[..0], vec![0u8; 0][..]);
    }

    #[test]
    fn test_formatter() {
        let nibbles = NibbleKey(vec![0xd, 0xe, 0xa, 0xd, 0xb, 0xe, 0xe, 0xf]);
        assert_eq!(format!("{}", nibbles), "deadbeef")
    }
}
