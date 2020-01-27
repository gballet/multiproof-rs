use super::instruction::*;
use super::tree::{NodeType, Tree};
use serde::{Deserialize, Serialize};

pub trait ProofToTree<N: NodeType, T: Tree<N>> {
    /// Rebuilds a tree of type `T` based on the proof's components.
    fn rebuild(&self) -> Result<T, String>;
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Multiproof {
    pub hashes: Vec<Vec<u8>>,           // List of hashes in the proof
    pub instructions: Vec<Instruction>, // List of instructions in the proof
    pub keyvals: Vec<Vec<u8>>,          // List of RLP-encoded (key, value) pairs in the proof
}

impl rlp::Encodable for Multiproof {
    fn rlp_append(&self, s: &mut rlp::RlpStream) {
        s.begin_list(3);
        s.append_list::<Vec<u8>, Vec<u8>>(&self.hashes[..]);
        s.append_list::<Vec<u8>, Vec<u8>>(&self.keyvals[..]);
        s.append_list::<Instruction, Instruction>(&self.instructions[..]);
    }
}

impl rlp::Decodable for Multiproof {
    fn decode(rlp: &rlp::Rlp) -> Result<Self, rlp::DecoderError> {
        let hashes: Vec<Vec<u8>> = rlp.list_at(0usize)?;
        let keyvals: Vec<Vec<u8>> = rlp.list_at(1usize)?;
        let instructions: Vec<Instruction> = rlp.list_at(2usize)?;
        Ok(Multiproof {
            hashes,
            instructions,
            keyvals,
        })
    }
}

impl std::fmt::Display for Multiproof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "instructions:")?;
        for i in self.instructions.iter() {
            writeln!(f, "\t{:?}", i)?;
        }
        writeln!(f, "keyvals:")?;
        for kv in self.keyvals.iter() {
            writeln!(f, "\t{:?}", hex::encode(kv))?;
        }
        writeln!(f, "hashes:")?;
        for h in self.hashes.iter() {
            writeln!(f, "\t{}", hex::encode(h))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::instruction::Instruction::*;
    use super::super::keys::NibbleKey;
    use super::super::node::Node::*;
    use super::*;

    #[test]
    fn rlp_encode_decode_multiproof() {
        let mp = Multiproof {
            hashes: vec![vec![1u8; 32]],
            instructions: vec![LEAF(0)],
            keyvals: vec![rlp::encode(&Leaf(NibbleKey::from(vec![1]), vec![2]))],
        };
        let rlp = rlp::encode(&mp);
        let decoded = rlp::decode::<Multiproof>(&rlp).unwrap();
        assert_eq!(
            decoded,
            Multiproof {
                hashes: vec![vec![1u8; 32]],
                keyvals: vec![rlp::encode(&Leaf(NibbleKey::from(vec![1]), vec![2]))],
                instructions: vec![LEAF(0)]
            }
        )
    }

    #[test]
    fn cbor_encode_decode_multiproof() {
        use serde_cbor::{from_slice, to_vec};

        let mp = Multiproof {
            hashes: vec![vec![1u8; 32]],
            instructions: vec![LEAF(0)],
            keyvals: vec![rlp::encode(&Leaf(NibbleKey::from(vec![1]), vec![2]))],
        };

        let encoding = to_vec(&mp).unwrap();
        assert_eq!(
            encoding,
            vec![
                163, 102, 104, 97, 115, 104, 101, 115, 129, 152, 32, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 108, 105, 110,
                115, 116, 114, 117, 99, 116, 105, 111, 110, 115, 129, 161, 100, 76, 69, 65, 70, 0,
                103, 107, 101, 121, 118, 97, 108, 115, 129, 131, 24, 194, 24, 49, 2
            ]
        );

        let out = from_slice(&encoding[..]).unwrap();
        assert_eq!(mp, out);
    }
}
