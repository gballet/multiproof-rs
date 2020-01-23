use super::instruction::*;
use super::tree::{NodeType, Tree};

pub trait ProofToTree<N: NodeType, T: Tree<N>> {
    /// Rebuilds a tree of type `T` based on the proof's components.
    fn rebuild(&self) -> Result<T, String>;
}

#[derive(Debug, PartialEq)]
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

impl rustc_serialize::Encodable for Multiproof {
    fn encode<E: rustc_serialize::Encoder>(&self, e: &mut E) -> Result<(), E::Error> {
        for instr in self.instructions {
            match instr {
                Instruction::BRANCH(slot) => cbor::CborTagEncode::new(100_002, &slot).encode(e)?,
                Instruction::HASHER => cbor::CborTagEncode::new(100_003, &[]).encode(e)?,
                Instruction::LEAF(key, val) => { 
                    cbor::CborTagEncode::new(100_004, &key).encode(e)?;
                    cbor::CborTagEncode::new(100_004, &val).encode(e)?;
                }
                Instruction::EXTENSION(ext) => cbor::CborTagEncode::new(100_005, &ext).encode(e)?,
                Instruction::ADD(slot) => cbor::CborTagEncode::new(100_002, &slot).encode(e)?,
                }
            }
        }
        cbor::CborTagEncode::new(100_000, &self.hashes.iter().flatten().collect()).encode(e)?;
        cbor::CborTagEncode::new(100_001, &self.keyvals.iter().flatten().collect()).encode(e)
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
    fn cbor_encode_decode_multiproof() {}
}
