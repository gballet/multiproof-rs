use super::instruction::*;

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

impl rlp::Decodable for Multiproof {
    fn decode(rlp: &rlp::Rlp) -> Result<Self, rlp::DecoderError> {
        let hashes: Vec<Vec<u8>> = rlp.list_at(0usize)?;
        let keyvals: Vec<Vec<u8>> = rlp.list_at(1usize)?;
        let instructions: Vec<Instruction> = rlp.list_at(2usize)?;
        Ok(Multiproof {
            hashes: hashes,
            instructions: instructions,
            keyvals: keyvals,
        })
    }
}

impl std::fmt::Display for Multiproof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "instructions:\n")?;
        for i in self.instructions.iter() {
            write!(f, "\t{:?}\n", i)?;
        }
        write!(f, "keyvals:\n")?;
        for kv in self.keyvals.iter() {
            write!(f, "\t{:?}\n", hex::encode(kv))?;
        }
        write!(f, "hashes:\n")?;
        for h in self.hashes.iter() {
            write!(f, "\t{}\n", hex::encode(h))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::instruction::Instruction::*;
    use super::super::node::Node::*;
    use super::super::utils::*;
    use super::*;

    #[test]
    fn encode_decode_multiproof() {
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
}
