const BRANCH_OPCODE: usize = 0;
const HASHER_OPCODE: usize = 1;
const LEAF_OPCODE: usize = 2;
const EXTENSION_OPCODE: usize = 3;
const ADD_OPCODE: usize = 4;

#[derive(Debug, PartialEq)]
pub enum Instruction {
    BRANCH(usize),
    HASHER,
    LEAF(usize),
    EXTENSION(Vec<u8>),
    ADD(usize),
}

impl rlp::Encodable for Instruction {
    fn rlp_append(&self, s: &mut rlp::RlpStream) {
        match self {
            Instruction::EXTENSION(ref ext) => {
                s.begin_list(2).append(&EXTENSION_OPCODE).append_list(ext)
            }
            Instruction::BRANCH(size) => s.begin_list(2).append(&BRANCH_OPCODE).append(size),
            Instruction::HASHER => s.begin_list(1).append(&HASHER_OPCODE),
            Instruction::LEAF(size) => s.begin_list(2).append(&LEAF_OPCODE).append(size),
            Instruction::ADD(index) => s.begin_list(2).append(&ADD_OPCODE).append(index),
        };
    }
}

impl rlp::Decodable for Instruction {
    fn decode(rlp: &rlp::Rlp) -> Result<Self, rlp::DecoderError> {
        let instrrlp = rlp.at(0usize)?;
        let instr: usize = instrrlp.as_val()?;

        if instr >= 5 {
            return Err(rlp::DecoderError::Custom("Invalid instruction opcode {}"));
        }

        if instr == EXTENSION_OPCODE {
            Ok(Instruction::EXTENSION(rlp.at(1)?.as_list()?))
        } else if instr == HASHER_OPCODE {
            Ok(Instruction::HASHER)
        } else {
            let size: usize = rlp.at(1usize)?.as_val()?;
            let i = match instr {
                BRANCH_OPCODE => Instruction::BRANCH(size),
                HASHER_OPCODE => Instruction::HASHER,
                LEAF_OPCODE => Instruction::LEAF(size),
                ADD_OPCODE => Instruction::ADD(size),
                _ => panic!("This should never happen!"), /* Famous last words */
            };

            Ok(i)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Instruction::*;
    use super::*;

    #[test]
    fn encode_decode_instruction() {
        let instructions = vec![LEAF(1), ADD(5), EXTENSION(vec![3u8; 4]), BRANCH(6)];

        let encoded = rlp::encode_list(&instructions);
        let decoded = rlp::decode_list::<Instruction>(&encoded);
        assert_eq!(decoded, instructions);
    }
}
