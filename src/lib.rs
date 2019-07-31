extern crate rlp;
extern crate sha3;

use sha3::{Digest, Keccak256};

#[derive(Debug, Clone, PartialEq)]
enum Node {
    Hash(usize, usize, usize), // (Item to hash, # of empty strings, total # of items)
    Leaf(Vec<u8>, Vec<u8>),
    Extension(Vec<u8>, Box<Node>),
    FullNode(Vec<Node>),
    EmptySlot,
}

trait Hashable {
    fn hash(&self, hashers: &mut Vec<Keccak256>) -> Vec<u8>;
}

impl Hashable for Node {
    fn hash(&self, hashers: &mut Vec<Keccak256>) -> Vec<u8> {
        use Node::*;
        match self {
            EmptySlot => Vec::new(),
            Leaf(ref k, ref v) => {
                let encoding =
                    rlp::encode_list::<Vec<u8>, Vec<u8>>(&vec![k.clone(), v.clone()][..]);
                let mut hasher = Keccak256::new();
                hasher.input(&encoding);
                Vec::<u8>::from(&hasher.result()[..])
            }
            FullNode(ref nodes) => {
                /* XXX placeholder, incorrect */
                let mut keys = Vec::new();
                for node in nodes {
                    keys.push(node.hash(hashers));
                }
                let encoding = rlp::encode_list::<Vec<u8>, Vec<u8>>(&keys[..]);
                let mut hasher = Keccak256::new();
                hasher.input(&encoding);
                Vec::<u8>::from(&hasher.result()[..])
            }
            Hash(hridx, _, _) => {
                let res = hashers[*hridx].clone().result();
                Vec::<u8>::from(&res[..])
            }
            _ => panic!("Attemped to hash invalid type"),
        }
    }
}

enum Instruction {
    BRANCH(usize),
    HASHER(usize),
    LEAF(usize),
    EXTENSION(Vec<u8>),
    ADD(usize),
}

fn step(
    stack: &mut Vec<Node>,
    keyvals: Vec<(Vec<u8>, Vec<u8>)>,
    instructions: Vec<Instruction>,
    mut hashers: &mut Vec<Keccak256>,
) -> Node {
    use Instruction::*;
    use Node::*;

    let mut keyvalidx = 0;
    for instr in instructions {
        match instr {
            HASHER(digit) => {
                if let Some(item) = stack.pop() {
                    let mut hasher = Keccak256::new();
                    for _ in 1..digit {
                        hasher.input(b"");
                    }
                    hasher.input(item.hash(&mut hashers));
                    hashers.push(hasher);
                    stack.push(Hash(hashers.len() - 1, 1 + digit, digit));
                } else {
                    panic!("Could not pop a value from the stack, that is required for a HASHER")
                }
            }
            LEAF(keylength) => {
                let (key, value) = &keyvals[keyvalidx];
                stack.push(Leaf(
                    (&key[key.len() - keylength..]).to_vec(),
                    value.to_vec(),
                ));
                keyvalidx += 1;
            }
            BRANCH(digit) => {
                if let Some(node) = stack.pop() {
                    let mut children = vec![Node::EmptySlot; 16];
                    children[digit] = node;
                    stack.push(FullNode(children))
                } else {
                    panic!("Could not pop a value from the stack, that is required for a BRANCH")
                }
            }
            EXTENSION(key) => {
                if let Some(node) = stack.pop() {
                    stack.push(Extension(key, Box::new(node)));
                } else {
                    panic!("Could not find a node on the stack, that is required for an EXTENSION")
                }
            }
            ADD(digit) => {
                if let (Some(el1), Some(el2)) = (stack.pop(), stack.last_mut()) {
                    match el2 {
                        FullNode(ref mut n2) => {
                            if digit >= n2.len() {
                                panic!(format!(
                                    "Incorrect full node index: {} > {}",
                                    digit,
                                    n2.len() - 1
                                ))
                            }

                            // A hash needs to be fed into the hash sponge, any other node is simply
                            // a child (el1) of the parent node (el2). this is done during resolve.
                            n2[digit] = el1;
                        }
                        Hash(ref hasher_num, ref mut count, ref mut nempty) => {
                            for _ in 1..digit {
                                hashers[*hasher_num].input(b"");
                            }
                            /* XXX if serialization length is < 32, input that directly */
                            let el1_hash = el1.hash(&mut hashers);
                            hashers[*hasher_num].input(el1_hash);

                            *nempty += digit;
                            *count += digit + 1;
                        }
                        _ => panic!("Unexpected node type"),
                    }
                } else {
                    panic!("Could not find enough parameters to ADD")
                }
            }
            _ => panic!("Unsupported instruction"),
        }
    }

    stack.pop().unwrap()
}

#[cfg(test)]
mod tests {
    use super::Instruction::*;
    use super::Node::*;
    use super::*;

    #[test]
    fn tree_with_just_one_leaf() {
        let mut stack = Vec::new();
        let mut hashers = Vec::new();
        let out = step(
            &mut stack,
            vec![(vec![1, 2, 3], vec![4, 5, 6])],
            vec![LEAF(0)],
            &mut hashers,
        );
        assert_eq!(out, Leaf(vec![], vec![4, 5, 6]))
    }

    #[test]
    fn tree_with_one_branch() {
        let mut stack = Vec::new();
        let mut hashers = Vec::new();
        let out = step(
            &mut stack,
            vec![(vec![1, 2, 3], vec![4, 5, 6])],
            vec![LEAF(0), BRANCH(0)],
            &mut hashers,
        );
        assert_eq!(
            out,
            FullNode(vec![
                Leaf(vec![], vec![4, 5, 6]),
                EmptySlot,
                EmptySlot,
                EmptySlot,
                EmptySlot,
                EmptySlot,
                EmptySlot,
                EmptySlot,
                EmptySlot,
                EmptySlot,
                EmptySlot,
                EmptySlot,
                EmptySlot,
                EmptySlot,
                EmptySlot,
                EmptySlot
            ])
        )
    }

    #[test]
    fn tree_with_added_branch() {
        let mut stack = Vec::new();
        let mut hashers = Vec::new();
        let out = step(
            &mut stack,
            vec![
                (vec![1, 2, 3], vec![4, 5, 6]),
                (vec![7, 8, 9], vec![10, 11, 12]),
            ],
            vec![LEAF(0), BRANCH(0), LEAF(1), ADD(2)],
            &mut hashers,
        );
        assert_eq!(
            out,
            FullNode(vec![
                Leaf(vec![], vec![4, 5, 6]),
                EmptySlot,
                Leaf(vec![9], vec![10, 11, 12]),
                EmptySlot,
                EmptySlot,
                EmptySlot,
                EmptySlot,
                EmptySlot,
                EmptySlot,
                EmptySlot,
                EmptySlot,
                EmptySlot,
                EmptySlot,
                EmptySlot,
                EmptySlot,
                EmptySlot
            ])
        )
    }
}
