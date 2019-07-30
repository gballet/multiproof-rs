extern crate sha3;

use sha3::{Digest, Keccak256};

#[derive(Debug, Clone, PartialEq)]
enum Node {
    Hash(Box<Node>, u32, u32), // (Item to hash, # of empty strings, total # of items)
    Leaf(Vec<u8>, Vec<u8>),
    Extension(Vec<u8>, Box<Node>),
    FullNode(Vec<Node>),
    EmptySlot,
}

trait Hashable {
    fn hash(&self) -> Vec<u8>;
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
) -> Node {
    use Instruction::*;
    use Node::*;

    let mut keyvalidx = 0;
    for instr in instructions {
        match instr {
            HASHER(digit) => {
                if let Some(item) = stack.pop() {
                    stack.push(Hash(Box::new(item), 1 + digit, digit));
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
                        _ => panic!("Not supported yet"), // Need to support Hash()
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
        let out = step(
            &mut stack,
            vec![(vec![1, 2, 3], vec![4, 5, 6])],
            vec![LEAF(0)],
        );
        assert_eq!(out, Leaf(vec![], vec![4, 5, 6]))
    }

    #[test]
    fn tree_with_one_branch() {
        let mut stack = Vec::new();
        let out = step(
            &mut stack,
            vec![(vec![1, 2, 3], vec![4, 5, 6])],
            vec![LEAF(0), BRANCH(0)],
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
        let out = step(
            &mut stack,
            vec![
                (vec![1, 2, 3], vec![4, 5, 6]),
                (vec![7, 8, 9], vec![10, 11, 12]),
            ],
            vec![LEAF(0), BRANCH(0), LEAF(1), ADD(2)],
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
