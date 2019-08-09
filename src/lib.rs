extern crate rlp;
extern crate sha3;

use sha3::{Digest, Keccak256};
use std::collections::BTreeMap;

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

                // Only hash if the encoder output is less than 32 bytes.
                if encoding.len() > 32 {
                    let mut hasher = Keccak256::new();
                    hasher.input(&encoding);
                    Vec::<u8>::from(&hasher.result()[..])
                } else {
                    encoding
                }
            }
            Extension(ref ext, node) => {
                let subtree_hash = node.hash(hashers);
                let encoding =
                    rlp::encode_list::<Vec<u8>, Vec<u8>>(&vec![ext.clone(), subtree_hash.clone()]);

                // Only hash if the encoder output is less than 32 bytes.
                if encoding.len() > 32 {
                    let mut hasher = Keccak256::new();
                    hasher.input(&encoding);
                    Vec::<u8>::from(&hasher.result()[..])
                } else {
                    encoding
                }
            }
            FullNode(ref nodes) => {
                let mut keys = Vec::new();
                for node in nodes {
                    keys.push(node.hash(hashers));
                }
                let encoding = rlp::encode_list::<Vec<u8>, Vec<u8>>(&keys[..]);

                // Only hash if the encoder output is less than 32 bytes.
                if encoding.len() > 32 {
                    let mut hasher = Keccak256::new();
                    hasher.input(&encoding);
                    Vec::<u8>::from(&hasher.result()[..])
                } else {
                    encoding
                }
            }
            Hash(hridx, _, _) => {
                let res = hashers[*hridx].clone().result();
                Vec::<u8>::from(&res[..])
            }
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
        }
    }

    stack.pop().unwrap()
}

fn bytes2nibbles(bytes: &[u8]) -> Vec<u8> {
    let mut nibbles = Vec::<u8>::new();
    for nibble in 0..2 * bytes.len() {
        let nibble_shift = (1 - nibble % 2) * 4;

        nibbles.push((bytes[nibble / 2] >> nibble_shift) & 0xF);
    }

    return nibbles;
}

fn nibbles2bytes(nibbles: &[u8]) -> Vec<u8> {
    let mut result = Vec::<u8>::new();
    let mut saved = 0u8;
    for (i, nibble) in nibbles.iter().enumerate() {
        if i % 2 == 0 {
            saved = nibble << 4;
        } else {
            result.push(saved | (nibble & 0xF));
        }
    }
    // Add the odd byte
    if nibbles.len() % 2 != 0 {
        result.push(saved);
    }
    result
}

// Helper function to build a tree based on its values
fn build_tree(keyvals: &Vec<(Vec<u8>, Vec<u8>)>) -> Node {
    use Node::*;

    let mut root = vec![EmptySlot; 16];

    let mut key2val = BTreeMap::<Vec<u8>, Vec<(Vec<u8>, Vec<u8>)>>::new();

    for (k, val) in keyvals.iter() {
        let nibble_key = bytes2nibbles(&k);
        for keylength in 0..64 {
            let mut key = vec![0u8; 64 - keylength];
            key.copy_from_slice(&nibble_key[..64 - keylength]);

            if key2val.contains_key(&key) {
                if let Some(_keys) = key2val.get_mut(&key) {
                    _keys.push((key, val.clone()));
                }
            } else {
                key2val.insert(key, vec![(k.clone(), val.clone())]);
            }
        }
    }

    let mut parents = BTreeMap::new(); // node -> parent map

    // Look for extension nodes&leaves
    for (k, v) in key2val.clone() {
        if k.len() > 0 {
            // Remove redundant values
            for n in 1..k.len() {
                let parent = &k[..k.len() - n];

                
                if key2val[parent].len() != v.len() {
                    let mut parentkey = vec![0u8; parent.len()];
                    parentkey.copy_from_slice(parent);
                    parents.insert(k.clone(), parentkey);
                    break;
                }
            }

            // Add root if no key was found
            if !parents.contains_key(&k) {
                parents.insert(k.clone(), Vec::<u8>::new());
            }
        }
    }
    parents.insert(vec![0u8; 0], vec![0u8; 0]);

    let mut initial_nodes = BTreeMap::<&[u8], Vec<(u8, Node)>>::new();
    for (k, v) in keyvals.iter() {
        let nkey = bytes2nibbles(&k);
        let parent = &parents[&nkey];
        let keylength = nkey.len() - parent.len();
        let mut leafkey = vec![0u8; keylength - 1];
        leafkey.copy_from_slice(&nkey[nkey.len() - keylength + 1..]);

        if initial_nodes.contains_key(&parent[..]) {
            let mut vec = initial_nodes.get_mut(&parent[..]).unwrap();
            vec.push((nkey[nkey.len() - keylength], Leaf(leafkey, v.to_vec())));
        } else {
            initial_nodes.insert(
                &parent[..],
                vec![(nkey[nkey.len() - keylength], Leaf(leafkey, v.to_vec()))],
            );
        }
    }
    // Insert the root node, which is expected in the main loop
    initial_nodes.insert(&[], vec![(16, FullNode(vec![EmptySlot; 16]))]);

    let mut node_list = initial_nodes.clone();

    while node_list.len() > 1 {
        let mut next_list = BTreeMap::<&[u8], Vec<(u8, Node)>>::new();
        for (k, v) in node_list.iter_mut() {
            // Special case of the root node, that has no parent but
            // should be in the next iteration.
            if k.len() == 0 {
                next_list.insert(k, v.to_vec());
                continue;
            }
            // 1. Get the parent key, calculate the selector

            // parent part = key length - parent length + selector
            let parent = &parents[&k.to_vec()];

            let sel = k[parent.len()];

            let mut fullnode = vec![EmptySlot; 16];
            for (selector, child_node) in v.iter_mut() {
                assert!(*selector == 16 || fullnode[*selector as usize] == EmptySlot);
                fullnode[*selector as usize] = child_node.clone();
            }

            // Merge the list into a list of FullNode siblings, and
            // insert it.
            if next_list.contains_key(&parent[..]) {
                // parent is an internal node
                let mut siblings = next_list[&parent[..]].clone();
                siblings.push((sel, FullNode(fullnode)));
                next_list.insert(parent, siblings);
            } else {
                // parent is the root node, so just update
                for (i, n) in fullnode.iter().enumerate() {
                    if root[i] == EmptySlot && *n != EmptySlot {
                        root[i] = n.clone()
                    }
                }
            };
        }
        node_list.clear();
        node_list.append(&mut next_list);
    }

    FullNode(root)
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

    #[test]
    fn tree_with_extension() {
        let mut stack = Vec::new();
        let mut hashers = Vec::new();
        let out = step(
            &mut stack,
            vec![
                (vec![1, 2, 3], vec![4, 5, 6]),
                (vec![7, 8, 9], vec![10, 11, 12]),
            ],
            vec![
                LEAF(0),
                BRANCH(0),
                LEAF(1),
                ADD(2),
                EXTENSION(vec![13, 14, 15]),
            ],
            &mut hashers,
        );
        assert_eq!(
            out,
            Extension(
                vec![13, 14, 15],
                Box::new(FullNode(vec![
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
                ]))
            )
        )
    }

    #[test]
    fn single_value_hash() {
        let mut hashers = Vec::new();
        assert_eq!(
            Leaf(vec![1, 2, 3], vec![4, 5, 6]).hash(&mut hashers),
            vec![200, 131, 1, 2, 3, 131, 4, 5, 6]
        );
    }

    #[test]
    fn big_value_single_key_hash() {
        let mut hashers = Vec::new();
        assert_eq!(
            Leaf(vec![0u8; 32], vec![4, 5, 6]).hash(&mut hashers),
            vec![
                0, 77, 126, 218, 113, 171, 7, 238, 113, 12, 152, 238, 20, 175, 97, 155, 196, 30,
                204, 126, 160, 234, 193, 58, 113, 98, 12, 214, 67, 79, 220, 254
            ]
        );
    }

    #[test]
    fn big_value_single_big_key_hash() {
        let mut hashers = Vec::new();
        assert_eq!(
            Leaf(vec![0u8; 32], vec![1u8; 32]).hash(&mut hashers),
            vec![
                39, 97, 78, 243, 73, 225, 199, 242, 196, 228, 21, 194, 103, 85, 166, 247, 138, 229,
                54, 32, 16, 17, 243, 46, 71, 115, 81, 139, 131, 214, 203, 184
            ]
        );
    }

    #[test]
    fn empty_value_hash() {
        let mut hashers = Vec::new();
        let node = EmptySlot;
        assert_eq!(node.hash(&mut hashers), vec![]);
    }

    #[test]
    fn full_node_hash() {
        let mut hashers = Vec::new();
        assert_eq!(
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
            .hash(&mut hashers),
            vec![
                220, 134, 197, 128, 131, 4, 5, 6, 128, 134, 197, 9, 131, 10, 11, 12, 128, 128, 128,
                128, 128, 128, 128, 128, 128, 128, 128, 128, 128
            ]
        );
    }


    #[test]
    fn test_bytes2nibbles() {
        let bytes = vec![0xde, 0xad, 0xbe, 0xef];
        assert_eq!(
            bytes2nibbles(&bytes),
            vec![0xd, 0xe, 0xa, 0xd, 0xb, 0xe, 0xe, 0xf]
        );
    }

    #[test]
    fn test_nibble2bytes() {
        let nibbles = vec![0xd, 0xe, 0xa, 0xd, 0xb, 0xe, 0xe, 0xf];
        assert_eq!(nibbles2bytes(&nibbles), vec![0xde, 0xad, 0xbe, 0xef]);
    }
}
