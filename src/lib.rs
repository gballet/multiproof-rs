#![feature(box_syntax, box_patterns)]

extern crate rlp;
extern crate sha3;

pub mod utils;

use sha3::{Digest, Keccak256};
use utils::*;

#[derive(Debug, Clone, PartialEq)]
pub enum Node {
    Hash(Vec<u8>, usize), // (Hash, # empty spaces)
    Leaf(NibbleKey, Vec<u8>),
    Extension(NibbleKey, Box<Node>),
    FullNode(Vec<Node>),
    EmptySlot,
}

impl rlp::Encodable for Node {
    fn rlp_append(&self, s: &mut rlp::RlpStream) {
        match self {
            Node::Leaf(ref k, ref v) => {
                let l: Vec<u8> = k.clone().into();
                s.append_list::<Vec<u8>, Vec<u8>>(&vec![l, v.to_vec()]);
            }
            Node::Extension(ref ext, box node) => {
                let l: Vec<u8> = ext.clone().into();
                let e: Vec<u8> = rlp::encode(node);
                s.append_list::<Vec<u8>, Vec<u8>>(&vec![l, e]);
            }
            _ => panic!("Not supported yet!"),
        }
    }
}

impl rlp::Decodable for Node {
    fn decode(rlp: &rlp::Rlp) -> Result<Self, rlp::DecoderError> {
        if !rlp.is_list() {
            return Err(rlp::DecoderError::RlpExpectedToBeList);
        }
        let keyval = rlp.as_list::<Vec<u8>>()?;
        Ok(Node::Leaf(
            NibbleKey::new(keyval[0].clone()),
            keyval[1].clone(),
        ))
    }
}

impl Node {
    fn hash(&self) -> Vec<u8> {
        use Node::*;
        match self {
            EmptySlot => Vec::new(),
            Leaf(_, _) => {
                let encoding = rlp::encode(self);

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
                let subtree_hash = node.hash();
                let encoding = rlp::encode(self);

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
                    keys.push(node.hash());
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
            Hash(h, _) => h.to_vec(),
        }
    }
}

#[derive(Debug)]
pub enum Instruction {
    BRANCH(usize),
    HASHER(usize),
    LEAF(usize),
    EXTENSION(Vec<u8>),
    ADD(usize),
}

#[derive(Debug)]
pub struct Multiproof {
    pub hashes: Vec<Vec<u8>>,           // List of hashes in the proof
    pub instructions: Vec<Instruction>, // List of instructions in the proof
    pub keyvals: Vec<Vec<u8>>,          // List of RLP-encoded (key, value) pairs in the proof
}

// Rebuilds the tree based on the multiproof components
pub fn rebuild(stack: &mut Vec<Node>, proof: &Multiproof) -> Result<Node, String> {
    use Instruction::*;
    use Node::*;

    let mut hiter = proof.hashes.iter();
    let iiter = proof.instructions.iter();
    let mut kviter = proof.keyvals.iter().map(|encoded| {
        // Deserialize the keys as they are read
        rlp::decode::<Node>(encoded).unwrap()
    });

    for instr in iiter {
        match instr {
            HASHER(digit) => {
                if let Some(h) = hiter.next() {
                    stack.push(Hash(h.to_vec(), *digit));
                } else {
                    return Err(format!("Proof requires one more hash in HASHER({})", digit));
                }
            }
            LEAF(keylength) => {
                if let Some(Leaf(key, value)) = kviter.next() {
                    stack.push(Leaf(
                        NibbleKey::new(key[key.len() - *keylength..].to_vec()),
                        value.to_vec(),
                    ));
                } else {
                    return Err(format!(
                        "Proof requires one more (key,value) pair in LEAF({})",
                        keylength
                    ));
                }
            }
            BRANCH(digit) => {
                if let Some(node) = stack.pop() {
                    let mut children = vec![Node::EmptySlot; 16];
                    children[*digit] = node;
                    stack.push(FullNode(children))
                } else {
                    return Err(format!(
                        "Could not pop a value from the stack, that is required for a BRANCH({})",
                        digit
                    ));
                }
            }
            EXTENSION(key) => {
                if let Some(node) = stack.pop() {
                    stack.push(Extension(NibbleKey::new(key.to_vec()), Box::new(node)));
                } else {
                    return Err(format!(
                        "Could not find a node on the stack, that is required for an EXTENSION({:?})",
                        key
                    ));
                }
            }
            ADD(digit) => {
                if let (Some(el1), Some(el2)) = (stack.pop(), stack.last_mut()) {
                    match el2 {
                        FullNode(ref mut n2) => {
                            if *digit >= n2.len() {
                                return Err(format!(
                                    "Incorrect full node index: {} > {}",
                                    digit,
                                    n2.len() - 1
                                ));
                            }

                            // A hash needs to be fed into the hash sponge, any other node is simply
                            // a child (el1) of the parent node (el2). this is done during resolve.
                            n2[*digit] = el1;
                        }
                        Hash(_, _) => {
                            return Err(String::from("Hash node no longer supported in this case"))
                        }
                        _ => return Err(String::from("Unexpected node type")),
                    }
                } else {
                    return Err(String::from("Could not find enough parameters to ADD"));
                }
            }
        }
    }

    stack
        .pop()
        .ok_or(String::from("Stack underflow, expected root node"))
}

// Insert a `(key,value)` pair into a (sub-)tree represented by `root`.
// It returns the root of the updated (sub-)tree.
pub fn insert_leaf(root: &mut Node, key: Vec<u8>, value: Vec<u8>) -> Result<Node, String> {
    use Node::*;

    if key.len() == 0 {
        return Err("Attempted to insert a 0-byte key".to_string());
    }

    match root {
        Leaf(leafkey, leafvalue) => {
            // Find the common part of the current key with that of the
            // leaf and create an intermediate full node.
            let firstdiffindex = leafkey.factor_length(&NibbleKey::new(key.clone()));

            // Return an error if the leaf is already present.
            if firstdiffindex == key.len() {
                return Err(format!("Key is is already present!",));
            }

            // Create the new root, which is a full node.
            let mut res = vec![EmptySlot; 16];
            // Add the initial leaf, with a key truncated by the common
            // key part.
            res[leafkey[firstdiffindex] as usize] = Leaf(
                NibbleKey::new(leafkey[firstdiffindex + 1..].to_vec()),
                leafvalue.to_vec(),
            );
            // Add the node to be inserted
            res[key[firstdiffindex] as usize] =
                Leaf(NibbleKey::new(key[firstdiffindex + 1..].to_vec()), value);
            // Put the common part into an extension node
            if firstdiffindex == 0 {
                // Special case: no extension necessary
                Ok(FullNode(res))
            } else {
                Ok(Extension(
                    NibbleKey::new(key[..firstdiffindex].to_vec()),
                    Box::new(FullNode(res)),
                ))
            }
        }
        Extension(extkey, box child) => {
            // Find the common part of the current key with that of the
            // extension and create an intermediate full node.
            let firstdiffindex = extkey.factor_length(&NibbleKey::from(key.clone()));

            // Special case: key is longer than the extension key:
            // recurse on the child node.
            if firstdiffindex == extkey.len() {
                let childroot =
                    insert_leaf(&mut child.clone(), key[extkey.len()..].to_vec(), value)?;
                return Ok(Extension(extkey.clone(), Box::new(childroot)));
            }

            // Special case: key is completely unlike the extension key
            if firstdiffindex == 0 {
                let mut res = vec![EmptySlot; 16];

                // Create the entry for the truncated extension key
                // Was it an extension of 1 ? If so, place the node directly
                // otherwise truncate the extension.
                res[extkey[0] as usize] = if extkey.len() == 1 {
                    child.clone()
                } else {
                    Extension(
                        NibbleKey::new(extkey[1..].to_vec()),
                        Box::new(child.clone()),
                    )
                };

                // Create the entry for the node. If there was only a
                // difference of one byte, that byte will be consumed by
                // the fullnode and therefore the key in the leaf will be
                // an empty slice `[]`.
                res[key[0] as usize] = Leaf(NibbleKey::new(key[1..].to_vec()), value);

                return Ok(FullNode(res));
            }

            // Create the new root, which is a full node.
            let mut res = vec![EmptySlot; 16];
            // Add the initial leaf, with a key truncated by the common
            // key part. If the common part corresponds to the extension
            // key length minus one, then there is no need for the creation
            // of an extension node past the full node.
            res[extkey[firstdiffindex] as usize] = if extkey.len() - firstdiffindex > 1 {
                Extension(
                    NibbleKey::new(extkey[firstdiffindex + 1..].to_vec()),
                    Box::new(child.clone()),
                )
            } else {
                child.clone()
            };
            // Add the node to be inserted
            res[key[firstdiffindex] as usize] =
                Leaf(NibbleKey::new(key[firstdiffindex + 1..].to_vec()), value);
            // Put the common part into an extension node
            Ok(Extension(
                NibbleKey::new(extkey[..firstdiffindex].to_vec()),
                Box::new(FullNode(res)),
            ))
        }
        FullNode(ref mut vec) => {
            let idx = key[0] as usize;
            // If the slot isn't yet in use, fill it, and otherwise,
            // recurse into the child node.
            vec[idx] = if vec[idx] == EmptySlot {
                // XXX check that the value is at least 1
                Leaf(NibbleKey::new(key[1..].to_vec()), value)
            } else {
                insert_leaf(&mut vec[idx], key[idx + 1..].to_vec(), value)?
            };
            // Return the root node with an updated entry
            Ok(FullNode(vec.to_vec()))
        }
        _ => panic!("Not supported yet"),
    }
}

// Helper function that generates a multiproof based on one `(key.value)`
// pair.
pub fn make_multiproof(
    root: &Node,
    keyvals: Vec<(Vec<u8>, Vec<u8>)>,
) -> Result<Multiproof, String> {
    use Node::*;

    let mut instructions = Vec::new();
    let mut values = Vec::new();
    let mut hashes = Vec::new();

    // If there are no keys specified at this node, then just hash that
    // node.
    if keyvals.len() == 0 {
        return Ok(Multiproof {
            instructions: vec![Instruction::HASHER(0)],
            hashes: vec![root.hash()],
            keyvals: vec![],
        });
    }

    // Recurse into each node, follow the trace
    match root {
        EmptySlot => return Err("Cannot build a multiproof on an empty slot".to_string()),
        FullNode(ref vec) => {
            // Split the current (key,value) tuples based on the first
            // nibble of their keys. Build a recursion table.
            let mut split = vec![Vec::new(); 16];
            for (k, v) in keyvals.iter() {
                let idx = k[0] as usize;
                split[idx].push((k[1..].to_vec(), v.to_vec()));
            }

            // Now recurse on each selector. If the recursion table is
            // empty, then the subnode needs to be hashed. Otherwise,
            // we must recurse.
            // `branch` is set to true at first, which is meant to add
            // a `BRANCH` instruction the first time that a child is
            // added to the node. All subsequent adds will be performed
            // by an `ADD` instruction.
            let mut branch = true;
            for (selector, subkeys) in split.iter().enumerate() {
                // Does the child have any key? If not, it will be hashed
                // and a `HASHER` instruction will be added to the list.
                if split[selector].len() == 0 {
                    // Empty slots are not to be hashed
                    if vec[selector] != EmptySlot {
                        instructions.push(Instruction::HASHER(0));
                        if branch {
                            instructions.push(Instruction::BRANCH(selector));
                            branch = false;
                        } else {
                            instructions.push(Instruction::ADD(selector));
                        }
                        hashes.push(vec[selector].hash());
                    }
                } else {
                    let mut proof = make_multiproof(&vec[selector], subkeys.to_vec())?;
                    instructions.append(&mut proof.instructions);
                    if branch {
                        instructions.push(Instruction::BRANCH(selector));
                        branch = false;
                    } else {
                        instructions.push(Instruction::ADD(selector));
                    }
                    hashes.append(&mut proof.hashes);
                    values.append(&mut proof.keyvals);
                }
            }
        }
        Leaf(leafkey, _) => {
            if keyvals.len() != 1 {
                return Err(format!(
                    "Expecting exactly 1 key in leaf, got {}: {:?}",
                    keyvals.len(),
                    keyvals
                )
                .to_string());
            }

            let key = &keyvals[0].0;
            if *leafkey == NibbleKey::new(key.to_vec()) {
                instructions.push(Instruction::LEAF(key.len()));
                let rlp = rlp::encode(&Leaf(NibbleKey::new(key.clone()), keyvals[0].1.clone()));
                values.push(rlp);
            } else {
                return Err(
                    format!("Trying to apply the wrong key {:?} != {:?}", key, leafkey).to_string(),
                );
            }
        }
        Extension(extkey, box child) => {
            // Make sure that all the keys follow the extension and
            // if so, then recurse.
            let mut truncated = vec![];
            for (k, v) in keyvals.iter() {
                if extkey.factor_length(&NibbleKey::new(k.clone())) != extkey.len() {
                    return Err(
                        format!("One of the keys isn't present in the tree: {:?}", k).to_string(),
                    );
                }
                truncated.push((k.to_vec(), v.to_vec()));
            }
            let mut proof = make_multiproof(child, truncated)?;
            hashes.append(&mut proof.hashes);
            instructions.append(&mut proof.instructions);
            values.append(&mut proof.keyvals);
        }
        Hash(_, _) => return Err("Should not have encountered a Hash in this context".to_string()),
    }

    Ok(Multiproof {
        instructions: instructions,
        hashes: hashes,
        keyvals: values,
    })
}

#[cfg(test)]
mod tests {
    extern crate hex;
    //extern crate rand;

    use super::Instruction::*;
    use super::Node::*;
    use super::*;
    //use rand::prelude::*;

    #[test]
    fn validate_tree() {
        let mut root = FullNode(vec![EmptySlot; 16]);
        insert_leaf(&mut root, vec![2u8; 32], vec![0u8; 32]).unwrap();
        insert_leaf(&mut root, vec![1u8; 32], vec![1u8; 32]).unwrap();
        insert_leaf(&mut root, vec![8u8; 32], vec![150u8; 32]).unwrap();

        let changes = vec![
            (vec![2u8; 32], vec![4u8; 32]),
            (vec![1u8; 32], vec![8u8; 32]),
        ];

        let proof = make_multiproof(&root, changes.clone()).unwrap();

        let mut stack = Vec::new();
        let proof = Multiproof {
            hashes: proof.hashes,
            keyvals: proof.keyvals,
            instructions: proof.instructions,
        };
        let new_root = rebuild(&mut stack, &proof).unwrap();

        assert_eq!(
            new_root,
            FullNode(vec![
                EmptySlot,
                Leaf(
                    NibbleKey::new(vec![
                        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                        1, 1, 1, 1, 1, 1
                    ]),
                    vec![
                        8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
                        8, 8, 8, 8, 8, 8, 8
                    ]
                ),
                Leaf(
                    NibbleKey::new(vec![
                        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
                        2, 2, 2, 2, 2, 2
                    ]),
                    vec![
                        4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
                        4, 4, 4, 4, 4, 4, 4
                    ]
                ),
                EmptySlot,
                EmptySlot,
                EmptySlot,
                EmptySlot,
                EmptySlot,
                Hash(
                    vec![
                        154, 251, 173, 154, 224, 13, 237, 90, 6, 107, 214, 240, 236, 103, 164, 93,
                        81, 243, 28, 37, 128, 102, 185, 151, 233, 187, 131, 54, 188, 19, 235, 168
                    ],
                    0
                ),
                EmptySlot,
                EmptySlot,
                EmptySlot,
                EmptySlot,
                EmptySlot,
                EmptySlot,
                EmptySlot
            ])
        );
    }

    #[test]
    fn make_multiproof_two_values() {
        let mut root = FullNode(vec![EmptySlot; 16]);
        insert_leaf(&mut root, vec![2u8; 32], vec![0u8; 32]).unwrap();
        insert_leaf(&mut root, vec![1u8; 32], vec![1u8; 32]).unwrap();
        insert_leaf(&mut root, vec![8u8; 32], vec![150u8; 32]).unwrap();

        let proof = make_multiproof(
            &root,
            vec![
                (vec![2u8; 32], vec![4u8; 32]),
                (vec![1u8; 32], vec![8u8; 32]),
            ],
        )
        .unwrap();
        let i = proof.instructions;
        let v = proof.keyvals;
        let h = proof.hashes;
        assert_eq!(i.len(), 6); // [LEAF, BRANCH, LEAF, ADD, HASHER, ADD]
        match i[0] {
            // Key length is 31
            LEAF(n) => assert_eq!(n, 31),
            _ => panic!(format!("Invalid instruction {:?}", i[0])),
        }
        match i[1] {
            BRANCH(n) => assert_eq!(n, 1),
            _ => panic!(format!("Invalid instruction {:?}", i[1])),
        }
        match i[2] {
            // Key length is 31
            LEAF(n) => assert_eq!(n, 31),
            _ => panic!(format!("Invalid instruction {:?}", i[2])),
        }
        match i[3] {
            ADD(n) => assert_eq!(n, 2),
            _ => panic!(format!("Invalid instruction {:?}", i[3])),
        }
        match i[5] {
            ADD(n) => assert_eq!(n, 8),
            _ => panic!(format!("Invalid instruction {:?}", i[5])),
        }
        assert_eq!(h.len(), 1); // Only one hash
        assert_eq!(v.len(), 2);
        assert_eq!(
            v[0],
            rlp::encode(&Leaf(NibbleKey::new(vec![1u8; 31]), vec![8u8; 32]))
        );
        assert_eq!(
            v[1],
            rlp::encode(&Leaf(NibbleKey::new(vec![2u8; 31]), vec![4u8; 32]))
        );
    }

    #[test]
    fn make_multiproof_single_value() {
        let mut root = FullNode(vec![EmptySlot; 16]);
        insert_leaf(&mut root, vec![2u8; 32], vec![0u8; 32]).unwrap();
        insert_leaf(&mut root, vec![1u8; 32], vec![1u8; 32]).unwrap();

        let proof = make_multiproof(&root, vec![(vec![1u8; 32], vec![1u8; 32])]).unwrap();
        let i = proof.instructions;
        let v = proof.keyvals;
        let h = proof.hashes;
        assert_eq!(i.len(), 4); // [LEAF, BRANCH, HASHER, ADD]
        match i[0] {
            // Key length is 31
            LEAF(n) => assert_eq!(n, 31),
            _ => panic!(format!("Invalid instruction {:?}", i[0])),
        }
        match i[1] {
            BRANCH(n) => assert_eq!(n, 1),
            _ => panic!(format!("Invalid instruction {:?}", i[1])),
        }
        match i[2] {
            HASHER(n) => assert_eq!(n, 0),
            _ => panic!(format!("Invalid instruction {:?}", i[2])),
        }
        match i[3] {
            ADD(n) => assert_eq!(n, 2),
            _ => panic!(format!("Invalid instruction {:?}", i[3])),
        }
        assert_eq!(h.len(), 1); // Only one hash
        assert_eq!(v.len(), 1); // Only one value
        assert_eq!(
            v[0],
            rlp::encode(&Leaf(NibbleKey::new(vec![1u8; 31]), vec![1u8; 32]))
        );
    }

    #[test]
    fn make_multiproof_no_values() {
        let mut root = FullNode(vec![EmptySlot; 16]);
        insert_leaf(&mut root, vec![2u8; 32], vec![0u8; 32]).unwrap();
        insert_leaf(&mut root, vec![1u8; 32], vec![1u8; 32]).unwrap();

        let proof = make_multiproof(&root, vec![]).unwrap();
        let i = proof.instructions;
        let v = proof.keyvals;
        let h = proof.hashes;
        assert_eq!(i.len(), 1);
        assert_eq!(h.len(), 1);
        assert_eq!(v.len(), 0);
    }

    #[test]
    fn make_multiproof_empty_tree() {
        let root = FullNode(vec![EmptySlot; 16]);

        let out = make_multiproof(&root, vec![(vec![1u8; 32], vec![1u8; 32])]);
        assert!(out.is_err());
    }

    #[test]
    fn make_multiproof_hash_before_nested_nodes_in_branch() {
        let mut root = FullNode(vec![EmptySlot; 16]);
        insert_leaf(&mut root, vec![1u8; 32], vec![0u8; 32]).unwrap();
        insert_leaf(&mut root, vec![2u8; 32], vec![0u8; 32]).unwrap();

        let pre_root_hash = root.hash();

        let proof = make_multiproof(&root, vec![(vec![2u8; 32], vec![0u8; 32])]).unwrap();

        let mut stack = Vec::new();
        let res = rebuild(&mut stack, &proof);

        assert_eq!(res.unwrap().hash(), pre_root_hash);
    }

    #[test]
    fn insert_leaf_zero_length_key_after_fullnode() {
        let mut root = Extension(
            NibbleKey::new(vec![0u8; 31]),
            Box::new(FullNode(vec![
                EmptySlot,
                Leaf(NibbleKey::new(vec![]), vec![0u8; 32]),
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
            ])),
        );
        let out = insert_leaf(&mut root, vec![0u8; 32], vec![1u8; 32]).unwrap();
        assert_eq!(
            out,
            Extension(
                NibbleKey::new(vec![0u8; 31]),
                Box::new(FullNode(vec![
                    Leaf(NibbleKey::new(vec![]), vec![1u8; 32]),
                    Leaf(NibbleKey::new(vec![]), vec![0u8; 32]),
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
                ]))
            )
        );
    }

    #[test]
    fn insert_leaf_into_extension_root_all_bytes_in_key_common() {
        let mut root = Extension(
            NibbleKey::new(vec![0xd, 0xe, 0xa, 0xd]),
            Box::new(Leaf(NibbleKey::new(vec![0u8; 28]), vec![1u8; 32])),
        );
        let mut key = vec![1u8; 32];
        key[0] = 0xd;
        key[1] = 0xe;
        key[2] = 0xa;
        key[3] = 0xd;
        let out = insert_leaf(&mut root, key, vec![2u8; 32]).unwrap();
        assert_eq!(
            out,
            Extension(
                NibbleKey::new(vec![0xd, 0xe, 0xa, 0xd]),
                Box::new(FullNode(vec![
                    Leaf(NibbleKey::new(vec![0u8; 27]), vec![1u8; 32]),
                    Leaf(NibbleKey::new(vec![1u8; 27]), vec![2u8; 32]),
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
                ]))
            )
        );
    }

    #[test]
    fn insert_leaf_into_extension_root_no_common_bytes_in_key() {
        let mut root = Extension(
            NibbleKey::new(vec![0xd, 0xe, 0xa, 0xd]),
            Box::new(Leaf(NibbleKey::new(vec![0u8; 24]), vec![1u8; 32])),
        );
        let out = insert_leaf(&mut root, vec![2u8; 32], vec![1u8; 32]).unwrap();
        assert_eq!(
            out,
            FullNode(vec![
                EmptySlot,
                EmptySlot,
                Leaf(NibbleKey::new(vec![2u8; 31]), vec![1u8; 32]),
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
                Extension(
                    NibbleKey::new(vec![14, 10, 13]),
                    Box::new(Leaf(NibbleKey::new(vec![0u8; 24]), vec![1u8; 32]))
                ),
                EmptySlot,
                EmptySlot
            ])
        );
    }

    #[test]
    fn insert_leaf_into_extension_root_half_bytes_in_key_common() {
        let mut root = Extension(
            NibbleKey::new(vec![0xd, 0xe, 0xa, 0xd]),
            Box::new(Leaf(NibbleKey::new(vec![0u8; 28]), vec![1u8; 32])),
        );
        let mut key = vec![0u8; 32];
        key[0] = 0xd;
        key[1] = 0xe;
        let out = insert_leaf(&mut root, key, vec![1u8; 32]).unwrap();
        assert_eq!(
            out,
            Extension(
                NibbleKey::new(vec![0xd, 0xe]),
                Box::new(FullNode(vec![
                    Leaf(NibbleKey::new(vec![0u8; 29]), vec![1u8; 32]),
                    EmptySlot,
                    EmptySlot,
                    EmptySlot,
                    EmptySlot,
                    EmptySlot,
                    EmptySlot,
                    EmptySlot,
                    EmptySlot,
                    EmptySlot,
                    Extension(
                        NibbleKey::new(vec![0xd]),
                        Box::new(Leaf(NibbleKey::new(vec![0u8; 28]), vec![1u8; 32]))
                    ),
                    EmptySlot,
                    EmptySlot,
                    EmptySlot,
                    EmptySlot,
                    EmptySlot
                ]))
            )
        );
    }

    #[test]
    fn insert_leaf_into_extension_root_almost_all_bytes_in_key_common() {
        let mut root = Extension(
            NibbleKey::new(vec![0xd, 0xe, 0xa, 0xd]),
            Box::new(Leaf(NibbleKey::new(vec![0u8; 28]), vec![1u8; 32])),
        );
        let mut key = vec![0u8; 32];
        key[0] = 0xd;
        key[1] = 0xe;
        key[2] = 0xa;
        let out = insert_leaf(&mut root, key, vec![1u8; 32]).unwrap();
        assert_eq!(
            out,
            Extension(
                NibbleKey::new(vec![0xd, 0xe, 0xa]),
                Box::new(FullNode(vec![
                    Leaf(NibbleKey::new(vec![0u8; 28]), vec![1u8; 32]),
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
                    Leaf(NibbleKey::new(vec![0u8; 28]), vec![1u8; 32]),
                    EmptySlot,
                    EmptySlot
                ]))
            )
        );
    }

    #[test]
    fn insert_leaf_into_leaf_root_common_bytes_in_key() {
        let mut key = vec![0u8; 32];
        for (i, v) in key.iter_mut().enumerate() {
            if i >= 16 {
                break;
            }
            *v = 2u8;
        }
        let mut root = Leaf(NibbleKey::new(key), vec![1u8; 32]);
        let out = insert_leaf(&mut root, vec![2u8; 32], vec![1u8; 32]).unwrap();
        assert_eq!(
            out,
            Extension(
                NibbleKey::new(vec![2u8; 16]),
                Box::new(FullNode(vec![
                    Leaf(NibbleKey::new(vec![0u8; 15]), vec![1u8; 32]),
                    EmptySlot,
                    Leaf(NibbleKey::new(vec![2u8; 15]), vec![1u8; 32]),
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
        );
    }

    #[test]
    fn insert_leaf_into_leaf_root_no_common_bytes_in_key() {
        let mut root = Leaf(NibbleKey::new(vec![1u8; 32]), vec![1u8; 32]);
        let out = insert_leaf(&mut root, vec![2u8; 32], vec![1u8; 32]).unwrap();
        assert_eq!(
            out,
            FullNode(vec![
                EmptySlot,
                Leaf(NibbleKey::new(vec![1u8; 31]), vec![1u8; 32]),
                Leaf(NibbleKey::new(vec![2u8; 31]), vec![1u8; 32]),
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
        );
    }

    #[test]
    fn insert_leaf_into_empty_root() {
        let children = vec![EmptySlot; 16];
        let mut root = FullNode(children);
        let out = insert_leaf(&mut root, vec![0u8; 32], vec![1u8; 32]);
        assert_eq!(
            out.unwrap(),
            FullNode(vec![
                Leaf(NibbleKey::new(vec![0u8; 31]), vec![1u8; 32]),
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
        );
    }

    #[test]
    fn insert_leaf_into_two_level_fullnodes() {
        let mut root = FullNode(vec![
            FullNode(vec![EmptySlot; 16]),
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
            EmptySlot,
        ]);
        let out = insert_leaf(&mut root, vec![0u8; 32], vec![1u8; 32]);
        assert_eq!(
            out.unwrap(),
            FullNode(vec![
                FullNode(vec![
                    Leaf(NibbleKey::new(vec![0u8; 30]), vec![1u8; 32]),
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
                ]),
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
        );
    }

    #[test]
    fn tree_with_just_one_leaf() {
        let mut stack = Vec::new();
        let proof = Multiproof {
            hashes: vec![],
            keyvals: vec![rlp::encode_list::<Vec<u8>, Vec<u8>>(&vec![
                vec![1, 2, 3],
                vec![4, 5, 6],
            ])],
            instructions: vec![LEAF(0)],
        };
        let out = rebuild(&mut stack, &proof).unwrap();
        assert_eq!(out, Leaf(NibbleKey::new(vec![]), vec![4, 5, 6]))
    }

    #[test]
    fn tree_with_one_branch() {
        let mut stack = Vec::new();
        let proof = Multiproof {
            hashes: vec![],
            keyvals: vec![rlp::encode_list::<Vec<u8>, Vec<u8>>(&vec![
                vec![1, 2, 3],
                vec![4, 5, 6],
            ])],
            instructions: vec![LEAF(0), BRANCH(0)],
        };
        let out = rebuild(&mut stack, &proof).unwrap();
        assert_eq!(
            out,
            FullNode(vec![
                Leaf(NibbleKey::new(vec![]), vec![4, 5, 6]),
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
        let proof = Multiproof {
            hashes: vec![],
            keyvals: vec![
                rlp::encode_list::<Vec<u8>, Vec<u8>>(&vec![vec![1, 2, 3], vec![4, 5, 6]]),
                rlp::encode_list::<Vec<u8>, Vec<u8>>(&vec![vec![7, 8, 9], vec![10, 11, 12]]),
            ],
            instructions: vec![LEAF(0), BRANCH(0), LEAF(1), ADD(2)],
        };
        let out = rebuild(&mut stack, &proof).unwrap();
        assert_eq!(
            out,
            FullNode(vec![
                Leaf(NibbleKey::new(vec![]), vec![4, 5, 6]),
                EmptySlot,
                Leaf(NibbleKey::new(vec![9]), vec![10, 11, 12]),
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
        let proof = Multiproof {
            hashes: vec![],
            instructions: vec![
                LEAF(0),
                BRANCH(0),
                LEAF(1),
                ADD(2),
                EXTENSION(vec![13, 14, 15]),
            ],
            keyvals: vec![
                rlp::encode_list::<Vec<u8>, Vec<u8>>(&vec![vec![1, 2, 3], vec![4, 5, 6]]),
                rlp::encode_list::<Vec<u8>, Vec<u8>>(&vec![vec![7, 8, 9], vec![10, 11, 12]]),
            ],
        };
        let out = rebuild(&mut stack, &proof).unwrap();
        assert_eq!(
            out,
            Extension(
                NibbleKey::new(vec![13, 14, 15]),
                Box::new(FullNode(vec![
                    Leaf(NibbleKey::new(vec![]), vec![4, 5, 6]),
                    EmptySlot,
                    Leaf(NibbleKey::new(vec![9]), vec![10, 11, 12]),
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
        assert_eq!(
            Leaf(NibbleKey::new(vec![1, 2, 3]), vec![4, 5, 6]).hash(),
            vec![200, 131, 1, 2, 3, 131, 4, 5, 6]
        );
    }

    #[test]
    fn big_value_single_key_hash() {
        assert_eq!(
            Leaf(NibbleKey::new(vec![0u8; 32]), vec![4, 5, 6]).hash(),
            vec![
                0, 77, 126, 218, 113, 171, 7, 238, 113, 12, 152, 238, 20, 175, 97, 155, 196, 30,
                204, 126, 160, 234, 193, 58, 113, 98, 12, 214, 67, 79, 220, 254
            ]
        );
    }

    #[test]
    fn big_value_single_big_key_hash() {
        assert_eq!(
            Leaf(NibbleKey::new(vec![0u8; 32]), vec![1u8; 32]).hash(),
            vec![
                39, 97, 78, 243, 73, 225, 199, 242, 196, 228, 21, 194, 103, 85, 166, 247, 138, 229,
                54, 32, 16, 17, 243, 46, 71, 115, 81, 139, 131, 214, 203, 184
            ]
        );
    }

    #[test]
    fn empty_value_hash() {
        let node = EmptySlot;
        assert_eq!(node.hash(), vec![]);
    }

    #[test]
    fn full_node_hash() {
        assert_eq!(
            FullNode(vec![
                Leaf(NibbleKey::new(vec![]), vec![4, 5, 6]),
                EmptySlot,
                Leaf(NibbleKey::new(vec![9]), vec![10, 11, 12]),
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
            .hash(),
            vec![
                220, 134, 197, 128, 131, 4, 5, 6, 128, 134, 197, 9, 131, 10, 11, 12, 128, 128, 128,
                128, 128, 128, 128, 128, 128, 128, 128, 128, 128
            ]
        );
    }
}
