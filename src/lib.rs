#![feature(box_syntax, box_patterns)]

extern crate rlp;
extern crate sha3;

pub mod binary_tree;
pub mod instruction;
pub mod keys;
pub mod multiproof;
pub mod node;
pub mod tree;

pub use instruction::*;
pub use keys::*;
pub use multiproof::*;
pub use node::*;
pub use tree::{NodeType, Tree};

impl<N: NodeType, T: Tree<N> + rlp::Decodable> ProofToTree<N, T> for Multiproof {
    fn rebuild(&self) -> Result<T, String> {
        use Instruction::*;

        let mut hiter = self.hashes.iter();
        let iiter = self.instructions.iter();
        let mut kviter = self.keyvals.iter().map(|encoded| {
            // Deserialize the keys as they are read
            rlp::decode::<T>(encoded).unwrap()
        });

        let mut stack = Vec::<T>::new();

        for instr in iiter {
            match instr {
                HASHER => {
                    if let Some(h) = hiter.next() {
                        stack.push(T::from_hash(h.to_vec()));
                    } else {
                        return Err("Proof requires one more hash in HASHER".to_string());
                    }
                }
                LEAF(keylength) => {
                    if let Some(leaf) = kviter.next() {
                        // If the value is empty, we have a NULL key and
                        // therefore an EmptySlot should be returned.
                        match leaf.value() {
                            None => stack.push(T::new_empty()),
                            Some(_) => {
                                if leaf.value_length().unwrap() == 0usize {
                                    stack.push(T::new_empty())
                                } else {
                                    stack.push(leaf)
                                }
                            }
                        }
                    } else {
                        return Err(format!(
                            "Proof requires one more (key,value) pair in LEAF({})",
                            keylength
                        ));
                    }
                }
                BRANCH(digit) => {
                    if let Some(ref node) = stack.pop() {
                        let mut b = T::new_branch();
                        b.set_ith_child(*digit, node);
                        stack.push(b)
                    } else {
                        return Err(format!(
                "Could not pop a value from the stack, that is required for a BRANCH({})",
                digit
                ));
                    }
                }
                EXTENSION(key) => {
                    if let Some(node) = stack.pop() {
                        stack.push(T::new_extension(key.to_vec(), node));
                    } else {
                        return Err(format!(
                "Could not find a node on the stack, that is required for an EXTENSION({:?})",
                key
                ));
                    }
                }
                ADD(digit) => {
                    if let (Some(el1), Some(el2)) = (stack.pop(), stack.last_mut()) {
                        // Only true if this is a branch node
                        if el2.num_children() > 1 {
                            if *digit >= el2.num_children() {
                                return Err(format!(
                                    "Incorrect full node index: {} > {}",
                                    digit,
                                    el2.num_children()
                                ));
                            }

                            // Any node is simply a child (el1) of the parent node (el2). This is done
                            // during resolve.
                            el2.set_ith_child(*digit, &el1);
                        } else {
                            return Err(String::from("Could not find enough parameters to ADD"));
                        }
                    } else {
                        return Err(String::from("Could not find enough parameters to ADD"));
                    }
                }
            }
        }

        stack
            .pop()
            .ok_or_else(|| "Stack underflow, expected root node".to_string())
    }
}

// Helper function that generates a multiproof based on one `(key.value)`
// pair.
pub fn make_multiproof(root: &Node, keys: Vec<NibbleKey>) -> Result<Multiproof, String> {
    use Node::*;

    let mut instructions = Vec::new();
    let mut values = Vec::new();
    let mut hashes = Vec::new();

    // If there are no keys specified at this node, then just hash that
    // node.
    if keys.is_empty() {
        return Ok(Multiproof {
            instructions: vec![Instruction::HASHER],
            hashes: vec![root.hash()],
            keyvals: vec![],
        });
    }

    // Recurse into each node, follow the trace
    match root {
        EmptySlot => {
            // This is a key that doesn't exist, add a leaf with no
            // value to mark the fact that it is not present in the
            // tree.
            instructions.push(Instruction::LEAF(0));
            values.push(rlp::encode(&Leaf(Vec::new().into(), Vec::new())));
        }
        Branch(ref vec) => {
            // Split the current keys based on their first nibble, in order
            // to dispatch each key to the proper sublevel.
            let mut dispatch = vec![Vec::new(); 16];
            for k in keys.iter() {
                let idx = k[0] as usize;
                dispatch[idx].push(NibbleKey::from(&k[1..]));
            }

            // Now recurse on each selector. If the dispatch table entry
            // is empty, then the subnode needs to be hashed. Otherwise,
            // recurse on the subnode, with the subkeys.
            // `branch` is set to true at first, which is meant to add
            // a `BRANCH` instruction the first time that a child is
            // added to the node. All subsequent adds will be performed
            // by an `ADD` instruction.
            let mut branch = true;
            for (selector, subkeys) in dispatch.iter().enumerate() {
                // Does the child have any key? If not, it will be hashed
                // and a `HASHER` instruction will be added to the list.
                if dispatch[selector].is_empty() {
                    // Empty slots are not to be hashed
                    if vec[selector] != EmptySlot {
                        instructions.push(Instruction::HASHER);
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
        Leaf(leafkey, leafval) => {
            // This is the simplest case: the key that is found at this
            // level in the recursion needs to match the unique one in
            // the list of keys that belong to the proof.
            if keys.len() != 1 {
                return Err(format!(
                    "Expecting exactly 1 key in leaf, got {}: {:?}",
                    keys.len(),
                    keys
                ));
            }

            // Here two things can happen:
            // 1. The key suffix is the same as the one in the leaf,
            //    so that leaf is added to the proof.
            // 2. The key is different as the one in the leaf, so the
            //    correct leaf is added to point out that the key that
            //    was requested is not the one in the proof.
            instructions.push(Instruction::LEAF(leafkey.len()));
            let rlp = rlp::encode(&Leaf(leafkey.clone(), leafval.clone()));
            values.push(rlp);
        }
        Extension(extkey, box child) => {
            // Make sure that all keys have the same prefix, corresponding
            // to the extension. If that is the case, recurse with the
            // prefix removed.
            let mut truncated = vec![];
            for k in keys.iter() {
                let factor_length = extkey.common_prefix(k);
                // If a key has a prefix that differs from that of the extension,
                // then it is missing in this tree and is not added to the list
                // of shortened keys to be recursively passed down. This special
                // case is handled after the loop.
                if factor_length == extkey.len() {
                    truncated.push(NibbleKey::from(&k[factor_length..]));
                }
            }
            // If truncated.len() > 0, there is at least one requested key
            // whose presence can not be determined at this level. If so,
            // then recurse on it, and ignore all nonexistent key, as the
            // presence of existing keys prove that those missing are not
            // present in the tree.
            if !truncated.is_empty() {
                let mut proof = make_multiproof(child, truncated)?;
                hashes.append(&mut proof.hashes);
                instructions.append(&mut proof.instructions);
                values.append(&mut proof.keyvals);
                instructions.push(Instruction::EXTENSION(extkey.clone().into()));
            } else {
                // If none of the keys are present, then we are requesting a
                // proof that these keys are missing. This is done with a hash
                // node, whose presence signals: "I know that the tree went
                // to a different direction at that point, and I don't need to
                // go any further down".
                hashes.push(child.hash());
                instructions.push(Instruction::HASHER);
                instructions.push(Instruction::EXTENSION(extkey.clone().into()));
            }
        }
        Hash(_) => return Err("Should not have encountered a Hash in this context".to_string()),
    }

    Ok(Multiproof {
        instructions,
        hashes,
        keyvals: values,
    })
}

#[cfg(test)]
mod tests {
    extern crate hex;

    use super::tree::*;
    use super::Instruction::*;
    use super::Node::*;
    use super::*;
    use sha3::{Digest, Keccak256};

    #[test]
    fn validate_tree() {
        let mut root = Node::default();
        root.insert(&NibbleKey::from(vec![2u8; 32]), vec![0u8; 32])
            .unwrap();
        root.insert(&NibbleKey::from(vec![1u8; 32]), vec![1u8; 32])
            .unwrap();
        root.insert(&NibbleKey::from(vec![8u8; 32]), vec![150u8; 32])
            .unwrap();

        let keys = vec![
            NibbleKey::from(vec![2u8; 32]),
            NibbleKey::from(vec![1u8; 32]),
        ];

        let proof = make_multiproof(&root, keys.clone()).unwrap();

        let proof = Multiproof {
            hashes: proof.hashes,
            keyvals: proof.keyvals,
            instructions: proof.instructions,
        };
        let new_root: Node = proof.rebuild().unwrap();

        assert_eq!(
            new_root,
            Branch(vec![
                EmptySlot,
                Leaf(NibbleKey::from(vec![1u8; 31]), vec![1u8; 32]),
                Leaf(NibbleKey::from(vec![2u8; 31]), vec![0u8; 32]),
                EmptySlot,
                EmptySlot,
                EmptySlot,
                EmptySlot,
                EmptySlot,
                Hash(vec![
                    14, 142, 96, 165, 156, 5, 72, 38, 156, 85, 14, 69, 181, 246, 113, 175, 254,
                    205, 123, 70, 93, 101, 33, 244, 149, 177, 98, 113, 75, 151, 252, 227
                ]),
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
        let mut root = Node::default();
        root.insert(&NibbleKey::from(vec![2u8; 32]), vec![0u8; 32])
            .unwrap();
        root.insert(&NibbleKey::from(vec![1u8; 32]), vec![1u8; 32])
            .unwrap();
        root.insert(&NibbleKey::from(vec![8u8; 32]), vec![150u8; 32])
            .unwrap();

        let proof = make_multiproof(
            &root,
            vec![
                NibbleKey::from(vec![2u8; 32]),
                NibbleKey::from(vec![1u8; 32]),
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
            rlp::encode(&Leaf(NibbleKey::from(vec![1u8; 31]), vec![1u8; 32]))
        );
        assert_eq!(
            v[1],
            rlp::encode(&Leaf(NibbleKey::from(vec![2u8; 31]), vec![0u8; 32]))
        );
    }

    #[test]
    fn make_multiproof_single_value() {
        let mut root = Node::default();
        root.insert(&NibbleKey::from(vec![2u8; 32]), vec![0u8; 32])
            .unwrap();
        root.insert(&NibbleKey::from(vec![1u8; 32]), vec![1u8; 32])
            .unwrap();

        let proof = make_multiproof(&root, vec![NibbleKey::from(vec![1u8; 32])]).unwrap();
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
        assert_eq!(i[2], HASHER);
        match i[3] {
            ADD(n) => assert_eq!(n, 2),
            _ => panic!(format!("Invalid instruction {:?}", i[3])),
        }
        assert_eq!(h.len(), 1); // Only one hash
        assert_eq!(v.len(), 1); // Only one value
        assert_eq!(
            v[0],
            rlp::encode(&Leaf(NibbleKey::from(vec![1u8; 31]), vec![1u8; 32]))
        );
    }

    #[test]
    fn make_multiproof_no_values() {
        let mut root = Node::default();
        root.insert(&NibbleKey::from(vec![2u8; 32]), vec![0u8; 32])
            .unwrap();
        root.insert(&NibbleKey::from(vec![1u8; 32]), vec![1u8; 32])
            .unwrap();

        let proof = make_multiproof(&root, vec![]).unwrap();
        let i = proof.instructions;
        let v = proof.keyvals;
        let h = proof.hashes;
        assert_eq!(i.len(), 1);
        assert_eq!(h.len(), 1);
        assert_eq!(v.len(), 0);
    }

    #[test]
    fn make_multiproof_hash_before_nested_nodes_in_branch() {
        let mut root = Node::default();
        root.insert(&NibbleKey::from(vec![1u8; 32]), vec![0u8; 32])
            .unwrap();
        root.insert(&NibbleKey::from(vec![2u8; 32]), vec![0u8; 32])
            .unwrap();

        let pre_root_hash = root.hash();

        let proof = make_multiproof(&root, vec![NibbleKey::from(vec![2u8; 32])]).unwrap();

        let res: Node = proof.rebuild().unwrap();

        assert_eq!(res.hash(), pre_root_hash);
    }

    #[test]
    fn make_multiproof_two_leaves_with_extension() {
        let inputs = [
            ("0x1111111111111111111111111111111111111111", vec![15u8; 32]),
            ("0x2222222222222222222222222222222222222222", vec![14u8; 32]),
            ("0x1111111111333333333333333333333333333333", vec![13u8; 32]),
        ];

        let nibble_from_hex = |h| NibbleKey::from(keys::ByteKey(hex::decode(h).unwrap()));

        let mut root = Node::default();
        for i in &inputs {
            let k = nibble_from_hex(&i.0[2..]);
            root.insert(&k, i.1.clone()).unwrap();
        }

        let pre_root_hash = root.hash();

        let keys = vec![
            nibble_from_hex(&inputs[2].0[2..]),
            nibble_from_hex(&inputs[0].0[2..]),
        ];
        let proof = make_multiproof(&root, keys).unwrap();

        let res: Node = proof.rebuild().unwrap();

        assert_eq!(res.hash(), pre_root_hash);
    }

    #[test]
    fn make_tree_from_json() {
        let data = r#"
{"0xe4397428176a9d67f315f2e6629fd765d42ae7e1":{"balance":"0xffffff","code":"","nonce":"0x00","storage":{}},"0x991d76d11c89f559eea25023d0dc46e3dd6fb950":{"balance":"0xffffff","code":"","nonce":"0x00","storage":{}},"0xcb4a4c7f9e05986b14637f39d450f0b7dd1b1d18":{"balance":"0xffffff","code":"","nonce":"0x00","storage":{}},"0xe45f028817e60dacaddf883e58fe95473064b442":{"balance":"0xffffff","code":"","nonce":"0x00","storage":{}},"0x04a7e6a2ab8e6052c1c43b479cfe259909c9e010":{"balance":"0xffffff","code":"","nonce":"0x00","storage":{}},"0x0964b7eb170f9b4ca78993dfc15651b0774dd736":{"balance":"0xffffff","code":"","nonce":"0x00","storage":{}},"0xc2a0bc0b3b823ef42949608e27c4f466d4396094":{"balance":"0xffffff","code":"","nonce":"0x00","storage":{}},"0x9bf5beb53363eaa698f2b7dc168d5f66226545c1":{"balance":"0xffffff","code":"","nonce":"0x00","storage":{}},"0x9599f2d7a33640cbf37f503628f4192abbea458f":{"balance":"0xffffff","code":"","nonce":"0x00","storage":{}},"0x0eea17ceda73fc60254ba5488191637438921691":{"balance":"0xffffff","code":"","nonce":"0x00","storage":{}},"0xd30dbf65784cf922cdce4cd120df8273e2ee549b":{"balance":"0xffffff","code":"","nonce":"0x00","storage":{}},"0x5231b00f2bbfac6b97684d831ed7f0e9501651fc":{"balance":"0xffffff","code":"","nonce":"0x00","storage":{}},"0x5bb511728564c51cd8d3416793e38568eda9d0a3":{"balance":"0xffffff","code":"","nonce":"0x00","storage":{}},"0xd70f4f01fd59bfe26490ecb2fc7c55c9649a57ce":{"balance":"0xffffff","code":"","nonce":"0x00","storage":{}},"0xd57a9b0d050c78adeb3e20f012f9a8319716ebb6":{"balance":"0xffffff","code":"","nonce":"0x00","storage":{}},"0xb66a9ac027d23f8f94f2c376a4052664ade498a9":{"balance":"0xffffff","code":"","nonce":"0x00","storage":{}},"0x34987dfcbae548e738088e1d11d2f72729eef184":{"balance":"0xffffff","code":"","nonce":"0x00","storage":{}},"0xe5d4dbc331522791b5b5219e8cd8d7c91a83799c":{"balance":"0xffffff","code":"","nonce":"0x00","storage":{}},"0x8bdc6990cdbd1224e3aecfe6e9e12f06e7c3b3cd":{"balance":"0xffffff","code":"","nonce":"0x00","storage":{}},"0x607d3fb274316356228b65e3ae17ca2b6022ade3":{"balance":"0xffffff","code":"","nonce":"0x00","storage":{}},"0xaeb4fe559c719ae4bf87d17b9de75d62546710bb":{"balance":"0xffffff","code":"","nonce":"0x00","storage":{}},"0xdea2814e18e0bc50f83fa6974ee666d5c2e31509":{"balance":"0xffffff","code":"","nonce":"0x00","storage":{}},"0xded0801b766b93a0b8f06ad28de5a1c6cd42915b":{"balance":"0xffffff","code":"","nonce":"0x00","storage":{}},"0x0302556bfc154e2d0c21c6491e60186cb9ece05c":{"balance":"0xffffff","code":"","nonce":"0x00","storage":{}},"0x04b35e8791a6558533e6bada21acfae056f0efc3":{"balance":"0xffffff","code":"","nonce":"0x00","storage":{}},"0x620dce1eae1821ef02cbf50ab341ef587fe27aa6":{"balance":"0xffffff","code":"","nonce":"0x00","storage":{}},"0x0b96a324f22c4a6030abebb33e951d85401d7eba":{"balance":"0xffffff","code":"","nonce":"0x00","storage":{}},"0xcd7f913d47fcab84440a2eb609071fe540df697a":{"balance":"0xffffff","code":"","nonce":"0x00","storage":{}},"0x29976a22bc3b4ea0ec93fc24fca6de6f4692fe06":{"balance":"0xffffff","code":"","nonce":"0x00","storage":{}},"0x939a1d05aaca711e59790b254c6309f7a2216c0c":{"balance":"0xffffff","code":"","nonce":"0x00","storage":{}},"0x452dd6bf56d3448d98149bc81380f7ea728cc43e":{"balance":"0xffffff","code":"","nonce":"0x00","storage":{}},"0x4f74de0942cdce1384e26bf0cf01d0fb229101e0":{"balance":"0xffffff","code":"","nonce":"0x00","storage":{}},"0x1feb351fb95e9fd645659879b8b43cb912098989":{"balance":"0xffffff","code":"","nonce":"0x00","storage":{}},"0x1c4f82ff74ea139cb30f680aeaf35537c1eabe1e":{"balance":"0xffffff","code":"","nonce":"0x00","storage":{}},"0xc95eed1a125c9721302434ffa7b600eb7a4d0cb1":{"balance":"0xffffff","code":"","nonce":"0x00","storage":{}},"0xf7b26440e89dce0e4dd46b671a717383af2db7a1":{"balance":"0xffffff","code":"","nonce":"0x00","storage":{}},"0xb4d2e982bfe983900b3daf60b12ad33ec21504dc":{"balance":"0xffffff","code":"","nonce":"0x00","storage":{}},"0xdb332086d4a6d8586b623e2becadadd6e1706190":{"balance":"0xffffff","code":"","nonce":"0x00","storage":{}},"0x170709b70bf8f3317cc5b097950a0692f0f2d217":{"balance":"0xffffff","code":"","nonce":"0x00","storage":{}},"0x24539768135d23da172a1de3c4a009e00706ba57":{"balance":"0xffffff","code":"","nonce":"0x00","storage":{}},"0xf8efbb9182faa0dba690817287a4c04049dba53e":{"balance":"0xffffff","code":"","nonce":"0x00","storage":{}},"0x7eafff58a00208547c4b029eab01046178cf9d85":{"balance":"0xffffff","code":"","nonce":"0x00","storage":{}},"0xcb26f66ec5236502fb827cc7ec3401ca9b5ab7d2":{"balance":"0xffffff","code":"","nonce":"0x00","storage":{}},"0xc4c29ba61264419fa9c199b777ea5757252befcb":{"balance":"0xffffff","code":"","nonce":"0x00","storage":{}},"0x63b778ed70c7163133ccea1866b6eb7243ca0277":{"balance":"0xffffff","code":"","nonce":"0x00","storage":{}},"0x8070abd918d5bb1f49a06cb90d8cb342b7bc3175":{"balance":"0xffffff","code":"","nonce":"0x00","storage":{}},"0xf6d3eda42fcb3390b1ef59e53cb0c3ef72c6093c":{"balance":"0xffffff","code":"","nonce":"0x00","storage":{}},"0xd6833a4ebd462c80bb972d6f9cf4d34cc520d2d0":{"balance":"0xffffff","code":"","nonce":"0x00","storage":{}},"0xd120e146e814feb22413fa0b0e93e9000ae6e3de":{"balance":"0xffffff","code":"","nonce":"0x00","storage":{}}}
"#;

        let v: serde_json::Value = serde_json::from_str(data).unwrap();
        let v_obj = v.as_object().unwrap();

        let mut root = Node::default();

        v_obj.keys().for_each(|key| {
            let address_bytes = hex::decode(&key[2..]).unwrap();
            // get hash of address
            let mut hasher = Keccak256::new();
            hasher.input(&address_bytes);
            let address_hash = Vec::<u8>::from(&hasher.result()[..]);
            let byte_key = keys::ByteKey(address_hash.to_vec());

            let val_obj = v_obj[key].as_object().unwrap();
            let balance = hex::decode(&val_obj["balance"].as_str().unwrap()[2..]).unwrap();
            let code =
                hex::decode("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")
                    .unwrap(); // val_obj["code"].as_str().unwrap();
            let mut nonce: Vec<u8> = hex::decode(&val_obj["nonce"].as_str().unwrap()[2..]).unwrap();
            if nonce.len() == 1 && nonce[0] == 0 {
                nonce = vec![];
            }
            let storage_hash =
                hex::decode("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
                    .unwrap();
            let mut stream = rlp::RlpStream::new_list(4);
            stream
                .append(&nonce)
                .append(&balance)
                .append(&code)
                .append(&storage_hash);
            let encoding = stream.out();
            root.insert(&NibbleKey::from(byte_key), encoding).unwrap();
        });

        let pre_root_hash = root.hash();
        assert_eq!(
            hex::encode(pre_root_hash),
            "b3c418cb00ad7c907176be86a5a21759b74bd3828ed62a1ea2ae8daea98c5da2"
        );
    }

    #[test]
    fn tree_with_just_one_leaf() {
        let proof = Multiproof {
            hashes: vec![],
            keyvals: vec![rlp::encode_list::<Vec<u8>, Vec<u8>>(&vec![
                vec![],
                vec![4, 5, 6],
            ])],
            instructions: vec![LEAF(0)],
        };
        let out: Node = proof.rebuild().unwrap();
        assert_eq!(out, Leaf(NibbleKey::from(vec![]), vec![4, 5, 6]))
    }

    #[test]
    fn tree_with_one_branch() {
        let proof = Multiproof {
            hashes: vec![],
            keyvals: vec![rlp::encode_list::<Vec<u8>, Vec<u8>>(&vec![
                vec![],
                vec![4, 5, 6],
            ])],
            instructions: vec![LEAF(0), BRANCH(0)],
        };
        let out: Node = proof.rebuild().unwrap();
        assert_eq!(
            out,
            Branch(vec![
                Leaf(NibbleKey::from(vec![]), vec![4, 5, 6]),
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
        let proof = Multiproof {
            hashes: vec![],
            keyvals: vec![
                rlp::encode_list::<Vec<u8>, Vec<u8>>(&vec![vec![], vec![4, 5, 6]]),
                rlp::encode_list::<Vec<u8>, Vec<u8>>(&vec![vec![25], vec![10, 11, 12]]),
            ],
            instructions: vec![LEAF(0), BRANCH(0), LEAF(1), ADD(2)],
        };
        let out: Node = proof.rebuild().unwrap();
        assert_eq!(
            out,
            Branch(vec![
                Leaf(NibbleKey::from(vec![]), vec![4, 5, 6]),
                EmptySlot,
                Leaf(NibbleKey::from(vec![9]), vec![10, 11, 12]),
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
                rlp::encode_list::<Vec<u8>, Vec<u8>>(&vec![vec![], vec![4, 5, 6]]),
                rlp::encode_list::<Vec<u8>, Vec<u8>>(&vec![vec![25], vec![10, 11, 12]]),
            ],
        };
        let out: Node = proof.rebuild().unwrap();
        assert_eq!(
            out,
            Extension(
                NibbleKey::from(vec![13, 14, 15]),
                Box::new(Branch(vec![
                    Leaf(NibbleKey::from(vec![]), vec![4, 5, 6]),
                    EmptySlot,
                    Leaf(NibbleKey::from(vec![9]), vec![10, 11, 12]),
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
    fn roundtrip() {
        let mut tree_root = Node::Branch(vec![Node::EmptySlot; 16]);
        tree_root
            .insert(&NibbleKey::from(vec![1u8; 32]), vec![2u8; 32])
            .unwrap();

        assert_eq!(
            tree_root.hash(),
            vec![
                86, 102, 96, 191, 106, 199, 70, 178, 131, 236, 157, 14, 50, 168, 100, 69, 123, 66,
                223, 122, 0, 97, 18, 144, 20, 79, 250, 219, 73, 190, 134, 108
            ]
        );

        let proof = make_multiproof(&tree_root, vec![NibbleKey::from(vec![1u8; 32])]).unwrap();

        // RLP roundtrip
        let proof_rlp = rlp::encode(&proof);
        let proof: Multiproof = rlp::decode(&proof_rlp).unwrap();

        let rebuilt_root = proof.rebuild().unwrap();
        assert_eq!(tree_root, rebuilt_root);
    }

    #[test]
    fn test_nullkey_leaf() {
        let missing_key = NibbleKey::from(vec![1u8; 32]);
        let mut root = Node::default();
        root.insert(&NibbleKey::from(vec![0u8; 32]), vec![0u8; 32])
            .unwrap();
        root.insert(
            &NibbleKey::from(ByteKey::from(
                hex::decode("11111111111111110000000000000000").unwrap(),
            )),
            vec![0u8; 32],
        )
        .unwrap();
        let proof = make_multiproof(&root, vec![missing_key.clone()]).unwrap();

        assert_eq!(
            proof.hashes,
            vec![vec![
                251, 145, 132, 252, 92, 249, 202, 65, 20, 16, 160, 32, 246, 163, 155, 125, 17, 186,
                16, 171, 64, 108, 250, 70, 60, 207, 16, 164, 199, 41, 252, 143
            ],]
        );
        assert_eq!(
            proof.keyvals,
            vec![vec![
                242, 144, 49, 17, 17, 17, 17, 17, 17, 17, 0, 0, 0, 0, 0, 0, 0, 0, 160, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            ]]
        );
        assert_eq!(proof.instructions.len(), 4);

        let rebuilt: Node = proof.rebuild().unwrap();
        assert_eq!(
            rebuilt,
            Branch(vec![
                Hash(
                    hex::decode("fb9184fc5cf9ca411410a020f6a39b7d11ba10ab406cfa463ccf10a4c729fc8f")
                        .unwrap()
                ),
                Leaf(
                    vec![
                        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0
                    ]
                    .into(),
                    vec![0u8; 32]
                ),
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
        assert!(!rebuilt.has_key(&missing_key));
    }

    #[test]
    fn test_nullkey_ext() {
        let missing_key = NibbleKey::from(vec![1u8; 32]);
        let mut root = Node::default();
        root.insert(
            &NibbleKey::from(ByteKey::from(
                hex::decode("11111111111111182222222222222222").unwrap(),
            )),
            vec![0u8; 32],
        )
        .unwrap();
        root.insert(
            &NibbleKey::from(ByteKey::from(
                hex::decode("11111111111111180000000000000000").unwrap(),
            )),
            vec![0u8; 32],
        )
        .unwrap();

        let proof = make_multiproof(&root, vec![missing_key.clone()]).unwrap();
        assert_eq!(
            proof.hashes,
            vec![
                hex::decode("72b1a3493c86a014dca29b01b487031ff64bf71c09bdd62815c45928baf2dbf0")
                    .unwrap()
            ]
        );
        assert_eq!(proof.keyvals.len(), 0);
        assert_eq!(proof.instructions.len(), 2);

        let rebuilt: Node = proof.rebuild().unwrap();
        assert_eq!(
            rebuilt,
            Extension(
                vec![1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 8].into(),
                Box::new(Hash(vec![
                    114, 177, 163, 73, 60, 134, 160, 20, 220, 162, 155, 1, 180, 135, 3, 31, 246,
                    75, 247, 28, 9, 189, 214, 40, 21, 196, 89, 40, 186, 242, 219, 240
                ]))
            )
        );
        assert!(!rebuilt.has_key(&missing_key));
    }

    #[test]
    fn test_nullkey_branch() {
        let missing_key = NibbleKey::from(vec![2u8; 32]);
        let mut root = Node::default();
        root.insert(
            &NibbleKey::from(ByteKey::from(
                hex::decode("11111111111111182222222222222222").unwrap(),
            )),
            vec![0u8; 32],
        )
        .unwrap();
        root.insert(
            &NibbleKey::from(ByteKey::from(
                hex::decode("01111111111111180000000000000000").unwrap(),
            )),
            vec![0u8; 32],
        )
        .unwrap();

        let proof = make_multiproof(&root, vec![missing_key.clone()]).unwrap();
        assert_eq!(
            proof.hashes,
            vec![
                hex::decode("df853a88c4113e0274dea41494ea397aee50d9f5be0e88c9eb274a7ce0716bb7")
                    .unwrap(),
                hex::decode("1a4c4b1aa982d7b8094ce199d89aba598bdc4a8c91c3133bbbcebe731229305c")
                    .unwrap()
            ]
        );
        assert_eq!(proof.keyvals.len(), 1);
        assert_eq!(proof.instructions.len(), 6);

        let rebuilt: Node = proof.rebuild().unwrap();
        assert_eq!(
            rebuilt,
            Branch(vec![
                Hash(vec![
                    223, 133, 58, 136, 196, 17, 62, 2, 116, 222, 164, 20, 148, 234, 57, 122, 238,
                    80, 217, 245, 190, 14, 136, 201, 235, 39, 74, 124, 224, 113, 107, 183
                ]),
                Hash(vec![
                    26, 76, 75, 26, 169, 130, 215, 184, 9, 76, 225, 153, 216, 154, 186, 89, 139,
                    220, 74, 140, 145, 195, 19, 59, 187, 206, 190, 115, 18, 41, 48, 92
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
                EmptySlot
            ])
        );
        assert!(!rebuilt.has_key(&missing_key));
    }

    #[test]
    fn test_nullkey_empty() {
        let root = Node::default();
        let missing_key = NibbleKey::from(vec![2u8; 32]);

        let proof = make_multiproof(&root, vec![missing_key.clone()]).unwrap();
        let rebuilt: Node = proof.rebuild().unwrap();
        assert!(!rebuilt.has_key(&missing_key));
    }

    #[test]
    fn subnode_index_branch() {
        let mut root = Node::default();
        let k1 = &NibbleKey::from(ByteKey::from(
            hex::decode("11111111111111110000000000000000").unwrap(),
        ));
        let k2 = &NibbleKey::from(ByteKey::from(
            hex::decode("01111111111111110000000000000000").unwrap(),
        ));
        let k3 = &NibbleKey::from(ByteKey::from(
            hex::decode("00111111111111110000000000000000").unwrap(),
        ));
        root.insert(k1, vec![0u8; 32]).unwrap();
        root.insert(k2, vec![0u8; 32]).unwrap();
        root.insert(k3, vec![0u8; 32]).unwrap();

        assert_eq!(
            root[&NibbleKey::from(&k2[..2])],
            Leaf(NibbleKey::from(&k2[2..]), vec![0u8; 32])
        );
    }

    #[test]
    fn subnode_index_extension() {
        let mut root = Node::default();
        let k1 = &NibbleKey::from(ByteKey::from(
            hex::decode("11111111111111100000000000000000").unwrap(),
        ));
        let k2 = &NibbleKey::from(ByteKey::from(
            hex::decode("11111111111111110000000000000000").unwrap(),
        ));
        let k3 = &NibbleKey::from(ByteKey::from(
            hex::decode("11111111111111120000000000000000").unwrap(),
        ));
        root.insert(k1, vec![0u8; 32]).unwrap();
        root.insert(k2, vec![0u8; 32]).unwrap();
        root.insert(k3, vec![0u8; 32]).unwrap();

        // check that a partial key returns the whole key
        assert_eq!(root[&NibbleKey::from(&k2[..2])], root);

        // check that a key beyond the extension will recurse
        assert_eq!(
            root[&NibbleKey::from(ByteKey::from(hex::decode("1111111111111112").unwrap(),))],
            Leaf(vec![0u8; 16].into(), vec![0u8; 32])
        );
    }
    #[test]
    fn subnode_index_empty_index() {
        let mut root = Node::default();
        let k1 = &NibbleKey::from(ByteKey::from(
            hex::decode("11111111111111110000000000000000").unwrap(),
        ));
        let k2 = &NibbleKey::from(ByteKey::from(
            hex::decode("01111111111111110000000000000000").unwrap(),
        ));
        let k3 = &NibbleKey::from(ByteKey::from(
            hex::decode("00111111111111110000000000000000").unwrap(),
        ));
        root.insert(k1, vec![0u8; 32]).unwrap();
        root.insert(k2, vec![0u8; 32]).unwrap();
        root.insert(k3, vec![0u8; 32]).unwrap();

        assert_eq!(root[&NibbleKey::from(vec![])], root);
    }

    #[test]
    fn key_present_found() {
        let mut root = Node::default();
        let k1 = &NibbleKey::from(ByteKey::from(
            hex::decode("11111111111111110000000000000000").unwrap(),
        ));
        let k2 = &NibbleKey::from(ByteKey::from(
            hex::decode("01111111111111110000000000000000").unwrap(),
        ));
        let k3 = &NibbleKey::from(ByteKey::from(
            hex::decode("11111111111111111111111111111111").unwrap(),
        ));

        root.insert(k1, vec![0u8; 32]).unwrap();
        root.insert(k2, vec![0u8; 32]).unwrap();
        root.insert(k3, vec![0u8; 32]).unwrap();

        assert!(root.has_key(k1));
    }

    #[test]
    fn key_absent_not_found() {
        let mut root = Node::default();
        let k1 = &NibbleKey::from(ByteKey::from(
            hex::decode("11111111111111110000000000000000").unwrap(),
        ));
        let k2 = &NibbleKey::from(ByteKey::from(
            hex::decode("01111111111111110000000000000000").unwrap(),
        ));
        let k3 = &NibbleKey::from(ByteKey::from(
            hex::decode("11111111111111111111111111111111").unwrap(),
        ));

        root.insert(k2, vec![0u8; 32]).unwrap();
        root.insert(k3, vec![0u8; 32]).unwrap();

        assert!(!root.has_key(k1));
    }

    #[test]
    fn check_payload_length_exactly_32_bytes() {
        let mut root = Node::default();

        root.insert(&NibbleKey::from(vec![1u8; 16]), vec![1u8; 20])
            .unwrap();
        assert_eq!(root.hash().len(), 32);
        assert_eq!(
            root.hash(),
            vec![
                149, 160, 25, 137, 124, 149, 98, 15, 208, 235, 90, 71, 238, 186, 81, 6, 47, 67,
                244, 224, 134, 155, 76, 154, 130, 70, 234, 61, 0, 11, 4, 135
            ]
        );
    }

    #[test]
    fn check_leaf_length_less_than_32_bytes() {
        let mut root = Node::default();

        root.insert(&NibbleKey::from(vec![1u8; 2]), vec![1u8; 20])
            .unwrap();
        assert_eq!(
            root.composition(),
            vec![216, 130, 32, 17, 148, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
        );
        assert_eq!(
            root.hash(),
            vec![
                121, 126, 245, 211, 88, 166, 171, 101, 137, 134, 207, 117, 161, 91, 198, 101, 156,
                171, 181, 198, 146, 124, 98, 133, 207, 71, 22, 54, 4, 84, 237, 169
            ]
        );
    }

    #[test]
    fn check_branch_less_than_32_bytes() {
        let mut root = Node::default();
        root.insert(&NibbleKey::from(vec![1u8; 4]), vec![1u8; 2])
            .unwrap();
        root.insert(&NibbleKey::from(vec![2u8; 4]), vec![1u8; 2])
            .unwrap();

        assert_eq!(
            root.composition(),
            vec![
                221, 128, 198, 130, 49, 17, 130, 1, 1, 198, 130, 50, 34, 130, 1, 1, 128, 128, 128,
                128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128
            ]
        );
        assert_eq!(
            root.hash(),
            vec![
                186, 8, 87, 233, 68, 14, 179, 61, 85, 127, 234, 111, 248, 166, 233, 195, 254, 176,
                176, 11, 16, 226, 228, 129, 126, 230, 92, 191, 236, 208, 253, 79
            ]
        );
    }

    #[test]
    fn check_extension_less_than_32_bytes() {
        let mut second_key = vec![1u8; 2];
        second_key.extend(vec![2u8; 2]);

        let mut root = Node::default();
        root.insert(&NibbleKey::from(vec![1u8; 4]), vec![1u8; 2])
            .unwrap();
        root.insert(&NibbleKey::from(second_key), vec![1u8; 2])
            .unwrap();

        assert_eq!(
            root.composition(),
            vec![
                222, 130, 0, 17, 154, 217, 128, 196, 49, 130, 1, 1, 196, 50, 130, 1, 1, 128, 128,
                128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128
            ]
        );
        assert_eq!(
            root.hash(),
            vec![
                121, 4, 12, 221, 211, 212, 144, 252, 108, 10, 139, 100, 184, 65, 160, 107, 191,
                241, 68, 121, 143, 178, 128, 248, 120, 199, 203, 34, 78, 26, 105, 77
            ]
        );
    }
}
