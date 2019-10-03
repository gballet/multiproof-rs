#![feature(box_syntax, box_patterns)]

extern crate rlp;
extern crate sha3;

pub mod utils;

use sha3::{Digest, Keccak256};
use utils::*;

#[derive(Debug, Clone, PartialEq)]
pub enum Node {
    Hash(Vec<u8>), // (Hash, # empty spaces)
    Leaf(NibbleKey, Vec<u8>),
    Extension(NibbleKey, Box<Node>),
    Branch(Vec<Node>),
    EmptySlot,
}

impl Default for Node {
    fn default() -> Self {
        Node::EmptySlot
    }
}

impl rlp::Encodable for Node {
    fn rlp_append(&self, s: &mut rlp::RlpStream) {
        match self {
            Node::Leaf(ref k, ref v) => {
                s.append_list::<Vec<u8>, Vec<u8>>(&vec![k.with_hex_prefix(true), v.to_vec()]);
            }
            Node::Extension(ref ext, box node) => {
                let extension_branch_hash = node.composition();

                s.append_list::<Vec<u8>, Vec<u8>>(&vec![
                    ext.with_hex_prefix(false),
                    extension_branch_hash,
                ]);
            }
            Node::Branch(ref nodes) => {
                let mut stream = rlp::RlpStream::new();
                stream.begin_unbounded_list();
                for node in nodes {
                    let hash = node.composition();
                    if hash.len() < 32 && hash.len() > 0 {
                        stream.append_raw(&hash, hash.len());
                    } else {
                        stream.append(&hash);
                    }
                }
                // 17th element
                stream.append(&"");
                stream.complete_unbounded_list();
                let encoding = stream.out();
                s.append_raw(&encoding, encoding.len());
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
        let key_bytes = utils::ByteKey(keyval[0].clone());
        let key_nibbles = NibbleKey::from(key_bytes);
        // TODO: remove indicator prefix if node is a leaf or extension
        Ok(Node::Leaf(key_nibbles, keyval[1].clone()))
    }
}

// Implement sub-node access based on a nibble key prefix.
impl std::ops::Index<&NibbleKey> for Node {
    type Output = Node;
    #[inline]
    fn index(&self, k: &NibbleKey) -> &Node {
        // If the key has 0-length, then the search is over and
        // the current node is returned.
        if k.len() == 0 {
            self
        } else {
            match self {
                Node::Branch(ref children) => {
                    children[k[0] as usize].index(&NibbleKey::from(&k[1..]))
                }
                Node::Extension(ref ext, box child) => {
                    let factor_length = ext.factor_length(k);
                    // If the factorized length is that of the extension,
                    // then the indexing key is compatible with this tree
                    // and the function recurses.
                    if factor_length == ext.len() {
                        child.index(&k[factor_length..].into())
                    } else {
                        // Otherwise, we either have a key that is shorter
                        // or a differing entry. The former returns the
                        // current node and the latter panics.
                        if k.len() == factor_length {
                            self
                        } else {
                            panic!("Requested key isn't present in the tree")
                        }
                    }
                }
                Node::Leaf(ref key, _) => {
                    let factor_length = key.factor_length(k);
                    if k[..factor_length] == key[..factor_length] {
                        self
                    } else {
                        panic!("Requested key isn't present in the tree")
                    }
                }
                Node::EmptySlot | Node::Hash(_) => {
                    panic!("Requested key isn't present in the tree")
                }
            }
        }
    }
}

impl Node {
    pub fn graphviz(&self) -> String {
        let (nodes, refs) = self.graphviz_rec(NibbleKey::from(vec![]), String::from("root"));
        format!(
            "digraph D {{
\tnode [shape=\"box\",label=\"hash\"];

\t{}

\t{}
}}",
            nodes.join("\n\t"),
            refs.join("\n\t")
        )
    }

    fn graphviz_key(key: NibbleKey) -> String {
        let mut ret = String::new();
        let nibbles: Vec<u8> = key.into();
        for (i, nibble) in nibbles.iter().enumerate() {
            ret.push_str(&format!("<td port=\"{}\">{:x}</td>", i, nibble));
        }
        ret
    }

    fn graphviz_rec(&self, prefix: NibbleKey, root: String) -> (Vec<String>, Vec<String>) {
        let pref: Vec<u8> = prefix.clone().into();
        match self {
            Node::Leaf(ref k, ref v) => {
                return (
                    vec![
                        format!("leaf{} [shape=none,margin=0,label=<<table border=\"0\" cellborder=\"1\" cellspacing=\"0\" cellpadding=\"4\"><tr>{}<td>{}</td></tr></table>>]", hex::encode(pref.clone()), Node::graphviz_key(k.clone()), hex::encode(v)),
                    ],
                    vec![format!("{} -> leaf{}", root, hex::encode(pref))],
                );
            }
            Node::Branch(ref subnodes) => {
                let name = format!("branch{}", hex::encode(pref.clone()));
                let mut label = String::from("");
                for i in 0..15 {
                    label.push_str(&format!("<td port=\"{}\">{:x}</td>", i, i));
                }
                println!("{:?}", hex::encode(pref.clone()));
                let mut refs = if prefix.len() > 0 {
                    vec![format!("{} -> {}", root, name)]
                } else {
                    Vec::new()
                };
                let mut nodes = vec![format!("{} [shape=none,label=<<table border=\"0\" cellborder=\"1\" cellspacing=\"0\"><tr>{}</tr></table>>]", name, label)];
                for (i, subnode) in subnodes.iter().enumerate() {
                    let mut subkey: Vec<u8> = prefix.clone().into();
                    subkey.push(i as u8);
                    let (sn, sr) = Node::graphviz_rec(
                        &subnode,
                        NibbleKey::from(subkey),
                        format!("{}:{}", name, i),
                    );
                    nodes.extend(sn);
                    refs.extend(sr);
                }
                return (nodes, refs);
            }
            Node::Extension(ref ext, ref subnode) => {
                let name = format!("extension{}", hex::encode(pref.clone()));
                let mut subkey: Vec<u8> = prefix.clone().into();
                subkey.extend_from_slice(&ext[0..]);
                let (mut sn, mut sr) = Node::graphviz_rec(
                    subnode,
                    NibbleKey::from(subkey),
                    format!("{}:{}", name, ext.len() - 1),
                );
                sn.push(format!("{} [shape=none,label=<<table border=\"0\" cellspacing=\"0\" cellborder=\"1\"><tr>{}</tr></table>>]", name, Node::graphviz_key(ext.clone())));
                sr.push(format!("{} -> {}:{}", root, name, 0));
                return (sn, sr);
            }
            Node::Hash(ref h) => {
                let name = format!("hash{}", hex::encode(pref.clone()));
                let label = if prefix.len() > 0 {
                    String::from("hash")
                } else {
                    String::from("root")
                };
                return (
                    vec![format!("{} [label=\"{}\"]", name, label)],
                    vec![format!("{} -> {}", root, name)],
                );
            }
            _ => {
                /* Ignore EmptySlot */
                (vec![], vec![])
            }
        }
    }

    pub fn is_key_present(&self, key: &NibbleKey) -> bool {
        match self {
            Node::Leaf(ref k, _) => k == key,
            Node::Hash(_) => false,
            Node::Branch(ref children) => {
                children[key[0] as usize].is_key_present(&NibbleKey::from(&key[1..]))
            }
            Node::Extension(ref ext, box child) => {
                ext.len() <= key.len()
                    && *ext == NibbleKey::from(&key[..ext.len()])
                    && child.is_key_present(&NibbleKey::from(&key[ext.len()..]))
            }
            Node::EmptySlot => false,
        }
    }

    pub fn hash(&self) -> Vec<u8> {
        let composed_node = self.composition();

        // If `composition` returned a payload whose length is less
        // than 32 bytes, then compute its keccack256 hash in order
        // to return the root hash.
        if composed_node.len() < 32 {
            let mut hasher = Keccak256::new();
            hasher.input(&composed_node);
            Vec::<u8>::from(&hasher.result()[..])
        } else {
            composed_node
        }
    }

    // This is the composition function that is described as `n` in the
    // yellow paper. The difference with the root of the merkle tree is
    // that it can potentially return an array of bytes whose length is
    // less than 32 bytes, in which case is represents the RLP encoding
    // of the root node.
    fn composition(&self) -> Vec<u8> {
        use Node::*;
        match self {
            EmptySlot => Vec::new(),
            Hash(h) => h.to_vec(),
            _ => {
                let encoding = rlp::encode(self);

                // Only hash if the encoder output is more than 32 bytes.
                if encoding.len() >= 32 {
                    let mut hasher = Keccak256::new();
                    hasher.input(&encoding);
                    Vec::<u8>::from(&hasher.result()[..])
                } else {
                    encoding
                }
            }
        }
    }
}

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

// Rebuilds the tree based on the multiproof components
pub fn rebuild(proof: &Multiproof) -> Result<Node, String> {
    use Instruction::*;
    use Node::*;

    let mut hiter = proof.hashes.iter();
    let iiter = proof.instructions.iter();
    let mut kviter = proof.keyvals.iter().map(|encoded| {
        // Deserialize the keys as they are read
        rlp::decode::<Node>(encoded).unwrap()
    });

    let mut stack = Vec::<Node>::new();

    for instr in iiter {
        match instr {
            HASHER => {
                if let Some(h) = hiter.next() {
                    stack.push(Hash(h.to_vec()));
                } else {
                    return Err(format!("Proof requires one more hash in HASHER"));
                }
            }
            LEAF(keylength) => {
                if let Some(Leaf(key, value)) = kviter.next() {
                    // If the value is empty, we have a NULL key and
                    // therefore an EmptySlot should be returned.
                    if value.len() != 0 {
                        stack.push(Leaf(
                            NibbleKey::from(key[key.len() - *keylength..].to_vec()),
                            value.to_vec(),
                        ));
                    } else {
                        stack.push(EmptySlot);
                    }
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
                    stack.push(Branch(children))
                } else {
                    return Err(format!(
                        "Could not pop a value from the stack, that is required for a BRANCH({})",
                        digit
                    ));
                }
            }
            EXTENSION(key) => {
                if let Some(node) = stack.pop() {
                    stack.push(Extension(NibbleKey::from(key.to_vec()), Box::new(node)));
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
                        Branch(ref mut n2) => {
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
                        Hash(_) => {
                            return Err(String::from("Hash node no longer supported in this case"));
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
pub fn insert_leaf(root: &mut Node, key: &NibbleKey, value: Vec<u8>) -> Result<Node, String> {
    use Node::*;

    if key.len() == 0 {
        return Err("Attempted to insert a 0-byte key".to_string());
    }

    match root {
        Leaf(leafkey, leafvalue) => {
            // Find the common part of the current key with that of the
            // leaf and create an intermediate full node.
            let firstdiffindex = leafkey.factor_length(key);

            // Return an error if the leaf is already present.
            if firstdiffindex == key.len() {
                return Err(format!("Key is is already present!",));
            }

            // Create the new root, which is a full node.
            let mut res = vec![EmptySlot; 16];
            // Add the initial leaf, with a key truncated by the common
            // key part.
            res[leafkey[firstdiffindex] as usize] = Leaf(
                NibbleKey::from(leafkey[firstdiffindex + 1..].to_vec()),
                leafvalue.to_vec(),
            );
            // Add the node to be inserted
            res[key[firstdiffindex] as usize] =
                Leaf(NibbleKey::from(key[firstdiffindex + 1..].to_vec()), value);
            // Put the common part into an extension node
            if firstdiffindex == 0 {
                // Special case: no extension necessary
                Ok(Branch(res))
            } else {
                Ok(Extension(
                    NibbleKey::from(key[..firstdiffindex].to_vec()),
                    Box::new(Branch(res)),
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
                let childroot = insert_leaf(
                    &mut child.clone(),
                    &NibbleKey::from(key[extkey.len()..].to_vec()),
                    value,
                )?;
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
                        NibbleKey::from(extkey[1..].to_vec()),
                        Box::new(child.clone()),
                    )
                };

                // Create the entry for the node. If there was only a
                // difference of one byte, that byte will be consumed by
                // the fullnode and therefore the key in the leaf will be
                // an empty slice `[]`.
                res[key[0] as usize] = Leaf(NibbleKey::from(key[1..].to_vec()), value);

                return Ok(Branch(res));
            }

            // Create the new root, which is a full node.
            let mut res = vec![EmptySlot; 16];
            // Add the initial leaf, with a key truncated by the common
            // key part. If the common part corresponds to the extension
            // key length minus one, then there is no need for the creation
            // of an extension node past the full node.
            res[extkey[firstdiffindex] as usize] = if extkey.len() - firstdiffindex > 1 {
                Extension(
                    NibbleKey::from(extkey[firstdiffindex + 1..].to_vec()),
                    Box::new(child.clone()),
                )
            } else {
                child.clone()
            };
            // Add the node to be inserted
            res[key[firstdiffindex] as usize] =
                Leaf(NibbleKey::from(key[firstdiffindex + 1..].to_vec()), value);
            // Put the common part into an extension node
            Ok(Extension(
                NibbleKey::from(extkey[..firstdiffindex].to_vec()),
                Box::new(Branch(res)),
            ))
        }
        Branch(ref mut vec) => {
            let idx = key[0] as usize;
            // If the slot isn't yet in use, fill it, and otherwise,
            // recurse into the child node.
            vec[idx] = if vec[idx] == EmptySlot {
                // XXX check that the value is at least 1
                Leaf(NibbleKey::from(key[1..].to_vec()), value)
            } else {
                insert_leaf(&mut vec[idx], &NibbleKey::from(key[1..].to_vec()), value)?
            };
            // Return the root node with an updated entry
            Ok(Branch(vec.to_vec()))
        }
        EmptySlot => Ok(Leaf(key.clone(), value)),
        _ => panic!("Can not insert a node into a hashed node"),
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
    if keys.len() == 0 {
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
                if dispatch[selector].len() == 0 {
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
                )
                .to_string());
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
                let factor_length = extkey.factor_length(k);
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
            if truncated.len() > 0 {
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
        instructions: instructions,
        hashes: hashes,
        keyvals: values,
    })
}

#[cfg(test)]
mod tests {
    extern crate hex;

    use super::Instruction::*;
    use super::Node::*;
    use super::*;

    #[test]
    fn validate_tree() {
        let mut root = Node::default();
        root = insert_leaf(&mut root, &NibbleKey::from(vec![2u8; 32]), vec![0u8; 32]).unwrap();
        root = insert_leaf(&mut root, &NibbleKey::from(vec![1u8; 32]), vec![1u8; 32]).unwrap();
        root = insert_leaf(&mut root, &NibbleKey::from(vec![8u8; 32]), vec![150u8; 32]).unwrap();

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
        let new_root = rebuild(&proof).unwrap();

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
        root = insert_leaf(&mut root, &NibbleKey::from(vec![2u8; 32]), vec![0u8; 32]).unwrap();
        root = insert_leaf(&mut root, &NibbleKey::from(vec![1u8; 32]), vec![1u8; 32]).unwrap();
        root = insert_leaf(&mut root, &NibbleKey::from(vec![8u8; 32]), vec![150u8; 32]).unwrap();

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
        root = insert_leaf(&mut root, &NibbleKey::from(vec![2u8; 32]), vec![0u8; 32]).unwrap();
        root = insert_leaf(&mut root, &NibbleKey::from(vec![1u8; 32]), vec![1u8; 32]).unwrap();

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
        insert_leaf(&mut root, &NibbleKey::from(vec![2u8; 32]), vec![0u8; 32]).unwrap();
        insert_leaf(&mut root, &NibbleKey::from(vec![1u8; 32]), vec![1u8; 32]).unwrap();

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
        root = insert_leaf(&mut root, &NibbleKey::from(vec![1u8; 32]), vec![0u8; 32]).unwrap();
        root = insert_leaf(&mut root, &NibbleKey::from(vec![2u8; 32]), vec![0u8; 32]).unwrap();

        let pre_root_hash = root.hash();

        let proof = make_multiproof(&root, vec![NibbleKey::from(vec![2u8; 32])]).unwrap();

        let res = rebuild(&proof);

        assert_eq!(res.unwrap().hash(), pre_root_hash);
    }

    #[test]
    fn make_multiproof_two_leaves_with_extension() {
        let inputs = [
            ("0x1111111111111111111111111111111111111111", vec![15u8; 32]),
            ("0x2222222222222222222222222222222222222222", vec![14u8; 32]),
            ("0x1111111111333333333333333333333333333333", vec![13u8; 32]),
        ];

        let nibble_from_hex = |h| NibbleKey::from(utils::ByteKey(hex::decode(h).unwrap()));

        let mut root = Node::default();
        for i in &inputs {
            let k = nibble_from_hex(&i.0[2..]);
            insert_leaf(&mut root, &k, i.1.clone()).unwrap();
        }

        let pre_root_hash = root.hash();

        let keys = vec![
            nibble_from_hex(&inputs[2].0[2..]),
            nibble_from_hex(&inputs[0].0[2..]),
        ];
        let proof = make_multiproof(&root, keys).unwrap();

        let res = rebuild(&proof);

        assert_eq!(res.unwrap().hash(), pre_root_hash);
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
            let byte_key = utils::ByteKey(address_hash.to_vec());

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
            root = insert_leaf(&mut root, &NibbleKey::from(byte_key), encoding).unwrap();
        });

        let pre_root_hash = root.hash();
        assert_eq!(
            hex::encode(pre_root_hash),
            "b3c418cb00ad7c907176be86a5a21759b74bd3828ed62a1ea2ae8daea98c5da2"
        );
    }

    #[test]
    fn insert_leaf_zero_length_key_after_fullnode() {
        let mut root = Extension(
            NibbleKey::from(vec![0u8; 31]),
            Box::new(Branch(vec![
                EmptySlot,
                Leaf(NibbleKey::from(vec![]), vec![0u8; 32]),
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
        let out = insert_leaf(&mut root, &NibbleKey::from(vec![0u8; 32]), vec![1u8; 32]).unwrap();
        assert_eq!(
            out,
            Extension(
                NibbleKey::from(vec![0u8; 31]),
                Box::new(Branch(vec![
                    Leaf(NibbleKey::from(vec![]), vec![1u8; 32]),
                    Leaf(NibbleKey::from(vec![]), vec![0u8; 32]),
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
            NibbleKey::from(vec![0xd, 0xe, 0xa, 0xd]),
            Box::new(Leaf(NibbleKey::from(vec![0u8; 28]), vec![1u8; 32])),
        );
        let mut key = vec![1u8; 32];
        key[0] = 0xd;
        key[1] = 0xe;
        key[2] = 0xa;
        key[3] = 0xd;
        let out = insert_leaf(&mut root, &NibbleKey::from(key), vec![2u8; 32]).unwrap();
        assert_eq!(
            out,
            Extension(
                NibbleKey::from(vec![0xd, 0xe, 0xa, 0xd]),
                Box::new(Branch(vec![
                    Leaf(NibbleKey::from(vec![0u8; 27]), vec![1u8; 32]),
                    Leaf(NibbleKey::from(vec![1u8; 27]), vec![2u8; 32]),
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
            NibbleKey::from(vec![0xd, 0xe, 0xa, 0xd]),
            Box::new(Leaf(NibbleKey::from(vec![0u8; 24]), vec![1u8; 32])),
        );
        let out = insert_leaf(&mut root, &NibbleKey::from(vec![2u8; 32]), vec![1u8; 32]).unwrap();
        assert_eq!(
            out,
            Branch(vec![
                EmptySlot,
                EmptySlot,
                Leaf(NibbleKey::from(vec![2u8; 31]), vec![1u8; 32]),
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
                    NibbleKey::from(vec![14, 10, 13]),
                    Box::new(Leaf(NibbleKey::from(vec![0u8; 24]), vec![1u8; 32]))
                ),
                EmptySlot,
                EmptySlot
            ])
        );
    }

    #[test]
    fn insert_leaf_into_extension_root_half_bytes_in_key_common() {
        let mut root = Extension(
            NibbleKey::from(vec![0xd, 0xe, 0xa, 0xd]),
            Box::new(Leaf(NibbleKey::from(vec![0u8; 28]), vec![1u8; 32])),
        );
        let mut key = vec![0u8; 32];
        key[0] = 0xd;
        key[1] = 0xe;
        let out = insert_leaf(&mut root, &NibbleKey::from(key), vec![1u8; 32]).unwrap();
        assert_eq!(
            out,
            Extension(
                NibbleKey::from(vec![0xd, 0xe]),
                Box::new(Branch(vec![
                    Leaf(NibbleKey::from(vec![0u8; 29]), vec![1u8; 32]),
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
                        NibbleKey::from(vec![0xd]),
                        Box::new(Leaf(NibbleKey::from(vec![0u8; 28]), vec![1u8; 32]))
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
            NibbleKey::from(vec![0xd, 0xe, 0xa, 0xd]),
            Box::new(Leaf(NibbleKey::from(vec![0u8; 28]), vec![1u8; 32])),
        );
        let mut key = vec![0u8; 32];
        key[0] = 0xd;
        key[1] = 0xe;
        key[2] = 0xa;
        let out = insert_leaf(&mut root, &NibbleKey::from(key), vec![1u8; 32]).unwrap();
        assert_eq!(
            out,
            Extension(
                NibbleKey::from(vec![0xd, 0xe, 0xa]),
                Box::new(Branch(vec![
                    Leaf(NibbleKey::from(vec![0u8; 28]), vec![1u8; 32]),
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
                    Leaf(NibbleKey::from(vec![0u8; 28]), vec![1u8; 32]),
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
        let mut root = Leaf(NibbleKey::from(key), vec![1u8; 32]);
        let out = insert_leaf(&mut root, &NibbleKey::from(vec![2u8; 32]), vec![1u8; 32]).unwrap();
        assert_eq!(
            out,
            Extension(
                NibbleKey::from(vec![2u8; 16]),
                Box::new(Branch(vec![
                    Leaf(NibbleKey::from(vec![0u8; 15]), vec![1u8; 32]),
                    EmptySlot,
                    Leaf(NibbleKey::from(vec![2u8; 15]), vec![1u8; 32]),
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
        let mut root = Leaf(NibbleKey::from(vec![1u8; 32]), vec![1u8; 32]);
        let out = insert_leaf(&mut root, &NibbleKey::from(vec![2u8; 32]), vec![1u8; 32]).unwrap();
        assert_eq!(
            out,
            Branch(vec![
                EmptySlot,
                Leaf(NibbleKey::from(vec![1u8; 31]), vec![1u8; 32]),
                Leaf(NibbleKey::from(vec![2u8; 31]), vec![1u8; 32]),
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
    fn insert_leaf_into_emptyslot() {
        let mut root = Node::default();
        assert_eq!(root, EmptySlot);
        let out = insert_leaf(&mut root, &NibbleKey::from(vec![0u8; 32]), vec![1u8; 32]).unwrap();
        assert_eq!(out, Leaf(NibbleKey::from(vec![0u8; 32]), vec![1u8; 32]));
    }

    #[test]
    fn insert_two_leaves_into_emptyslot() {
        let mut root = Node::default();
        assert_eq!(root, EmptySlot);
        root = insert_leaf(&mut root, &NibbleKey::from(vec![0u8; 32]), vec![1u8; 32]).unwrap();
        root = insert_leaf(&mut root, &NibbleKey::from(vec![1u8; 32]), vec![1u8; 32]).unwrap();
        assert_eq!(
            root,
            Branch(vec![
                Leaf(NibbleKey::from(vec![0u8; 31]), vec![1u8; 32]),
                Leaf(NibbleKey::from(vec![1u8; 31]), vec![1u8; 32]),
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
    fn insert_leaf_into_empty_root() {
        let children = vec![EmptySlot; 16];
        let mut root = Branch(children);
        let out = insert_leaf(&mut root, &NibbleKey::from(vec![0u8; 32]), vec![1u8; 32]);
        assert_eq!(
            out.unwrap(),
            Branch(vec![
                Leaf(NibbleKey::from(vec![0u8; 31]), vec![1u8; 32]),
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
        let mut root = Branch(vec![
            Branch(vec![EmptySlot; 16]),
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
        let out = insert_leaf(&mut root, &NibbleKey::from(vec![0u8; 32]), vec![1u8; 32]);
        assert_eq!(
            out.unwrap(),
            Branch(vec![
                Branch(vec![
                    Leaf(NibbleKey::from(vec![0u8; 30]), vec![1u8; 32]),
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
    fn insert_leaf_two_embedded_nodes() {
        let expected_root =
            hex::decode(&"0x1e1f73cc50d595585797d261df5be9bf69037a57e6470c9e4ffc87b6221ab67a"[2..])
                .unwrap();
        let inputs = [
            ("0x1111111111111111111111111111111111111111", "0xffff"),
            ("0x2222222222222222222222222222222222222222", "0xeeee"),
        ];

        let mut root = Branch(vec![EmptySlot; 16]);
        for (ik, iv) in inputs.iter() {
            let k = NibbleKey::from(utils::ByteKey(hex::decode(&ik[2..]).unwrap()));
            let v = hex::decode(&iv[2..]).unwrap();
            insert_leaf(&mut root, &k, v).unwrap();
        }

        let root_hash = root.hash();
        assert_eq!(expected_root, root_hash);
    }

    #[test]
    fn tree_with_just_one_leaf() {
        let proof = Multiproof {
            hashes: vec![],
            keyvals: vec![rlp::encode_list::<Vec<u8>, Vec<u8>>(&vec![
                vec![1, 2, 3],
                vec![4, 5, 6],
            ])],
            instructions: vec![LEAF(0)],
        };
        let out = rebuild(&proof).unwrap();
        assert_eq!(out, Leaf(NibbleKey::from(vec![]), vec![4, 5, 6]))
    }

    #[test]
    fn tree_with_one_branch() {
        let proof = Multiproof {
            hashes: vec![],
            keyvals: vec![rlp::encode_list::<Vec<u8>, Vec<u8>>(&vec![
                vec![1, 2, 3],
                vec![4, 5, 6],
            ])],
            instructions: vec![LEAF(0), BRANCH(0)],
        };
        let out = rebuild(&proof).unwrap();
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
                rlp::encode_list::<Vec<u8>, Vec<u8>>(&vec![vec![1, 2, 3], vec![4, 5, 6]]),
                rlp::encode_list::<Vec<u8>, Vec<u8>>(&vec![vec![7, 8, 9], vec![10, 11, 12]]),
            ],
            instructions: vec![LEAF(0), BRANCH(0), LEAF(1), ADD(2)],
        };
        let out = rebuild(&proof).unwrap();
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
                rlp::encode_list::<Vec<u8>, Vec<u8>>(&vec![vec![1, 2, 3], vec![4, 5, 6]]),
                rlp::encode_list::<Vec<u8>, Vec<u8>>(&vec![vec![7, 8, 9], vec![10, 11, 12]]),
            ],
        };
        let out = rebuild(&proof).unwrap();
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
    fn single_value_hash() {
        let leaf = Leaf(NibbleKey::from(vec![1, 2, 3]), vec![4, 5, 6]);
        assert_eq!(leaf.composition(), vec![199, 130, 49, 35, 131, 4, 5, 6]);
        assert_eq!(
            leaf.hash(),
            vec![
                49, 52, 36, 163, 130, 221, 147, 71, 223, 121, 140, 253, 220, 114, 118, 36, 169, 89,
                166, 229, 35, 209, 64, 242, 137, 173, 129, 227, 76, 91, 110, 151
            ]
        );
    }

    #[test]
    fn big_value_single_key_hash() {
        assert_eq!(
            Leaf(NibbleKey::from(vec![0u8; 32]), vec![4u8; 32]).hash(),
            vec![
                99, 116, 144, 157, 101, 254, 188, 135, 196, 46, 49, 240, 157, 79, 192, 61, 117,
                243, 84, 131, 36, 12, 147, 251, 17, 134, 48, 59, 76, 39, 205, 106
            ]
        );
    }

    #[test]
    fn big_value_single_big_key_hash() {
        assert_eq!(
            Leaf(NibbleKey::from(vec![0u8; 32]), vec![1u8; 32]).hash(),
            vec![
                132, 254, 5, 139, 174, 187, 212, 158, 12, 39, 213, 88, 18, 194, 107, 214, 83, 52,
                2, 1, 66, 133, 239, 172, 206, 141, 135, 220, 34, 196, 98, 222
            ]
        );
    }

    #[test]
    fn empty_value_hash() {
        let node = EmptySlot;
        assert_eq!(node.composition(), vec![0u8; 0]);
        assert_eq!(
            node.hash(),
            vec![
                197, 210, 70, 1, 134, 247, 35, 60, 146, 126, 125, 178, 220, 199, 3, 192, 229, 0,
                182, 83, 202, 130, 39, 59, 123, 250, 216, 4, 93, 133, 164, 112
            ]
        );
    }

    #[test]
    fn branch_hash() {
        let branch = Branch(vec![
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
            EmptySlot,
        ]);
        assert_eq!(
            branch.composition(),
            vec![
                219, 197, 32, 131, 4, 5, 6, 128, 197, 57, 131, 10, 11, 12, 128, 128, 128, 128, 128,
                128, 128, 128, 128, 128, 128, 128, 128, 128
            ]
        );
        assert_eq!(
            branch.hash(),
            vec![
                6, 134, 255, 246, 145, 43, 211, 204, 240, 23, 77, 89, 244, 40, 13, 2, 201, 73, 218,
                51, 53, 12, 149, 35, 120, 93, 254, 247, 104, 88, 103, 177
            ]
        );
    }

    #[test]
    fn encode_decode_instruction() {
        let instructions = vec![LEAF(1), ADD(5), EXTENSION(vec![3u8; 4]), BRANCH(6)];

        let encoded = rlp::encode_list(&instructions);
        let decoded = rlp::decode_list::<Instruction>(&encoded);
        assert_eq!(decoded, instructions);
    }

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

    #[test]
    fn roundtrip() {
        let mut tree_root = Node::Branch(vec![Node::EmptySlot; 16]);
        let new_root = insert_leaf(
            &mut tree_root,
            &NibbleKey::from(vec![1u8; 32]),
            vec![2u8; 32],
        )
        .unwrap();

        assert_eq!(
            new_root.hash(),
            vec![
                86, 102, 96, 191, 106, 199, 70, 178, 131, 236, 157, 14, 50, 168, 100, 69, 123, 66,
                223, 122, 0, 97, 18, 144, 20, 79, 250, 219, 73, 190, 134, 108
            ]
        );

        let proof = make_multiproof(&new_root, vec![NibbleKey::from(vec![1u8; 32])]).unwrap();

        // RLP roundtrip
        let proof_rlp = rlp::encode(&proof);
        let proof = rlp::decode(&proof_rlp).unwrap();

        let rebuilt_root = rebuild(&proof).unwrap();
        assert_eq!(new_root, rebuilt_root);
    }

    fn hex_string_to_vec(s: &str) -> Vec<u8> {
        // Assumes `0x` prefix
        (2..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn test_nullkey_leaf() {
        let missing_key = NibbleKey::from(vec![1u8; 32]);
        let mut root = Node::default();
        root = insert_leaf(&mut root, &NibbleKey::from(vec![0u8; 32]), vec![0u8; 32]).unwrap();
        root = insert_leaf(
            &mut root,
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

        let rebuilt = rebuild(&proof).unwrap();
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
        assert!(!rebuilt.is_key_present(&missing_key));
    }

    #[test]
    fn test_nullkey_ext() {
        let missing_key = NibbleKey::from(vec![1u8; 32]);
        let mut root = Node::default();
        root = insert_leaf(
            &mut root,
            &NibbleKey::from(ByteKey::from(
                hex::decode("11111111111111182222222222222222").unwrap(),
            )),
            vec![0u8; 32],
        )
        .unwrap();
        root = insert_leaf(
            &mut root,
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

        let rebuilt = rebuild(&proof).unwrap();
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
        assert!(!rebuilt.is_key_present(&missing_key));
    }

    #[test]
    fn test_nullkey_branch() {
        let missing_key = NibbleKey::from(vec![2u8; 32]);
        let mut root = Node::default();
        root = insert_leaf(
            &mut root,
            &NibbleKey::from(ByteKey::from(
                hex::decode("11111111111111182222222222222222").unwrap(),
            )),
            vec![0u8; 32],
        )
        .unwrap();
        root = insert_leaf(
            &mut root,
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

        let rebuilt = rebuild(&proof).unwrap();
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
        assert!(!rebuilt.is_key_present(&missing_key));
    }

    #[test]
    fn test_nullkey_empty() {
        let root = Node::default();
        let missing_key = NibbleKey::from(vec![2u8; 32]);

        let proof = make_multiproof(&root, vec![missing_key.clone()]).unwrap();
        let rebuilt = rebuild(&proof).unwrap();
        assert!(!rebuilt.is_key_present(&missing_key));
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
        root = insert_leaf(&mut root, k1, vec![0u8; 32]).unwrap();
        root = insert_leaf(&mut root, k2, vec![0u8; 32]).unwrap();
        root = insert_leaf(&mut root, k3, vec![0u8; 32]).unwrap();

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
        root = insert_leaf(&mut root, k1, vec![0u8; 32]).unwrap();
        root = insert_leaf(&mut root, k2, vec![0u8; 32]).unwrap();
        root = insert_leaf(&mut root, k3, vec![0u8; 32]).unwrap();

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
        root = insert_leaf(&mut root, k1, vec![0u8; 32]).unwrap();
        root = insert_leaf(&mut root, k2, vec![0u8; 32]).unwrap();
        root = insert_leaf(&mut root, k3, vec![0u8; 32]).unwrap();

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

        root = insert_leaf(&mut root, k1, vec![0u8; 32]).unwrap();
        root = insert_leaf(&mut root, k2, vec![0u8; 32]).unwrap();
        root = insert_leaf(&mut root, k3, vec![0u8; 32]).unwrap();

        assert!(root.is_key_present(k1));
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

        root = insert_leaf(&mut root, k2, vec![0u8; 32]).unwrap();
        root = insert_leaf(&mut root, k3, vec![0u8; 32]).unwrap();

        assert!(!root.is_key_present(k1));
    }
}
