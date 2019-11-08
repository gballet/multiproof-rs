extern crate sha3;

use super::utils::*;
use sha3::{Digest, Keccak256};

#[derive(Debug, Clone, PartialEq)]
pub enum Node {
    Hash(Vec<u8>),
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
        let key_bytes = ByteKey(keyval[0].clone());
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
            Node::Hash(_) => {
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
    pub fn composition(&self) -> Vec<u8> {
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

#[cfg(test)]
mod tests {
    use super::Node::*;
    use super::*;

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
}
