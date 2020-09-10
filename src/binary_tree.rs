extern crate sha3;

use super::hashable::Hashable;
use super::keys::*;
use super::tree::*;
use sha3::{Digest, Keccak256};

// Binary tries with extensions as described in https://ethresear.ch/t/binary-trie-format/7621/6
#[derive(Debug, Clone, PartialEq)]
pub enum BinaryExtTree {
    Hash(Vec<u8>),
    Leaf(BinaryKey, Vec<u8>),
    Branch(BinaryKey, Box<BinaryExtTree>, Box<BinaryExtTree>),
    EmptyChild,
}

impl Hashable for BinaryExtTree {
    fn hash(&self) -> Vec<u8> {
        self.hash_m2()
    }
}

impl BinaryExtTree {
    fn hash_m2(&self) -> Vec<u8> {
        match self {
            BinaryExtTree::Hash(h) => h.to_vec(),
            BinaryExtTree::Leaf(key, val) => {
                let mut keccak256 = Keccak256::new();
                keccak256.input(vec![0u8]);
                keccak256.input(val);
                let h = keccak256.result_reset();
                keccak256.input::<Vec<u8>>(key.into());
                keccak256.input(h.to_vec());
                keccak256.result().to_vec()
            }
            BinaryExtTree::Branch(prefix, box left, box right) => {
                let mut keccak256 = Keccak256::new();
                keccak256.input(left.hash());
                keccak256.input(right.hash());
                let h = keccak256.result_reset();
                keccak256.input::<Vec<u8>>(prefix.into());
                keccak256.input(h);
                keccak256.result().to_vec()
            }
            BinaryExtTree::EmptyChild => {
                let keccak256 = Keccak256::new();
                keccak256.result().to_vec()
            }
        }
    }

    pub fn hash_m3(&self) -> Vec<u8> {
        self.hash_m3_helper(Vec::new())
    }

    fn hash_m3_helper(&self, bits: Vec<bool>) -> Vec<u8> {
        match self {
            BinaryExtTree::Hash(h) => h.to_vec(),
            BinaryExtTree::Leaf(key, val) => {
                // Add all the missing bits and convert the array
                // to a BinaryKey.
                let mut final_bits = bits;
                let prefix_bits: Vec<bool> = key.into();
                final_bits.extend_from_slice(&prefix_bits[..]);

                let binkey = BinaryKey::from(final_bits);

                let mut keccak256 = Keccak256::new();
                keccak256.input::<Vec<u8>>((&binkey).into());
                keccak256.input(val);
                keccak256.result().to_vec()
            }
            BinaryExtTree::Branch(prefix, box left, box right) => {
                let mut subkey = bits;

                let prefix_bits: Vec<bool> = prefix.into();
                subkey.extend_from_slice(&prefix_bits[..]);

                subkey.push(false);
                let left_h = left.hash_m3_helper(subkey[..].to_vec());
                *subkey.last_mut().unwrap() = true;

                let right_h = right.hash_m3_helper(subkey);
                let mut keccak256 = Keccak256::new();
                keccak256.input(left_h);
                keccak256.input(right_h);
                keccak256.result().to_vec()
            }
            BinaryExtTree::EmptyChild => {
                let keccak256 = Keccak256::new();
                keccak256.result().to_vec()
            }
        }
    }

    pub fn hash_m4(&self) -> Vec<u8> {
        let mut keccak256 = Keccak256::new();
        match self {
            BinaryExtTree::Hash(h) => return h.to_vec(),
            BinaryExtTree::Leaf(key, val) => {
                keccak256.input(vec![0u8]);
                keccak256.input(val);
                let mut rewind: Vec<u8>;
                for i in 0..key.len() {
                    rewind = keccak256.result_reset().to_vec().clone();
                    if key[key.len() - 1 - i] {
                        keccak256.input(BinaryExtTree::EmptyChild.hash_m4());
                        keccak256.input(rewind);
                    } else {
                        keccak256.input(rewind);
                        keccak256.input(BinaryExtTree::EmptyChild.hash_m4());
                    }
                }
            }
            BinaryExtTree::Branch(prefix, box left, box right) => {
                keccak256.input(left.hash_m4());
                keccak256.input(right.hash_m4());
                let mut rewind: Vec<u8>;
                for i in 0..prefix.len() {
                    rewind = keccak256.result_reset().to_vec().clone();
                    if prefix[prefix.len() - 1 - i] {
                        keccak256.input(BinaryExtTree::EmptyChild.hash_m4());
                        keccak256.input(rewind);
                    } else {
                        keccak256.input(rewind);
                        keccak256.input(BinaryExtTree::EmptyChild.hash_m4());
                    }
                }
            }
            BinaryExtTree::EmptyChild => {}
        }
        keccak256.result().to_vec()
    }
}

impl NodeType for BinaryExtTree {
    type Key = BinaryKey;
    type Value = Vec<u8>;
}

impl Tree<BinaryExtTree> for BinaryExtTree {
    fn is_leaf(&self) -> bool {
        matches!(self, BinaryExtTree::Leaf(_, _))
    }

    fn is_empty(&self) -> bool {
        matches!(self, BinaryExtTree::EmptyChild)
    }

    fn num_children(&self) -> usize {
        match self {
            BinaryExtTree::EmptyChild | BinaryExtTree::Leaf(_, _) | BinaryExtTree::Hash(_) => {
                0usize
            }
            BinaryExtTree::Branch(_, _, _) => 2usize,
        }
    }

    fn ith_child(&self, index: usize) -> Option<&Self> {
        if index >= self.num_children() {
            return None;
        }

        match self {
            BinaryExtTree::Branch(_, box left, box right) => {
                if index == 0 {
                    Some(left)
                } else {
                    Some(right)
                }
            }
            _ => None,
        }
    }

    fn set_ith_child(&mut self, index: usize, child: &Self) {
        if index >= self.num_children() {
            panic!(format!(
                "Requested child number #{}, only have #{}",
                index,
                self.num_children()
            ));
        }

        match self {
            BinaryExtTree::Branch(ref prefix, box left, box right) => {
                if index == 0 {
                    *self = BinaryExtTree::Branch(
                        prefix.clone(),
                        Box::new(child.clone()),
                        Box::new(right.clone()),
                    );
                } else {
                    *self = BinaryExtTree::Branch(
                        prefix.clone(),
                        Box::new(left.clone()),
                        Box::new(child.clone()),
                    );
                }
            }
            _ => panic!("Only internal nodes can have their children set in this implementation."),
        }
    }

    fn insert(&mut self, key: &BinaryKey, value: Vec<u8>) -> Result<(), String> {
        match self {
            BinaryExtTree::Leaf(ref leafkey, leafvalue) => {
                // Look for the point where keys split
                for (i, b) in leafkey.iter().enumerate() {
                    if key[i] != b {
                        let (parent_prefix, child_prefix) = leafkey.split(i);
                        let new_key = key.suffix(i);
                        let (left, right) = if b {
                            (
                                BinaryExtTree::Leaf(new_key, value),
                                BinaryExtTree::Leaf(child_prefix, leafvalue[..].to_vec()),
                            )
                        } else {
                            (
                                BinaryExtTree::Leaf(child_prefix, leafvalue[..].to_vec()),
                                BinaryExtTree::Leaf(new_key, value),
                            )
                        };
                        *self =
                            BinaryExtTree::Branch(parent_prefix, Box::new(left), Box::new(right));
                        return Ok(());
                    }
                }

                // No split, replace the value
                *leafvalue = value;
                Ok(())
            }
            BinaryExtTree::Branch(ref prefix, box l, box r) => {
                // Look for the point where keys split
                for (i, b) in prefix.iter().enumerate() {
                    if key[i] != b {
                        let (parent_prefix, child_prefix) = prefix.split(i);
                        let new_key = key.suffix(i);
                        let (left, right) = if b {
                            (
                                BinaryExtTree::Branch(
                                    child_prefix,
                                    Box::new(l.clone()),
                                    Box::new(r.clone()),
                                ),
                                BinaryExtTree::Leaf(new_key, value),
                            )
                        } else {
                            (
                                BinaryExtTree::Leaf(new_key, value),
                                BinaryExtTree::Branch(
                                    child_prefix,
                                    Box::new(l.clone()),
                                    Box::new(r.clone()),
                                ),
                            )
                        };
                        *self =
                            BinaryExtTree::Branch(parent_prefix, Box::new(left), Box::new(right));
                        return Ok(());
                    }
                }

                let child_prefix = key.suffix(prefix.len());
                if key[prefix.len()] {
                    r.insert(&child_prefix, value)
                } else {
                    l.insert(&child_prefix, value)
                }
            }
            BinaryExtTree::EmptyChild => {
                *self = BinaryExtTree::Leaf(key.clone(), value);
                Ok(())
            }
            _ => panic!("Can not insert in this node type"),
        }
    }

    fn has_key(&self, key: &BinaryKey) -> bool {
        match self {
            BinaryExtTree::Leaf(ref k, _) => k == key,
            BinaryExtTree::Hash(_) => false,
            BinaryExtTree::Branch(ref prefix, box left, box right) => {
                if key.len() < prefix.len() {
                    return true;
                }

                let mut child_key = key.clone();
                for (i, b) in prefix.iter().enumerate() {
                    if key[i] != b {
                        return false;
                    }
                    child_key = child_key.tail();
                }

                if key[prefix.len()] {
                    right.has_key(&child_key)
                } else {
                    left.has_key(&child_key)
                }
            }
            BinaryExtTree::EmptyChild => false,
        }
    }

    fn value(&self) -> Option<&Vec<u8>> {
        match self {
            BinaryExtTree::Leaf(_, ref v) => Some(v),
            _ => None,
        }
    }

    fn value_length(&self) -> Option<usize> {
        match self {
            BinaryExtTree::Leaf(_, ref v) => Some(v.len()),
            _ => None,
        }
    }
    fn from_hash(h: Vec<u8>) -> Self {
        BinaryExtTree::Hash(h.to_vec())
    }

    fn new_extension(ext: Vec<u8>, child: Self) -> Self {
        let (left, right) = match ext[ext.len() - 1] {
            0 => (Box::new(child), Box::new(BinaryExtTree::EmptyChild)),
            _ => (Box::new(BinaryExtTree::EmptyChild), Box::new(child)),
        };
        let ext_len = ext.len();
        BinaryExtTree::Branch(BinaryKey::new(ext, 0, ext_len - 1), left, right)
    }

    fn new_branch() -> Self {
        BinaryExtTree::Branch(
            BinaryKey::new(vec![], 0, 0),
            Box::new(BinaryExtTree::EmptyChild),
            Box::new(BinaryExtTree::EmptyChild),
        )
    }

    fn new_leaf(key: Vec<u8>, value: Vec<u8>) -> Self {
        BinaryExtTree::Leaf(BinaryKey::from(key), value)
    }

    fn new_empty() -> Self {
        BinaryExtTree::EmptyChild
    }
}

impl Default for BinaryExtTree {
    fn default() -> Self {
        BinaryExtTree::EmptyChild
    }
}

#[cfg(test)]
mod tests {
    use super::BinaryExtTree::*;
    use super::*;

    #[test]
    fn simple_insert() {
        let mut root = EmptyChild;

        root.insert(&BinaryKey::from(vec![5u8; 32]), vec![10; 32])
            .unwrap();

        assert_eq!(root, Leaf(BinaryKey::from(vec![5u8; 32]), vec![10; 32]));
    }

    #[test]
    fn insert_branch() {
        let mut root = BinaryExtTree::new_branch();

        root.insert(&BinaryKey::from(vec![5u8; 32]), vec![10; 32])
            .unwrap();

        assert_eq!(
            root,
            Branch(
                BinaryKey::new(vec![], 0, 0),
                Box::new(Leaf(BinaryKey::new(vec![5u8; 32], 1, 256), vec![10; 32])),
                Box::new(EmptyChild)
            )
        );
    }

    #[test]
    fn insert_branch_with_prefix() {
        let mut root = Branch(
            BinaryKey::new(vec![5u8; 32], 0, 15),
            Box::new(EmptyChild),
            Box::new(EmptyChild),
        );

        root.insert(&BinaryKey::from(vec![5u8; 32]), vec![10; 32])
            .unwrap();

        assert_eq!(
            root,
            Branch(
                BinaryKey::new(vec![5u8; 32], 0, 15),
                Box::new(EmptyChild),
                Box::new(Leaf(BinaryKey::new(vec![5u8; 32], 16, 256), vec![10; 32])),
            )
        );
    }

    #[test]
    fn insert_leaf() {
        let mut root = BinaryExtTree::new_leaf(vec![0x66u8; 32], vec![10; 32]);

        root.insert(&BinaryKey::from(vec![0x55u8; 32]), vec![10; 32])
            .unwrap();

        assert_eq!(
            root,
            Branch(
                BinaryKey::new(vec![0x55u8; 32], 0, 2),
                Box::new(Leaf(BinaryKey::new(vec![0x55u8; 32], 3, 256), vec![10; 32])),
                Box::new(Leaf(BinaryKey::new(vec![0x66u8; 32], 3, 256), vec![10; 32]))
            )
        );
    }

    #[test]
    fn m4_hash_empty() {
        let root = BinaryExtTree::default();
        assert_eq!(
            root.hash_m4(),
            vec![
                197, 210, 70, 1, 134, 247, 35, 60, 146, 126, 125, 178, 220, 199, 3, 192, 229, 0,
                182, 83, 202, 130, 39, 59, 123, 250, 216, 4, 93, 133, 164, 112
            ]
        )
    }

    #[test]
    fn m4_hash_single_leaf() {
        let mut root = BinaryExtTree::default();
        let k = BinaryKey::from(vec![0x55u8; 32]);
        root.insert(&k, vec![10; 32]).unwrap();

        let mut digest = Keccak256::new();
        digest.input(vec![0u8]);
        digest.input(vec![10u8; 32]);
        let mut rewind = digest.result_reset().to_vec();
        for i in 0..k.len() {
            if k[255 - i] {
                digest.input(BinaryExtTree::EmptyChild.hash_m4());
            }
            digest.input(rewind);
            if !k[255 - i] {
                digest.input(BinaryExtTree::EmptyChild.hash_m4());
            }
            rewind = digest.result_reset().to_vec();
        }

        assert_eq!(root.hash_m4(), rewind);
    }

    #[test]
    fn m4_hash_single_branch_split() {
        let mut root = BinaryExtTree::default();
        let k1 = BinaryKey::from(vec![0x00u8; 32]); // First bit = 0
        root.insert(&k1, vec![10; 32]).unwrap();
        let k2 = BinaryKey::from(vec![0xFFu8; 32]); // First bit = 1
        root.insert(&k2, vec![10; 32]).unwrap();

        let m4_hash = root.hash_m4();

        if let BinaryExtTree::Branch(prefix, box left, box right) = root {
            let mut digest = Keccak256::new();
            digest.input(left.hash_m4());
            digest.input(right.hash_m4());
            let h = digest.result().to_vec();

            assert_eq!(prefix.len(), 0);
            assert_eq!(m4_hash, h);
        }
    }
}
