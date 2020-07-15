extern crate sha3;

use super::keys::*;
use super::tree::*;

// Binary tries with extensions as described in https://ethresear.ch/t/binary-trie-format/7621/6
#[derive(Debug, Clone, PartialEq)]
pub enum BinaryExtTree {
    Hash(Vec<u8>),
    Leaf(BinaryKey, Vec<u8>),
    Branch(BinaryKey, Box<BinaryExtTree>, Box<BinaryExtTree>),
    EmptyChild,
}

impl NodeType for BinaryExtTree {
    type Key = BinaryKey;
    type Value = Vec<u8>;
}

impl Tree<BinaryExtTree> for BinaryExtTree {
    fn is_leaf(&self) -> bool {
        match self {
            BinaryExtTree::Leaf(_, _) => true,
            _ => false,
        }
    }

    fn is_empty(&self) -> bool {
        match self {
            BinaryExtTree::EmptyChild => true,
            _ => false,
        }
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
                        let (left, right) = match b {
                            0 => (
                                BinaryExtTree::Leaf(child_prefix, leafvalue[..].to_vec()),
                                BinaryExtTree::Leaf(new_key, value),
                            ),
                            _ => (
                                BinaryExtTree::Leaf(new_key, value),
                                BinaryExtTree::Leaf(child_prefix, leafvalue[..].to_vec()),
                            ),
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
                        let (left, right) = if b == 0 {
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

                if key[prefix.len()] == 0 {
                    l.insert(&key.tail(), value)
                } else {
                    r.insert(&key.tail(), value)
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

                if key[prefix.len()] == 0 {
                    left.has_key(&child_key)
                } else {
                    right.has_key(&child_key)
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
