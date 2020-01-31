extern crate sha3;

use super::keys::*;
use super::tree::*;

#[derive(Debug, Clone, PartialEq)]
pub enum BinaryTree {
    Hash(Vec<u8>),
    Leaf(BinaryKey, Vec<u8>),
    Branch(Box<BinaryTree>, Box<BinaryTree>),
    EmptyChild,
}

impl NodeType for BinaryTree {
    type Key = BinaryKey;
    type Value = Vec<u8>;
}

impl Tree<BinaryTree> for BinaryTree {
    fn is_leaf(&self) -> bool {
        match self {
            BinaryTree::Leaf(_, _) => true,
            _ => false,
        }
    }

    fn is_empty(&self) -> bool {
        match self {
            BinaryTree::EmptyChild => true,
            _ => false,
        }
    }

    fn num_children(&self) -> usize {
        match self {
            BinaryTree::EmptyChild | BinaryTree::Leaf(_, _) | BinaryTree::Hash(_) => 0usize,
            BinaryTree::Branch(_, _) => 2usize,
        }
    }

    fn ith_child(&self, index: usize) -> Option<&Self> {
        if index >= self.num_children() {
            panic!(format!(
                "Requested child number #{}, only have #{}",
                index,
                self.num_children()
            ));
        }

        match self {
            BinaryTree::Branch(box left, box right) => {
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
            BinaryTree::Branch(box left, box right) => {
                if index == 0 {
                    *self = BinaryTree::Branch(Box::new(child.clone()), Box::new(right.clone()));
                } else {
                    *self = BinaryTree::Branch(Box::new(left.clone()), Box::new(child.clone()));
                }
            }
            _ => panic!("Only internal nodes can have their children set in this implementation."),
        }
    }

    fn insert(&mut self, key: &BinaryKey, value: Vec<u8>) -> Result<(), String> {
        let mut kit = key.iter();
        match self {
            BinaryTree::Leaf(ref leafkey, leafvalue) => {
                let mut lit = leafkey.iter();
                match (kit.next(), lit.next()) {
                    // Keep inserting branches until the two keys
                    // differ.
                    (Some(k), Some(l)) if k == l => {
                        let mut child = BinaryTree::Leaf(BinaryKey::from(lit), leafvalue.to_vec());
                        child.insert(&BinaryKey::from(kit), value)?;
                        let (left, right) = match k {
                            true => (child, BinaryTree::EmptyChild),
                            false => (BinaryTree::EmptyChild, child),
                        };
                        *self = BinaryTree::Branch(Box::new(left), Box::new(right));
                    }
                    (Some(k), Some(_)) => {
                        let orig = BinaryTree::Leaf(BinaryKey::from(lit), leafvalue.to_vec());
                        let new = BinaryTree::Leaf(BinaryKey::from(kit), value);
                        let (left, right) = match k {
                            false => (new, orig),
                            true => (orig, new),
                        };
                        *self = BinaryTree::Branch(Box::new(left), Box::new(right));
                    }
                    // Both reached the end, update (TODO)
                    (None, None) => panic!("No update currently supported"),
                    _ => panic!("Key length mismatch in insert"),
                }
                Ok(())
            }
            BinaryTree::Branch(box left, box right) => {
                if key[0] {
                    left.insert(&key.tail(), value)
                } else {
                    right.insert(&key.tail(), value)
                }
            }
            BinaryTree::EmptyChild => {
                *self = BinaryTree::Leaf(key.clone(), value);
                Ok(())
            }
            _ => panic!("Can not insert in this node type"),
        }
    }

    fn has_key(&self, key: &BinaryKey) -> bool {
        match self {
            BinaryTree::Leaf(ref k, _) => k == key,
            BinaryTree::Hash(_) => false,
            BinaryTree::Branch(box left, box right) => {
                if key[0] {
                    left.has_key(&key.tail())
                } else {
                    right.has_key(&key.tail())
                }
            }
            BinaryTree::EmptyChild => false,
        }
    }

    fn value(&self) -> Option<&Vec<u8>> {
        match self {
            BinaryTree::Leaf(_, ref v) => Some(v),
            _ => None,
        }
    }

    fn value_length(&self) -> Option<usize> {
        match self {
            BinaryTree::Leaf(_, ref v) => Some(v.len()),
            _ => None,
        }
    }
    fn from_hash(h: Vec<u8>) -> Self {
        BinaryTree::Hash(h.to_vec())
    }

    fn new_extension(_ext: Vec<u8>, _child: Self) -> Self {
        // TODO see if a simple list of nodes can be created
        // instead of panicking
        panic!("Extensions not supported");
    }

    fn new_branch() -> Self {
        BinaryTree::Branch(
            Box::new(BinaryTree::EmptyChild),
            Box::new(BinaryTree::EmptyChild),
        )
    }

    fn new_leaf(key: Vec<u8>, value: Vec<u8>) -> Self {
        BinaryTree::Leaf(BinaryKey::from(key), value)
    }

    fn new_empty() -> Self {
        BinaryTree::EmptyChild
    }
}

impl Default for BinaryTree {
    fn default() -> Self {
        BinaryTree::EmptyChild
    }
}

#[cfg(test)]
mod tests {
    use super::BinaryTree::*;
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
        let mut root = BinaryTree::new_branch();

        root.insert(&BinaryKey::from(vec![5u8; 32]), vec![10; 32])
            .unwrap();

        assert_eq!(
            root,
            Branch(
                Box::new(Leaf(BinaryKey::new(vec![5u8; 32], 6, 0), vec![10; 32])),
                Box::new(EmptyChild)
            )
        );
    }

    #[test]
    fn insert_leaf() {
        let mut root = BinaryTree::new_leaf(vec![0x66u8; 32], vec![10; 32]);

        root.insert(&BinaryKey::from(vec![0x55u8; 32]), vec![10; 32])
            .unwrap();

        assert_eq!(
            root,
            Branch(
                Box::new(Branch(
                    Box::new(EmptyChild),
                    Box::new(Branch(
                        Box::new(Leaf(BinaryKey::new(vec![0x55u8; 32], 4, 0), vec![10; 32])),
                        Box::new(Leaf(BinaryKey::new(vec![0x66u8; 32], 4, 0), vec![10; 32])),
                    )),
                )),
                Box::new(EmptyChild)
            )
        );
    }
}
