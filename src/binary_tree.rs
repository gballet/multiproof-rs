use super::tree::*;
use super::*;

#[derive(Debug, Clone, PartialEq)]
pub enum BinaryNode {
    Hash(Vec<u8>),
    Leaf(Vec<u8>),
    Branch(Box<BinaryNode>, Box<BinaryNode>),
    EmptyChild,
}

impl NodeType for BinaryNode {
    type Key = BinaryKey;
    type Value = Vec<u8>;
}

impl Tree<BinaryNode> for BinaryNode {
    fn is_leaf(&self) -> bool {
        match self {
            BinaryNode::Leaf(_) => true,
            _ => false,
        }
    }

    fn is_empty(&self) -> bool {
        match self {
            BinaryNode::EmptyChild => true,
            _ => false,
        }
    }

    /// Returns the *maximum* child count of the tree's root.
    ///
    /// Branch nodes will always report 16, as empty slots are counted as children.
    fn num_children(&self) -> usize {
        match self {
            BinaryNode::EmptyChild | BinaryNode::Leaf(_) | BinaryNode::Hash(_) => 0usize,
            BinaryNode::Branch(_, _) => 16usize,
        }
    }

    /// Return the tree root's *ith* child.
    ///
    /// The function will return `EmptyChild` instead of `None` if a branch node has no *ith* child.
    fn ith_child(&self, index: usize) -> Option<&Self> {
        if index >= self.num_children() {
            panic!(format!(
                "Requested child #{}, only have #{}",
                index,
                self.num_children()
            ));
        }

        match self {
            BinaryNode::EmptyChild | BinaryNode::Leaf(_) | BinaryNode::Hash(_) => None,
            BinaryNode::Branch(ref left, ref right) => match index {
                0 => Some(left),
                1 => Some(right),
                _ => Some(&BinaryNode::EmptyChild),
            },
        }
    }

    fn set_ith_child(&mut self, index: usize, child: &Self) {
        if index >= self.num_children() {
            panic!(format!(
                "Requested child #{}, only have #{}",
                index,
                self.num_children()
            ));
        }

        match self {
            BinaryNode::Branch(box left, box right) => {
                if index == 0 {
                    if left.is_empty() {
                        *self = BinaryNode::Branch(Box::new(child.clone()), Box::new(right.clone()))
                    } else {
                        panic!("Refusing to overwrite child node");
                    }
                } else {
                    if right.is_empty() {
                        *self = BinaryNode::Branch(Box::new(left.clone()), Box::new(child.clone()))
                    } else {
                        panic!("Refusing to overwrite child node");
                    }
                }
            }
            _ => panic!("Only branch nodes can be set in this implementation."),
        }
    }

    fn children(&self) -> NodeChildIterator<Self, Self> {
        NodeChildIterator {
            index: 0,
            key: None,
            node: &self,
        }
    }

    fn insert(&mut self, key: &BinaryKey, value: Vec<u8>) -> Result<(), String> {
        use BinaryNode::*;

        if key.is_empty() {
            return Err("Attempted to insert a 0-byte key".to_string());
        }

        match self {
            Leaf(_) => {
                // If we reach this point, we have reached the bottom of a tree
                // and this should not happen. Report an error.
                Err("A key is already present".to_string())
            }
            Branch(ref mut left, ref mut right) => {
                if key.is_empty() {
                    return Err("Key shorter than the tree depth".to_string());
                }
                let childptr = if key[0] == 0 { left } else { right };
                // Recurse into the child node.
                (*childptr).insert(&key.tail(), value)?;
                Ok(())
            }
            EmptyChild => {
                // Found the fork, create the final leaf and
                // build the path until then, from the bottom
                // up.
                let mut child = Leaf(value);
                for i in 0..key.len() {
                    if key[key.len() - i - 1] == 0 {
                        child = Branch(Box::new(child), Box::new(EmptyChild));
                    } else {
                        child = Branch(Box::new(EmptyChild), Box::new(child));
                    }
                }
                *self = child;
                Ok(())
            }
            _ => panic!("Can not insert a node into a hashed node"),
        }
    }

    fn has_key(&self, key: &BinaryKey) -> bool {
        match self {
            // Key is present if we hit a leaf and
            // we have walked the entire key.
            BinaryNode::Leaf(_) => key.len() == 0,
            BinaryNode::Branch(ref left, ref right) => {
                if key[0] == 0 {
                    left.has_key(&key.tail())
                } else {
                    right.has_key(&key.tail())
                }
            }
            _ => false,
        }
    }

    fn value(&self) -> Option<&Vec<u8>> {
        match self {
            BinaryNode::Leaf(ref v) => Some(v),
            _ => None,
        }
    }

    fn value_length(&self) -> Option<usize> {
        match self {
            BinaryNode::Leaf(ref v) => Some(v.len()),
            _ => None,
        }
    }

    fn from_hash(h: Vec<u8>) -> Self {
        BinaryNode::Hash(h.to_vec())
    }

    fn new_extension(_ext: Vec<u8>, _child: Self) -> Self {
        panic!("This operation isn't supported by this kind of tree");
    }

    fn new_branch() -> Self {
        BinaryNode::Branch(
            Box::new(BinaryNode::EmptyChild),
            Box::new(BinaryNode::EmptyChild),
        )
    }

    fn new_leaf(key: Vec<u8>, value: Vec<u8>) -> Self {
        if !key.is_empty() {
            panic!("Key should be empty in leaf creation")
        }
        BinaryNode::Leaf(value)
    }

    fn new_empty() -> Self {
        BinaryNode::EmptyChild
    }
}

impl Default for BinaryNode {
    fn default() -> Self {
        BinaryNode::EmptyChild
    }
}
