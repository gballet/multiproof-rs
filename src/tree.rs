use super::utils::*;

pub struct NodeChildIterator<'a, K, V> {
    pub index: usize,
    pub node: &'a dyn Tree<Key = K, Value = V>,
}

/// A trait representing the an underlying tree structure.
pub trait Tree {
    /// The tree's key type. Must be specified when implementing this trait.
    type Key;
    /// The tree's value type. Must be specified when implementing this trait.
    type Value;

    /// Specifies if the current tree is a simple leaf.
    fn is_leaf(&self) -> bool;
    /// Specifies if the current tree is empty.
    fn is_empty(&self) -> bool;
    /// Returns the tree root's *maximal* number of children.
    fn num_children(&self) -> usize;
    /// Returns a pointer to child #i, or `None` if no such child exists.
    fn ith_child(&self, index: usize) -> Option<&dyn Tree<Key = Self::Key, Value = Self::Value>>;
    /// Returns an iterator to the node's children. Some of these nodes can be empty.
    fn children(&self) -> NodeChildIterator<Self::Key, Self::Value>;
    /// Insert a `(key,value)` pair into a (sub-)tree represented by `root`.
    fn insert(&mut self, key: &Self::Key, value: Self::Value) -> Result<(), String>;
}

impl<'a> std::iter::Iterator for NodeChildIterator<'a, NibbleKey, Vec<u8>> {
    type Item = &'a dyn Tree<Key = NibbleKey, Value = Vec<u8>>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.index < self.node.num_children() {
            self.index += 1;
            self.node.ith_child(self.index - 1)
        } else {
            None
        }
    }
}
