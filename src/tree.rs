pub struct NodeChildIterator<'a, N: NodeType, T: Tree<N>> {
    /// The iterator's current child index.
    pub index: usize,
    /// The node's current key, if available.
    pub key: Option<&'a N::Key>,
    /// The node whose children are being iterated on.
    pub node: &'a T,
}

/// Represents the type of keys and values stored into the tree.
///
/// To implement tre trait, one has to specify the types of `Key`
/// and `Value`. A further requirement is that implementors must
/// also implement the `Default` trait.
pub trait NodeType: Default {
    /// The tree's key type. Must be specified when implementing this trait.
    type Key;
    /// The tree's value type. Must be specified when implementing this trait.
    type Value;
}

/// A trait representing the an underlying tree structure.
pub trait Tree<N: NodeType>: Sized {
    /// Specifies if the current tree is a simple leaf.
    fn is_leaf(&self) -> bool;
    /// Specifies if the current tree is empty.
    fn is_empty(&self) -> bool;
    /// Returns the tree root's *maximal* number of children.
    fn num_children(&self) -> usize;
    /// Returns a pointer to child #i, or `None` if no such child exists.
    fn ith_child(&self, index: usize) -> Option<&Self>;
    /// Set child node #i of the current node.
    fn set_ith_child(&mut self, index: usize, child: &Self);
    /// Returns an iterator to the node's children. Some of these nodes can be empty.
    fn children(&self) -> NodeChildIterator<N, Self>;
    /// Insert a `(key,value)` pair into a (sub-)tree represented by `root`.
    fn insert(&mut self, key: &N::Key, value: N::Value) -> Result</* TODO &mut self */ (), String>;

    fn value(&self) -> Option<&N::Value>;
    fn value_length(&self) -> Option<usize>;

    fn from_hash(h: Vec<u8>) -> Self;
    fn new_empty() -> Self;
    fn new_extension(ext: Vec<u8>, child: Self) -> Self;
    fn new_branch() -> Self;
    fn new_leaf(key: Vec<u8>, value: Vec<u8>) -> Self;
}

impl<'a, N: NodeType, T: Tree<N>> std::iter::Iterator for NodeChildIterator<'a, N, T> {
    type Item = &'a T;

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
