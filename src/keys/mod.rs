pub mod binary_key;
pub mod byte_key;
pub mod nibble_key;

pub use binary_key::*;
pub use byte_key::*;
pub use nibble_key::*;

/// Used as an abstraction of the key type, for handling in generic
/// tree/proof constructions.
pub trait Key<T> {
    /// Returns a copy of the current key, in which the first unit
    /// (i.e. byte, bit, nibble) has been removed. Note that the
    /// tail of an empty list is another empty list.
    fn tail(&self) -> Self;

    /// Returns the number of units (i.e. bit, nibble or byte)
    fn len(&self) -> usize;

    /// Returns `true` if the key is zero unit long.
    fn is_empty(&self) -> bool;

    /// Returns the length of the common prefix between `self`
    /// and `other`.
    fn common_prefix(&self, other: &Self) -> usize;
}
