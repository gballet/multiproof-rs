pub mod binary_key;
pub mod byte_key;
pub mod nibble_key;

pub use binary_key::*;
pub use byte_key::*;
pub use nibble_key::*;

/// Used as an abstraction of the key type, for handling in generic
/// tree/proof constructions.
pub trait Key<T> {
    /// Separates the "head" unit (i.e. bit, nibble or byte) from
    /// the "tail", i.e. the rest of the key.
    fn head_and_tail(&self) -> (Option<T>, Self);

    /// Returns the number of units (i.e. bit, nibble or byte)
    fn len(&self) -> usize;

    /// Returns `true` if the key is zero unit long.
    fn is_empty(&self) -> bool;
}
