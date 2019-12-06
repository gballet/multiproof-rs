pub mod binary_key;
pub mod byte_key;
//pub mod nibble_key;

pub use binary_key::*;
pub use byte_key::*;
//pub use nibble_key::*;

pub trait Key<T> {
    /// separates the "head" unit (i.e. bit, nibble or byte) from
    /// the "tail", i.e. the rest of the key.
    fn head_and_tail(&self) -> (Option<T>, Self);

    fn len(&self) -> usize;

    fn is_empty(&self) -> bool;
}
