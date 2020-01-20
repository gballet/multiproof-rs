pub mod byte_key;
pub mod nibble_key;

pub use byte_key::*;
pub use nibble_key::*;

/// An iterator that will walk the elements of the key. `U` is the unit
/// type of a key element (e.g. byte, bit, nibble) and `K` is the key type.
pub struct KeyIterator<'a, U, K: Key<U> + std::ops::Index<usize, Output = U>> {
    /// Index of the element that the iterator is currently pointing at.
    item_num: usize,

    /// A reference to the object being iterated.
    container: &'a K,

    last_element: U,
}

/// Used as an abstraction of the key type, for handling in generic
/// tree/proof constructions.
pub trait Key<T: std::marker::Sized> {
    /// Returns the number of units (i.e. bit, nibble or byte)
    fn len(&self) -> usize;

    /// Returns `true` if the key is zero unit long.
    fn is_empty(&self) -> bool;

    /// Returns an iterator over the key components (bit, byte, etc...)
    fn component_iter(&self) -> KeyIterator<T, Self>
    where
        Self: std::marker::Sized + std::ops::Index<usize, Output = T>;
}

impl<'a, U, K> Iterator for KeyIterator<'a, U, K>
where
    U: std::marker::Sized + Copy,
    K: Key<U> + std::ops::Index<usize, Output = U>,
{
    type Item = U;

    fn next(&mut self) -> Option<U> {
        if self.item_num < self.container.len() {
            let element: U = self.container[self.item_num];
            self.item_num += 1;
            self.last_element = element;
            Some(element)
        } else {
            None
        }
    }
}
