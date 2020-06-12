pub mod binary_key;
pub mod byte_key;
pub mod nibble_key;

pub use binary_key::*;
pub use byte_key::*;
pub use nibble_key::*;

/// An iterator that will walk the elements of the key. `U` is the unit
/// type of a key element (e.g. byte, bit, nibble) and `K` is the key type.
pub struct KeyIterator<'a, U, K>
where
    K: Key<U> + std::ops::Index<usize, Output = U>,
{
    /// Index of the element that the iterator is currently pointing at.
    item_num: usize,

    /// A reference to the object being iterated.
    container: &'a K,

    element: U,
}

impl<'a, U, K> std::fmt::Debug for KeyIterator<'a, U, K>
where
    K: Key<U> + std::ops::Index<usize, Output = U>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "iterator at element {}/{}",
            self.item_num,
            self.container.len()
        )
    }
}

impl<'a, U, K> Iterator for KeyIterator<'a, U, K>
where
    U: Copy,
    K: Key<U> + std::ops::Index<usize, Output = U>,
{
    type Item = U;

    fn next(&mut self) -> Option<U> {
        if self.item_num < self.container.len() {
            let element: U = self.container[self.item_num];
            self.item_num += 1;
            self.element = element;
            Some(element)
        } else {
            None
        }
    }
}

impl<'a, U, K> KeyIterator<'a, U, K>
where
    U: PartialEq + Copy,
    K: Key<U> + std::ops::Index<usize, Output = U>,
{
    fn peek(&self) -> Option<U> {
        if self.item_num >= self.container.len() {
            None
        } else {
            Some(self.container[self.item_num])
        }
    }

    /// Compares the two iterators and leave them at their first differing
    /// element. Returns an iterator over the common part.
    pub fn waypoint(&mut self, other: &mut Self) -> Self {
        let selfstart = self.item_num;
        loop {
            match (self.peek(), other.peek()) {
                // Keep advancing while iterators return the same
                // values.
                (Some(k), Some(l)) if k == l => {
                    self.next().unwrap();
                    other.next().unwrap();
                }
                _ => break,
            }
        }
        Self {
            container: self.container,
            item_num: selfstart,
            element: self.element,
        }
    }

    pub fn is_end(&self) -> bool {
        self.item_num >= self.container.len()
    }
}

/// Used as an abstraction of the key type, for handling in generic
/// tree/proof constructions.
pub trait Key<T> {
    /// Returns the number of units (i.e. bit, nibble or byte)
    fn len(&self) -> usize;

    /// Returns `true` if the key is zero unit long.
    fn is_empty(&self) -> bool;

    /// Returns an iterator over the key components (bit, byte, etc...)
    fn iter(&self) -> KeyIterator<T, Self>
    where
        T: Default,
        Self: std::marker::Sized + std::ops::Index<usize, Output = T>,
    {
        KeyIterator::<T, Self> {
            item_num: 0,
            container: &self,
            element: T::default(),
        }
    }
}
