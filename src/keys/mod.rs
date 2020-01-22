pub mod byte_key;
pub mod nibble_key;

pub use byte_key::*;
pub use nibble_key::*;

/// An iterator that will walk the elements of the key. `U` is the unit
/// type of a key element (e.g. byte, bit, nibble) and `K` is the key type.
pub struct KeyIterator<'a, U, K>
where
    U: Copy + PartialEq + std::fmt::Debug + Default,
    K: Key<U> + std::ops::Index<usize, Output = U>,
{
    /// Index of the element that the iterator is currently pointing at.
    item_num: usize,

    /// A reference to the object being iterated.
    container: &'a K,

    element: U,
}

/// Used as an abstraction of the key type, for handling in generic
/// tree/proof constructions.
pub trait Key<T>
where
    T: std::marker::Sized + Copy + PartialEq + std::fmt::Debug + Default,
{
    /// Returns the number of units (i.e. bit, nibble or byte)
    fn len(&self) -> usize;

    /// Returns `true` if the key is zero unit long.
    fn is_empty(&self) -> bool;

    /// Returns the common length between `self` and `other`.
    fn common_length(&self, other: &Self) -> usize
    where
        Self: std::ops::Index<usize, Output = T> + std::marker::Sized + std::fmt::Debug,
    {
        let mut i = 0;
        for v in self.component_iter() {
            if other.len() <= i || self.len() <= i || other[i] != v {
                return i;
            }
            i += 1;
        }

        i
    }

    /// Returns an iterator over the key components (bit, byte, etc...)
    fn component_iter(&self) -> KeyIterator<T, Self>
    where
        Self: std::marker::Sized + std::ops::Index<usize, Output = T>;
}

impl<'a, U, K> Iterator for KeyIterator<'a, U, K>
where
    U: std::marker::Sized + Copy + PartialEq + std::fmt::Debug + Default,
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
    U: std::marker::Sized + Copy + PartialEq + std::fmt::Debug + Default,
    K: Key<U> + std::ops::Index<usize, Output = U>,
{
    pub fn chop_common(&mut self, k: &K) -> usize {
        for (i, other) in k.component_iter().enumerate() {
            match self.next() {
                None => return i,
                Some(step2) => {
                    if step2 != other {
                        return i;
                    }
                }
            }
        }
        k.len()
    }

    pub fn is_end(&self) -> bool {
        self.item_num >= self.container.len()
    }
}
