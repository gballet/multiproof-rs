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

impl<'a, U, K> std::fmt::Debug for KeyIterator<'a, U, K>
where
    U: std::marker::Sized + Copy + PartialEq + std::fmt::Debug + Default,
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
    fn rewind(&mut self) {
        assert!(self.item_num > 0);
        self.item_num -= 1;
    }

    /// Compares the two iterators and leave them at their first differing
    /// element.
    pub fn chop_common(&mut self, other: &mut Self) -> usize {
        loop {
            let (rewind, brk) = match (self.next(), other.next()) {
                // Both iterators reached the end, keys are
                // identical.
                (None, None) => (false, true),
                // One of the iterators has reached the end,
                // advance both and return.
                (_, None) | (None, _) => (true, true),
                // Both iterators are still pointing at a
                // value, check if these values are the same.
                // If they are, loop, otherwise quit.
                (Some(x), Some(y)) => (x != y, x != y),
            };

            if rewind {
                self.rewind();
                other.rewind();
            }

            if brk {
                break;
            }
        }
        self.course()
    }

    fn course(&self) -> usize {
        self.item_num
    }

    pub fn is_end(&self) -> bool {
        self.item_num >= self.container.len()
    }
}

/// Used as an abstraction of the key type, for handling in generic
/// tree/proof constructions.
pub trait Key<T>
where
{
    /// Returns the number of units (i.e. bit, nibble or byte)
    fn len(&self) -> usize;

    /// Returns `true` if the key is zero unit long.
    fn is_empty(&self) -> bool;

    /// Returns an iterator over the key components (bit, byte, etc...)
    fn iter(&self) -> KeyIterator<T, Self>
    where
        Self: std::marker::Sized + std::ops::Index<usize, Output = T>;
}
