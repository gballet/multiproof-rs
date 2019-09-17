# multiproof.rs
A rust implementation of Alexey Akhunov's [multiproof algorithm](https://github.com/ledgerwatch/turbo-geth/blob/master/docs/programmers_guide/guide.md).

At the time of creation, multiproof is still a work in progress and this code makes a series of assumptions that are to be discussed and updated in order to achieve complete compatibility. Here is a non-exhaustive list of assumptions:

  * The initial `LEAF`, `BRANCH`, `ADD`, `HASHER` and `EXTENSION` model is still in use,
  * `HASHER` always has a parameter of `0`. This is clearly and issue with this code as several distrinct trees end up having the same hash.

## Installation

**This code uses features from rust nightly.** Install it by typing:

```
rustup install nightly
```

You can then run the tests with:

```
cargo +nightly test
```

## Usage

### Creating trees

Start with an empty tree:

```rust
let mut tree_root = Node::FullNode(vec![Node::EmptySlot; 16]);
```

This creates a mutable tree root, which is a node with 16 (currently empty) children.

You can use `insert_leaf` to add a `(key,value)` pair to that tree. This example adds `(0x11111..111, 0x22222..222)` to the tree that was created above:

```rust
let new_root = insert_leaf(&mut tree_root, &NibbleKey::from(vec![1u8; 32]), vec![2u8; 32]).unwrap();
```

Note that the key format is `&NibbleKey`, and no longer `Vec<u8>`.

### Calculating hashes

The `hash` function will walk the tree and calculate the hash representation.

```rust
let hash = new_root.hash();
```

### Creating the proof

Call `make_multiproof` with the root of the tree and the list of keys to be changed. It returns a `Multiproof` object, which can be sent to the verifier over the network; The example below will create a proof for leaf `0x11...11`:

```rust
let proof = make_multiproof(&new_root, vec![NibbleKey::from(vec![1u8; 32])]).unwrap();
```

### Verifying proof

Call the `rebuild` function on the output of `make_multiproof`:

```rust
let root = rebuild(&proof).unwrap();
```

### Examples

See unit tests.
