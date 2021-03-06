[![CircleCI](https://circleci.com/gh/gballet/multiproof-rs.svg?style=svg)](https://circleci.com/gh/gballet/multiproof-rs)
[![Crates.io](https://img.shields.io/crates/v/multiproof-rs.svg)](https://crates.io/crates/multiproof-rs)

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
let mut tree_root = Node::default();
```

This creates a mutable tree root, which is a node with 16 (currently empty) children.

You can use `insert_leaf` to add a `(key,value)` pair to that tree. This example adds `(0x11111..111, 0x22222..222)` to the tree that was created above:

```rust
new_root.insert(&NibbleKey::from(vec![1u8; 32]), vec![2u8; 32]).unwrap();
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
let root = proof.rebuild().unwrap();
```

### Examples

See unit tests.

## Changelog

### 0.1.9

  * Add the `Hashable` trait and use methods M2 and M3 (see https://ethresear.ch/t/binary-trie-format/7621/6)
  * Implement `From<Vec<bool>>` and `Into<Vec<bool>>`
  * Binary keys use `bool` as a key type
  * Use extensions for binary tries
  * Bugfix: check that keys have the same length in insert.
  * Fuzzing: introduce tests for nibblekey and Node::inset.

### 0.1.8

  * `keys` method on `Node` in order to get the list of keys present in the tree.
  * Fixes #61 - if several keys have the same prefix leading to a `Leaf` object,
    don't return an error; instead, add that key to the proof, as a proof that
    all the extra keys are missing.

### 0.1.7

  * Accept the insertion of empty keys

### 0.1.6

  * Fix a bug in even-length hex prefix calculations

### 0.1.5

  * Export ByteKey to Vec<u8>
  * Implement `fmt::Display` for `NibbleKey`

### 0.1.4

  * Support for binary trees
  * CBOR encoding of proofs

### 0.1.3

  * Allow `insert`s to overwrite existing leaves
  * Make `has_key` part of the tree trait
  * Bugfix in `NibbleKey` index calculation
  * README updates

### 0.1.2

  * Export all submodules

### 0.1.1

  * Export `node::*` from crate
