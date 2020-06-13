#![no_main]
use libfuzzer_sys::fuzz_target;
use multiproof_rs::{NibbleKey, Node, Tree};

fuzz_target!(|keyvals: Vec<(NibbleKey, Vec<u8>)>| {
    let mut root = Node::default();
    for (k, v) in keyvals.iter() {
        root.insert(k, v.to_vec());
    }
});
