#![no_main]
use libfuzzer_sys::fuzz_target;
use multiproof_rs::{ByteKey, NibbleKey, Node, Tree};

fuzz_target!(|keyvals: Vec<(Vec<u8>, Vec<u8>)>| {
    let mut root = Node::default();
    for (k, v) in keyvals.iter() {
        root.insert(&NibbleKey::from(ByteKey::from(k.to_vec())), v.to_vec());
    }
});
