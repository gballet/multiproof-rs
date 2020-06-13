#![no_main]
use libfuzzer_sys::fuzz_target;
use multiproof_rs::keys::{ByteKey, NibbleKey};

fuzz_target!(|data: &[u8]| {
    let nkey = NibbleKey::from(ByteKey::from(data.to_vec()));
    let revert: Vec<u8> = ByteKey::from(NibbleKey::from(nkey)).into();
    assert_eq!(revert, data);
});
