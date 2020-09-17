extern crate multiproof_rs;
extern crate rand;

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use multiproof_rs::BinaryExtTree;
use multiproof_rs::{BinaryKey, Tree};
use rand::{thread_rng, Rng};
use sha3::Sha3_256;

#[inline]
fn many_keys_m4(n: u64) {
    let mut root = BinaryExtTree::default();
    for _ in 0..n {
        let mut key_bytes = vec![0u8; 32];
        thread_rng().fill(&mut key_bytes[..]);
        let key = BinaryKey::from(key_bytes);
        root.insert(&key, vec![5u8; 32]).unwrap();
    }

    root.hash_m4::<Sha3_256>();
}

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("m4 1000", |b| b.iter(|| many_keys_m4(black_box(1000))));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
