use bench::{criterion::bench, util::po2};
use bench_hashcaster::hash::HashcasterKeccak;
use criterion::{criterion_group, criterion_main, Criterion};

fn bench_keccak(c: &mut Criterion) {
    let mut group = c.benchmark_group("keccak");

    type H = HashcasterKeccak;
    bench::<H>(&mut group, "aes_tower_groestl_mt", po2(10..13));
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_keccak,
);
criterion_main!(benches);
