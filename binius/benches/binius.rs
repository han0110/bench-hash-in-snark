use bench::{criterion::bench, util::po2};
use bench_binius::hash::{BiniusKeccak, BiniusVision};
use criterion::{criterion_group, criterion_main, Criterion};

fn bench_keccak(c: &mut Criterion) {
    let mut group = c.benchmark_group("keccak");

    type H = BiniusKeccak;
    bench::<H>(&mut group, "canonical_tower_groestl_mt", po2(10..13));
}

fn bench_vision(c: &mut Criterion) {
    let mut group = c.benchmark_group("bench_vision");

    type H = BiniusVision;
    bench::<H>(&mut group, "canonical_tower_groestl_mt", po2(10..13));
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_keccak, bench_vision,
);
criterion_main!(benches);
