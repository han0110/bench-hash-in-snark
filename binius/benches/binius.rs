use bench::{criterion::bench, util::po2};
use bench_binius::hash::{BiniusGroestl, BiniusKeccak};
use criterion::{criterion_group, criterion_main, Criterion};

fn bench_groestl(c: &mut Criterion) {
    let mut group = c.benchmark_group("bench_groestl");

    type H = BiniusGroestl;
    bench::<H>(&mut group, "canonical_tower_groestl_mt", po2(10..13));
}

fn bench_keccak(c: &mut Criterion) {
    let mut group = c.benchmark_group("keccak");

    type H = BiniusKeccak;
    bench::<H>(&mut group, "canonical_tower_groestl_mt", po2(10..13));
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_groestl, bench_keccak,
);
criterion_main!(benches);
