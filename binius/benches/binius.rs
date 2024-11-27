use bench::criterion::bench;
use bench_binius::circuit::{BiniusGroestl, BiniusKeccak};
use criterion::{criterion_group, criterion_main, Criterion};

fn num_perms(logs: impl IntoIterator<Item = usize>) -> impl Iterator<Item = usize> {
    logs.into_iter().map(|log| 1 << log)
}

fn bench_groestl(c: &mut Criterion) {
    let mut group = c.benchmark_group("groestl");

    type H = BiniusGroestl;
    bench::<H>(&mut group, "aes_tower_groestl_mt", num_perms(10..13));
}

fn bench_keccak(c: &mut Criterion) {
    let mut group = c.benchmark_group("keccak");

    type H = BiniusKeccak;
    bench::<H>(&mut group, "canonical_tower_groestl_mt", num_perms(10..13));
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_groestl, bench_keccak,
);
criterion_main!(benches);
