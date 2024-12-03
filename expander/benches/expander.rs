use bench::{criterion::bench, util::po2};
use bench_expander::{
    circuit::{Gf2Keccak, M31Poseidon},
    Expander,
};
use criterion::{criterion_group, criterion_main, Criterion};

fn bench_keccak(c: &mut Criterion) {
    let mut group = c.benchmark_group("keccak");

    type H = Expander<Gf2Keccak>;
    bench::<H>(&mut group, "raw", po2(10..13));
}

fn bench_poseidon(c: &mut Criterion) {
    let mut group = c.benchmark_group("m31_poseidon");

    type H = Expander<M31Poseidon>;
    bench::<H>(&mut group, "raw", po2(15..18));
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_keccak, bench_poseidon,
);
criterion_main!(benches);
