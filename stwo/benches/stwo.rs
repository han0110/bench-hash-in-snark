use bench::criterion::bench;
use bench_stwo::hash::{StwoBlake2s, StwoPoseidon2};
use criterion::{criterion_group, criterion_main, Criterion};

fn num_perms(logs: impl IntoIterator<Item = usize>) -> impl Iterator<Item = usize> {
    logs.into_iter().map(|log| 1 << log)
}

fn bench_blake2s(c: &mut Criterion) {
    let mut group = c.benchmark_group("blake2s");

    type H = StwoBlake2s;
    bench::<H>(&mut group, "m31_blake2s_mt", num_perms(15..18));
}

fn bench_m31_poseidon2(c: &mut Criterion) {
    let mut group = c.benchmark_group("m31_poseidon2");

    type H = StwoPoseidon2;
    bench::<H>(&mut group, "m31_blake2s_mt", num_perms(15..18));
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_blake2s, bench_m31_poseidon2,
);
criterion_main!(benches);
