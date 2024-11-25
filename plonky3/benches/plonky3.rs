use bench::bench;
use bench_plonky3::{
    circuit::{Blake3Circuit, KeccakCircuit, KoalaBearPoseidon2Circuit},
    config::{BabyBearKeccakMtConfig, KoalaBearKeccakMtConfig},
    Plonky3,
};
use criterion::{criterion_group, criterion_main, Criterion};

fn num_perms(logs: impl IntoIterator<Item = usize>) -> impl Iterator<Item = usize> {
    logs.into_iter().map(|log| 1 << log)
}

fn bench_keccak(c: &mut Criterion) {
    let mut group = c.benchmark_group("keccak");

    type H = Plonky3<BabyBearKeccakMtConfig, KeccakCircuit>;
    bench::<H>(&mut group, "baby_bear_keccak_mt", num_perms(10..13));
}

fn bench_blake3(c: &mut Criterion) {
    let mut group = c.benchmark_group("blake3");

    type H = Plonky3<BabyBearKeccakMtConfig, Blake3Circuit>;
    bench::<H>(&mut group, "baby_bear_keccak_mt", num_perms(10..13));
}

fn bench_koala_bear_poseidon2(c: &mut Criterion) {
    let mut group = c.benchmark_group("koala_bear_poseidon2");

    type H = Plonky3<KoalaBearKeccakMtConfig, KoalaBearPoseidon2Circuit>;
    bench::<H>(&mut group, "koala_bear_keccak_mt", num_perms(15..18));
}

criterion_group!(
    benches,
    bench_keccak,
    bench_blake3,
    bench_koala_bear_poseidon2,
);
criterion_main!(benches);
