use bench::{criterion::bench, util::po2};
use bench_plonky3::{
    circuit::{Blake3Circuit, KeccakCircuit, KoalaBearPoseidon2Circuit},
    config::{BabyBearKeccakMtConfig, KoalaBearKeccakMtConfig},
    Plonky3,
};
use criterion::{criterion_group, criterion_main, Criterion};

fn bench_keccak(c: &mut Criterion) {
    let mut group = c.benchmark_group("keccak");

    type H = Plonky3<BabyBearKeccakMtConfig, KeccakCircuit>;
    bench::<H>(&mut group, "baby_bear_keccak_mt", po2(10..13));
}

fn bench_blake3(c: &mut Criterion) {
    let mut group = c.benchmark_group("blake3");

    type H = Plonky3<BabyBearKeccakMtConfig, Blake3Circuit>;
    bench::<H>(&mut group, "baby_bear_keccak_mt", po2(10..13));
}

fn bench_koala_bear_poseidon2(c: &mut Criterion) {
    let mut group = c.benchmark_group("koala_bear_poseidon2");

    type H = Plonky3<KoalaBearKeccakMtConfig, KoalaBearPoseidon2Circuit>;
    bench::<H>(&mut group, "koala_bear_keccak_mt", po2(15..18));
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_keccak, bench_blake3, bench_koala_bear_poseidon2,
);
criterion_main!(benches);
