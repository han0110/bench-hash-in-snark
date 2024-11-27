use bench::main;
use bench_plonky3::{
    circuit::{Blake3Circuit, KeccakCircuit, KoalaBearPoseidon2Circuit},
    config::{BabyBearKeccakMtConfig, KoalaBearKeccakMtConfig},
    Plonky3,
};

main!(
    Keccak => Plonky3<BabyBearKeccakMtConfig, KeccakCircuit>,
    Blake3 => Plonky3<BabyBearKeccakMtConfig, Blake3Circuit>,
    Poseidon2 => Plonky3<KoalaBearKeccakMtConfig, KoalaBearPoseidon2Circuit>,
);
