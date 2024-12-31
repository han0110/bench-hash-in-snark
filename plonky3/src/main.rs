use bench::main;
use bench_plonky3::{
    circuit::{Blake3Circuit, KeccakCircuit, KoalaBearPoseidon2Circuit},
    config::{BabyBearKeccakMtConfig, KoalaBearKeccakMtConfig},
    setup_trace, Plonky3,
};

main!(
    setup_trace = setup_trace;
    hash = {
        Keccak => Plonky3<BabyBearKeccakMtConfig, KeccakCircuit>,
        Blake3 => Plonky3<BabyBearKeccakMtConfig, Blake3Circuit>,
        Poseidon2 => Plonky3<KoalaBearKeccakMtConfig, KoalaBearPoseidon2Circuit>,
    };
);
