use bench::main;
use bench_expander::{circuit::Gf2Keccak, circuit::M31Poseidon, Expander};

main!(
    Keccak => Expander<Gf2Keccak>,
    Poseidon => Expander<M31Poseidon>,
);
