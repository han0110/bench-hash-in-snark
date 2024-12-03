use bench::main;
use bench_expander::{circuit::M31Keccak, circuit::M31Poseidon, Expander};

main!(
    Keccak => Expander<M31Keccak>,
    Poseidon => Expander<M31Poseidon>,
);
