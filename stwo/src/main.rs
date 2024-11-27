use bench::main;
use bench_stwo::circuit::{StwoBlake2s, StwoPoseidon2};

main!(
    Blake2s => StwoBlake2s,
    Poseidon2 => StwoPoseidon2,
);
