use bench::main;
use bench_binius::circuit::{BiniusGroestl, BiniusKeccak};

main!(
    Groestl => BiniusGroestl,
    Keccak => BiniusKeccak,
);
