use bench::main;
use bench_binius::hash::{BiniusGroestl, BiniusKeccak};

main!(
    Groestl => BiniusGroestl,
    Keccak => BiniusKeccak,
);
