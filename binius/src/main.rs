use bench::main;
use bench_binius::{
    hash::{BiniusGroestl, BiniusKeccak},
    setup_trace,
};

main!(
    setup_trace = setup_trace;
    hash = {
        Groestl => BiniusGroestl,
        Keccak => BiniusKeccak,
    };
);
