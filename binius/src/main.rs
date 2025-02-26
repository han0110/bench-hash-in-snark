use bench::main;
use bench_binius::{
    hash::{BiniusKeccak, BiniusVision},
    setup_trace,
};

main!(
    setup_trace = setup_trace;
    hash = {
        Vision => BiniusVision,
        Keccak => BiniusKeccak,
    };
);
