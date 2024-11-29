// use bench::criterion::bench;
// use bench_binius::hash::{BiniusGroestl, BiniusKeccak};
// use criterion::{criterion_group, criterion_main, Criterion};

// fn num_perms(logs: impl IntoIterator<Item = usize>) -> impl Iterator<Item = usize> {
//     logs.into_iter().map(|log| 1 << log)
// }

// fn bench_keccak(c: &mut Criterion) {
//     let mut group = c.benchmark_group("keccak");

//     type H = BiniusKeccak;
//     bench::<H>(&mut group, "polyval_groestl_mt", num_perms(10..13));
// }

// criterion_group!(
//     name = benches;
//     config = Criterion::default().sample_size(10);
//     targets = bench_groestl, bench_keccak,
// );
// criterion_main!(benches);

fn main() {}
