use crate::HashInSnark;
use criterion::{measurement::Measurement, BatchSize, BenchmarkGroup, BenchmarkId, Throughput};
use rand::{rngs::StdRng, SeedableRng};
use rayon::current_num_threads;

pub fn bench<H: HashInSnark>(
    group: &mut BenchmarkGroup<impl Measurement>,
    name: impl AsRef<str>,
    num_permutations: impl IntoIterator<Item = usize>,
) {
    let mut rng = StdRng::from_os_rng();
    for num_permutations in num_permutations {
        let snark = H::new(num_permutations);
        let id = BenchmarkId::new(
            name.as_ref(),
            format!(
                "num_threads={}/num_permutations={}",
                current_num_threads(),
                snark.num_permutations()
            ),
        );
        group.throughput(Throughput::Elements(snark.num_permutations() as _));
        group.bench_function(id, |b| {
            b.iter_batched(
                || snark.generate_input(&mut rng),
                |input| snark.prove(input),
                BatchSize::LargeInput,
            );
        });
    }
}
