use core::fmt::Debug;
use criterion::{measurement::Measurement, BatchSize, BenchmarkGroup, BenchmarkId, Throughput};
use rand::{rngs::StdRng, RngCore, SeedableRng};

pub trait HashInSnark {
    type Input;
    type Proof;

    fn new(num_permutations: usize) -> Self
    where
        Self: Sized;

    fn num_permutations(&self) -> usize;

    fn generate_input(&self, rng: impl RngCore) -> Self::Input;

    fn prove(&self, input: Self::Input) -> Self::Proof;

    fn verify(&self, proof: &Self::Proof) -> Result<(), impl Debug>;

    fn serialize_proof(proof: &Self::Proof) -> Vec<u8>;

    fn deserialize_proof(data: &[u8]) -> Self::Proof;

    fn proof_size(&self) -> usize {
        let mut rng = StdRng::from_entropy();
        let input = self.generate_input(&mut rng);
        let proof = self.prove(input);
        self.verify(&proof).unwrap();
        let bytes = Self::serialize_proof(&proof);
        let proof = Self::deserialize_proof(&bytes);
        self.verify(&proof).unwrap();
        bytes.len()
    }
}

pub fn bench<H: HashInSnark>(
    group: &mut BenchmarkGroup<impl Measurement>,
    name: impl AsRef<str>,
    num_permutations: impl IntoIterator<Item = usize>,
) {
    let mut rng = StdRng::from_entropy();
    for num_permutations in num_permutations {
        let prover = H::new(num_permutations);
        let id = BenchmarkId::new(name.as_ref(), prover.num_permutations());
        group.throughput(Throughput::Elements(prover.num_permutations() as _));
        group.bench_function(id, |b| {
            b.iter_batched(
                || prover.generate_input(&mut rng),
                |input| prover.prove(input),
                BatchSize::LargeInput,
            );
        });
    }
}

pub fn assert_proof_size<H: HashInSnark>(expected: impl IntoIterator<Item = (usize, usize)>) {
    for (num_permutations, expected_proof_size) in expected {
        let prover = H::new(num_permutations);
        let proof_size = prover.proof_size();
        assert_eq!(
            proof_size, expected_proof_size,
            "Expected {expected_proof_size}, got {proof_size}"
        );
    }
}
