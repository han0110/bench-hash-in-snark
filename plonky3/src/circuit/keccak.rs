use crate::Plonky3Circuit;
use p3_field::PrimeField64;
use p3_keccak_air::{generate_trace_rows, KeccakAir};
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{StarkGenericConfig, Val};
use rand::{Rng, RngCore};

pub struct KeccakCircuit {
    air: KeccakAir,
    num_permutations: usize,
    log_blowup: usize,
}

impl<SC: StarkGenericConfig> Plonky3Circuit<SC> for KeccakCircuit
where
    Val<SC>: PrimeField64,
{
    type Air = KeccakAir;
    type Input = Vec<[u64; 25]>;

    fn new(num_permutations: usize, log_blowup: usize) -> Self
    where
        Self: Sized,
    {
        Self {
            air: KeccakAir {},
            num_permutations,
            log_blowup,
        }
    }

    fn num_permutations(&self) -> usize {
        Plonky3Circuit::<SC>::trace_height(self) / 24
    }

    fn trace_height(&self) -> usize {
        (24 * self.num_permutations).next_power_of_two()
    }

    fn air(&self) -> &Self::Air {
        &self.air
    }

    fn generate_input(&self, mut rng: impl RngCore) -> Self::Input {
        (0..Plonky3Circuit::<SC>::num_permutations(self))
            .map(|_| rng.gen())
            .collect()
    }

    fn generate_trace(&self, input: Self::Input) -> RowMajorMatrix<Val<SC>> {
        generate_trace_rows(input, self.log_blowup)
    }
}
