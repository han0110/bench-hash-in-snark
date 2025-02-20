use crate::Plonky3Circuit;
use p3_blake3_air::{generate_trace_rows, Blake3Air};
use p3_field::PrimeField64;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{StarkGenericConfig, Val};
use rand::{Rng, RngCore};

pub struct Blake3Circuit {
    air: Blake3Air,
    num_permutations: usize,
    log_blowup: usize,
}

impl<SC: StarkGenericConfig> Plonky3Circuit<SC> for Blake3Circuit
where
    Val<SC>: PrimeField64,
{
    type Air = Blake3Air;
    type Input = Vec<[u32; 24]>;

    fn new(num_permutations: usize, log_blowup: usize) -> Self
    where
        Self: Sized,
    {
        Self {
            air: Blake3Air {},
            num_permutations,
            log_blowup,
        }
    }

    fn num_permutations(&self) -> usize {
        self.num_permutations
    }

    fn trace_height(&self) -> usize {
        self.num_permutations.next_power_of_two()
    }

    fn air(&self) -> &Self::Air {
        &self.air
    }

    fn generate_input(&self, mut rng: impl RngCore) -> Self::Input {
        (0..self.num_permutations).map(|_| rng.gen()).collect()
    }

    fn generate_trace(&self, input: Self::Input) -> RowMajorMatrix<Val<SC>> {
        generate_trace_rows(input, self.log_blowup)
    }
}
