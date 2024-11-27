use crate::Plonky3Circuit;
use p3_commit::PolynomialSpace;
use p3_koala_bear::{GenericPoseidon2LinearLayersKoalaBear, KoalaBear};
use p3_matrix::dense::RowMajorMatrix;
use p3_poseidon2_air::{generate_vectorized_trace_rows, RoundConstants, VectorizedPoseidon2Air};
use p3_uni_stark::{Domain, StarkGenericConfig, Val};
use rand::{rngs::StdRng, Rng, RngCore, SeedableRng};

// Copied from https://github.com/Plonky3/Plonky3/blob/abdc2a0/poseidon2-air/examples/prove_poseidon2_koala_bear_keccak.rs#L26-L34.
const WIDTH: usize = 16;
const SBOX_DEGREE: u64 = 3;
const SBOX_REGISTERS: usize = 0;
const HALF_FULL_ROUNDS: usize = 4;
const PARTIAL_ROUNDS: usize = 20;
const VECTOR_LEN: usize = 1 << 3;

type KoalaBearPoseidon2Air = VectorizedPoseidon2Air<
    KoalaBear,
    GenericPoseidon2LinearLayersKoalaBear,
    WIDTH,
    SBOX_DEGREE,
    SBOX_REGISTERS,
    HALF_FULL_ROUNDS,
    PARTIAL_ROUNDS,
    VECTOR_LEN,
>;

pub struct KoalaBearPoseidon2Circuit {
    constants: RoundConstants<KoalaBear, WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>,
    air: KoalaBearPoseidon2Air,
    num_permutations: usize,
}

impl<SC: StarkGenericConfig> Plonky3Circuit<SC> for KoalaBearPoseidon2Circuit
where
    Domain<SC>: PolynomialSpace<Val = KoalaBear>,
{
    type Air = KoalaBearPoseidon2Air;
    type Input = Vec<[KoalaBear; WIDTH]>;

    fn new(num_permutations: usize) -> Self
    where
        Self: Sized,
    {
        let rng = StdRng::from_entropy();
        let constants = RoundConstants::from_rng(&mut rng.clone());
        let air = VectorizedPoseidon2Air::new(RoundConstants::from_rng(&mut rng.clone()));
        Self {
            constants,
            air,
            num_permutations,
        }
    }

    fn num_permutations(&self) -> usize {
        self.num_permutations
    }

    fn trace_size(&self) -> usize {
        self.num_permutations / VECTOR_LEN
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
        generate_vectorized_trace_rows::<
            KoalaBear,
            GenericPoseidon2LinearLayersKoalaBear,
            WIDTH,
            SBOX_DEGREE,
            SBOX_REGISTERS,
            HALF_FULL_ROUNDS,
            PARTIAL_ROUNDS,
            VECTOR_LEN,
        >(input, &self.constants)
    }
}
