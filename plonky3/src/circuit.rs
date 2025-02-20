use p3_air::Air;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{
    ProverConstraintFolder, StarkGenericConfig, SymbolicAirBuilder, Val, VerifierConstraintFolder,
};
use rand::RngCore;

#[cfg(debug_assertions)]
use p3_uni_stark::DebugConstraintBuilder;

mod blake3;
mod keccak;
mod koala_bear_poseidon2;

pub use blake3::Blake3Circuit;
pub use keccak::KeccakCircuit;
pub use koala_bear_poseidon2::KoalaBearPoseidon2Circuit;

pub trait Plonky3Circuit<SC: StarkGenericConfig> {
    #[cfg(debug_assertions)]
    type Air: Air<SymbolicAirBuilder<Val<SC>>>
        + for<'a> Air<ProverConstraintFolder<'a, SC>>
        + for<'a> Air<DebugConstraintBuilder<'a, Val<SC>>>
        + for<'a> Air<VerifierConstraintFolder<'a, SC>>;
    #[cfg(not(debug_assertions))]
    type Air: Air<SymbolicAirBuilder<Val<SC>>>
        + for<'a> Air<ProverConstraintFolder<'a, SC>>
        + for<'a> Air<VerifierConstraintFolder<'a, SC>>;
    type Input;

    fn new(num_permutations: usize, log_blowup: usize) -> Self
    where
        Self: Sized;

    fn num_permutations(&self) -> usize;

    fn trace_height(&self) -> usize;

    fn air(&self) -> &Self::Air;

    fn generate_input(&self, rng: impl RngCore) -> Self::Input;

    fn generate_trace(&self, input: Self::Input) -> RowMajorMatrix<Val<SC>>;
}
