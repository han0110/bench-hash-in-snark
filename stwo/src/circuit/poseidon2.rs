use bench::HashInSnark;
use core::fmt::Debug;
use rand::RngCore;
use stwo_prover::{
    constraint_framework::TraceLocationAllocator,
    core::{
        air::Component,
        channel::Blake2sChannel,
        fields::qm31::QM31,
        fri::FriConfig,
        pcs::{CommitmentSchemeVerifier, PcsConfig, TreeVec},
        prover::{verify, StarkProof},
        vcs::blake2_merkle::{Blake2sMerkleChannel, Blake2sMerkleHasher},
        ColumnVec,
    },
    examples::poseidon::{prove_poseidon, PoseidonComponent, PoseidonElements, PoseidonEval},
};

const N_LOG_INSTANCES_PER_ROW: usize = 3;

pub struct StwoPoseidon2 {
    num_permutations: usize,
    config: PcsConfig,
}

impl HashInSnark for StwoPoseidon2 {
    type Input = ();
    type Proof = (
        QM31,
        TreeVec<ColumnVec<u32>>,
        StarkProof<Blake2sMerkleHasher>,
    );

    fn new(num_permutations: usize) -> Self
    where
        Self: Sized,
    {
        let num_permutations = (num_permutations >> N_LOG_INSTANCES_PER_ROW).next_power_of_two()
            << N_LOG_INSTANCES_PER_ROW;

        let config = PcsConfig {
            pow_bits: 0,
            fri_config: FriConfig::new(0, 1, 256),
        };

        Self {
            num_permutations,
            config,
        }
    }

    fn num_permutations(&self) -> usize {
        self.num_permutations
    }

    fn generate_input(&self, _: impl RngCore) -> Self::Input {}

    fn prove(&self, _: Self::Input) -> Self::Proof {
        // TODO: Move preprocessing out of prove.
        let (component, proof) = prove_poseidon(self.num_permutations.ilog2(), self.config);
        (
            component.total_sum,
            component.trace_log_degree_bounds(),
            proof,
        )
    }

    fn verify(&self, (total_sum, sizes, proof): &Self::Proof) -> Result<(), impl Debug> {
        let mut channel = Blake2sChannel::default();
        let mut commitment_scheme =
            CommitmentSchemeVerifier::<Blake2sMerkleChannel>::new(self.config);

        commitment_scheme.commit(proof.commitments[0], &sizes[0], &mut channel);

        commitment_scheme.commit(proof.commitments[1], &sizes[1], &mut channel);

        let lookup_elements = PoseidonElements::draw(&mut channel);

        commitment_scheme.commit(proof.commitments[2], &sizes[2], &mut channel);

        let component = PoseidonComponent::new(
            &mut TraceLocationAllocator::default(),
            PoseidonEval {
                log_n_rows: (self.num_permutations >> N_LOG_INSTANCES_PER_ROW).ilog2(),
                lookup_elements,
                total_sum: *total_sum,
            },
            (*total_sum, None),
        );

        let proof = bincode::deserialize(&bincode::serialize(proof).unwrap()).unwrap();

        verify(&[&component], &mut channel, &mut commitment_scheme, proof)
    }

    fn serialize_proof(proof: &Self::Proof) -> Vec<u8> {
        bincode::serialize(proof).unwrap()
    }

    fn deserialize_proof(data: &[u8]) -> Self::Proof {
        bincode::deserialize(data).unwrap()
    }
}
