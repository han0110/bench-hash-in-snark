use bench::{util::pcs_log_inv_rate, HashInSnark};
use rand::RngCore;
use stwo::core::{
    air::Component,
    channel::Blake2sChannel,
    fields::qm31::QM31,
    fri::FriConfig,
    pcs::{CommitmentSchemeVerifier, PcsConfig, TreeVec},
    proof::StarkProof,
    vcs::blake2_merkle::{Blake2sMerkleChannel, Blake2sMerkleHasher},
    verifier::{verify, VerificationError},
    ColumnVec,
};
use stwo_constraint_framework::TraceLocationAllocator;
use stwo_examples::poseidon::{prove_poseidon, PoseidonComponent, PoseidonElements, PoseidonEval};

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
    type Error = VerificationError;

    fn new(num_permutations: usize) -> Self
    where
        Self: Sized,
    {
        let num_permutations = (num_permutations >> N_LOG_INSTANCES_PER_ROW).next_power_of_two()
            << N_LOG_INSTANCES_PER_ROW;

        let log_blowup_factor = pcs_log_inv_rate() as _;
        let num_queries = usize::div_ceil(256, log_blowup_factor);
        let config = PcsConfig {
            pow_bits: 0,
            fri_config: FriConfig::new(0, log_blowup_factor as _, num_queries),
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
            component.claimed_sum,
            component.trace_log_degree_bounds(),
            proof,
        )
    }

    fn verify(&self, (claimed_sum, sizes, proof): &Self::Proof) -> Result<(), Self::Error> {
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
                claimed_sum: *claimed_sum,
            },
            *claimed_sum,
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
