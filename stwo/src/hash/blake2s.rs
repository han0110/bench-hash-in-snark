use bench::{util::pcs_log_inv_rate, HashInSnark};
use rand::RngCore;
use stwo_prover::{
    core::{
        fri::FriConfig,
        pcs::PcsConfig,
        prover::VerificationError,
        vcs::blake2_merkle::{Blake2sMerkleChannel, Blake2sMerkleHasher},
    },
    examples::blake::{prove_blake, verify_blake, BlakeProof},
};

pub struct StwoBlake2s {
    num_permutations: usize,
    config: PcsConfig,
}

impl HashInSnark for StwoBlake2s {
    type Input = ();
    type Proof = BlakeProof<Blake2sMerkleHasher>;
    type Error = VerificationError;

    fn new(num_permutations: usize) -> Self
    where
        Self: Sized,
    {
        let num_permutations = num_permutations.next_power_of_two();

        let log_blowup_factor = pcs_log_inv_rate();
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
        prove_blake::<Blake2sMerkleChannel>(self.num_permutations.ilog2(), self.config)
    }

    fn verify(&self, proof: &Self::Proof) -> Result<(), Self::Error> {
        verify_blake::<Blake2sMerkleChannel>(
            bincode::deserialize(&bincode::serialize(proof).unwrap()).unwrap(),
            self.config,
        )
    }

    fn serialize_proof(proof: &Self::Proof) -> Vec<u8> {
        bincode::serialize(proof).unwrap()
    }

    fn deserialize_proof(data: &[u8]) -> Self::Proof {
        bincode::deserialize(data).unwrap()
    }
}
