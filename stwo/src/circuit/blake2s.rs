use bench::HashInSnark;
use core::fmt::Debug;
use rand::RngCore;
use stwo_prover::{
    core::{
        fri::FriConfig,
        pcs::PcsConfig,
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

    fn new(num_permutations: usize) -> Self
    where
        Self: Sized,
    {
        let num_permutations = num_permutations.next_power_of_two();

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
        prove_blake::<Blake2sMerkleChannel>(self.num_permutations.ilog2(), self.config)
    }

    fn verify(&self, proof: &Self::Proof) -> Result<(), impl Debug> {
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
