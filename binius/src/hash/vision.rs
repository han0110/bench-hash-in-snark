// Copied and modified from https://github.com/IrreducibleOSS/binius/blob/main/examples/vision32b_circuit.rs

use bench::{util::pcs_log_inv_rate, HashInSnark};
use binius_circuits::{builder::ConstraintSystemBuilder, unconstrained::unconstrained};
use binius_core::{
    constraint_system::{self, error::Error, Proof},
    fiat_shamir::HasherChallenger,
    tower::CanonicalTowerFamily,
};
use binius_field::{arch::OptimalUnderlier, BinaryField32b, BinaryField8b};
use binius_hal::make_portable_backend;
use binius_hash::compress::Groestl256ByteCompression;
use binius_math::IsomorphicEvaluationDomainFactory;
use core::array::from_fn;
use groestl_crypto::Groestl256;
use rand::RngCore;

type U = OptimalUnderlier;

pub struct BiniusVision {
    num_permutations: usize,
    log_inv_rate: usize,
    security_bits: usize,
}

impl HashInSnark for BiniusVision {
    type Input = ();
    type Proof = Proof;
    type Error = Error;

    fn new(num_permutations: usize) -> Self
    where
        Self: Sized,
    {
        let num_permutations = num_permutations.next_power_of_two();
        Self {
            num_permutations,
            log_inv_rate: pcs_log_inv_rate(),
            security_bits: 100,
        }
    }

    fn num_permutations(&self) -> usize {
        self.num_permutations
    }

    fn generate_input(&self, _: impl RngCore) -> Self::Input {}

    fn prove(&self, _: Self::Input) -> Self::Proof {
        let allocator = bumpalo::Bump::new();
        let mut builder = ConstraintSystemBuilder::new_with_witness(&allocator);
        let log_size = self.num_permutations.ilog2() as usize;
        vision_permutation(&mut builder, log_size);
        let witness = builder.take_witness().unwrap();
        let constraint_system = builder.build().unwrap();
        constraint_system::prove::<
            U,
            CanonicalTowerFamily,
            _,
            Groestl256,
            Groestl256ByteCompression,
            HasherChallenger<Groestl256>,
            _,
        >(
            &constraint_system,
            self.log_inv_rate,
            self.security_bits,
            &[],
            witness,
            &IsomorphicEvaluationDomainFactory::<BinaryField8b>::default(),
            &make_portable_backend(),
        )
        .unwrap()
    }

    fn verify(&self, proof: &Self::Proof) -> Result<(), Self::Error> {
        let mut builder = ConstraintSystemBuilder::new();
        let log_size = self.num_permutations.ilog2() as usize;
        vision_permutation(&mut builder, log_size);
        let constraint_system = builder.build().unwrap();
        constraint_system::verify::<
            U,
            CanonicalTowerFamily,
            Groestl256,
            Groestl256ByteCompression,
            HasherChallenger<Groestl256>,
        >(
            &constraint_system.no_base_constraints(),
            self.log_inv_rate,
            self.security_bits,
            &[],
            proof.clone(),
        )
    }

    fn serialize_proof(proof: &Self::Proof) -> Vec<u8> {
        bincode::serialize(&proof.transcript).unwrap()
    }

    fn deserialize_proof(data: &[u8]) -> Self::Proof {
        let transcript = bincode::deserialize(data).unwrap();
        Proof { transcript }
    }
}

fn vision_permutation(builder: &mut ConstraintSystemBuilder, log_size: usize) {
    let state_in = from_fn(|i| {
        unconstrained::<BinaryField32b>(builder, format!("p_in_{i}"), log_size).unwrap()
    });
    binius_circuits::vision::vision_permutation(builder, log_size, state_in).unwrap();
}
