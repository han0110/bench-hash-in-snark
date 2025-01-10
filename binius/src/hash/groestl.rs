// Copied and modified from https://github.com/IrreducibleOSS/binius/blob/main/examples/groestl_circuit.rs

use bench::{util::pcs_log_inv_rate, HashInSnark};
use binius_circuits::builder::ConstraintSystemBuilder;
use binius_core::{
    constraint_system::{self, error::Error, Proof},
    fiat_shamir::HasherChallenger,
    tower::AESTowerFamily,
};
use binius_field::{arch::OptimalUnderlier, AESTowerField128b, BinaryField8b};
use binius_hal::make_portable_backend;
use binius_hash::compress::Groestl256ByteCompression;
use binius_math::IsomorphicEvaluationDomainFactory;
use groestl_crypto::Groestl256;
use rand::RngCore;

type U = OptimalUnderlier;

pub struct BiniusGroestl {
    num_permutations: usize,
    log_inv_rate: usize,
    security_bits: usize,
}

impl HashInSnark for BiniusGroestl {
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
        binius_circuits::groestl::groestl_p_permutation(&mut builder, log_size).unwrap();
        let witness = builder.take_witness().unwrap();
        let constraint_system = builder.build().unwrap();
        constraint_system::prove::<
            U,
            AESTowerFamily,
            _,
            Groestl256,
            Groestl256ByteCompression,
            HasherChallenger<Groestl256>,
            _,
        >(
            &constraint_system,
            self.log_inv_rate,
            self.security_bits,
            witness,
            &IsomorphicEvaluationDomainFactory::<BinaryField8b>::default(),
            &make_portable_backend(),
        )
        .unwrap()
    }

    fn verify(&self, proof: &Self::Proof) -> Result<(), Self::Error> {
        let mut builder = ConstraintSystemBuilder::<U, AESTowerField128b>::new();
        let log_size = self.num_permutations.ilog2() as usize;
        binius_circuits::groestl::groestl_p_permutation(&mut builder, log_size).unwrap();
        let constraint_system = builder.build().unwrap();
        constraint_system::verify::<
            U,
            AESTowerFamily,
            Groestl256,
            Groestl256ByteCompression,
            HasherChallenger<Groestl256>,
        >(
            &constraint_system.no_base_constraints(),
            self.log_inv_rate,
            self.security_bits,
            vec![],
            proof.clone(),
        )
    }

    fn serialize_proof(proof: &Self::Proof) -> Vec<u8> {
        bincode::serialize(&(&proof.transcript, &proof.advice)).unwrap()
    }

    fn deserialize_proof(data: &[u8]) -> Self::Proof {
        let (transcript, advice) = bincode::deserialize(data).unwrap();
        Proof { transcript, advice }
    }
}
