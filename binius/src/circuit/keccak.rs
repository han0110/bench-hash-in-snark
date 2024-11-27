use bench::HashInSnark;
use binius_circuits::{builder::ConstraintSystemBuilder, unconstrained::unconstrained};
use binius_core::{
    constraint_system::{self, Proof},
    fiat_shamir::HasherChallenger,
    tower::CanonicalTowerFamily,
};
use binius_field::{arch::OptimalUnderlier, BinaryField128b, BinaryField1b, BinaryField8b};
use binius_hal::make_portable_backend;
use binius_hash::{GroestlDigestCompression, GroestlHasher};
use binius_math::DefaultEvaluationDomainFactory;
use core::{
    array::{self},
    fmt::Debug,
};
use groestl_crypto::Groestl256;
use rand::RngCore;

type U = OptimalUnderlier;

const LOG_ROWS_PER_PERMUTATION: usize = 6;

pub struct BiniusKeccak {
    num_permutations: usize,
    log_inv_rate: usize,
    security_bits: usize,
}

impl HashInSnark for BiniusKeccak {
    type Input = ();
    type Proof = Proof;

    fn new(num_permutations: usize) -> Self
    where
        Self: Sized,
    {
        let num_permutations = num_permutations.next_power_of_two();
        Self {
            num_permutations,
            log_inv_rate: 1,
            security_bits: 100,
        }
    }

    fn num_permutations(&self) -> usize {
        self.num_permutations
    }

    fn generate_input(&self, _: impl RngCore) -> Self::Input {}

    fn prove(&self, _: Self::Input) -> Self::Proof {
        let allocator = bumpalo::Bump::new();
        let mut builder =
            ConstraintSystemBuilder::<U, BinaryField128b, BinaryField8b>::new_with_witness(
                &allocator,
            );
        let log_size = self.num_permutations.ilog2() as usize + LOG_ROWS_PER_PERMUTATION;
        let input = array::from_fn(|_| {
            unconstrained::<_, _, _, BinaryField1b>(&mut builder, "input", log_size).unwrap()
        });
        binius_circuits::keccakf::keccakf(&mut builder, input, log_size).unwrap();
        let witness = builder.take_witness().unwrap();
        let constraint_system = builder.build().unwrap();
        constraint_system::prove::<
            U,
            CanonicalTowerFamily,
            _,
            _,
            _,
            GroestlHasher<BinaryField128b>,
            GroestlDigestCompression<BinaryField8b>,
            HasherChallenger<Groestl256>,
            _,
        >(
            &constraint_system,
            self.log_inv_rate,
            self.security_bits,
            witness,
            &DefaultEvaluationDomainFactory::default(),
            &make_portable_backend(),
        )
        .unwrap()
    }

    fn verify(&self, proof: &Self::Proof) -> Result<(), impl Debug> {
        let mut builder = ConstraintSystemBuilder::<U, BinaryField128b, BinaryField8b>::new();
        let log_n_permutations = self.num_permutations.ilog2() as usize;
        let log_size = log_n_permutations + LOG_ROWS_PER_PERMUTATION;
        let input = array::from_fn(|_| {
            unconstrained::<_, _, _, BinaryField1b>(&mut builder, "input", log_size).unwrap()
        });
        binius_circuits::keccakf::keccakf(&mut builder, input, log_size).unwrap();
        let constraint_system = builder.build().unwrap();
        constraint_system::verify::<
            U,
            CanonicalTowerFamily,
            _,
            _,
            GroestlHasher<BinaryField128b>,
            GroestlDigestCompression<BinaryField8b>,
            HasherChallenger<Groestl256>,
        >(
            &constraint_system.no_base_constraints(),
            self.log_inv_rate,
            self.security_bits,
            &DefaultEvaluationDomainFactory::default(),
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
