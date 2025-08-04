// Copied and modified from https://github.com/IrreducibleOSS/binius/blob/main/examples/keccak.rs.

use anyhow::{Error, Result};
use bench::{util::pcs_log_inv_rate, HashInSnark};
use binius_compute::{cpu::alloc::CpuComputeAllocator, ComputeHolder};
use binius_core::{
    constraint_system::{self, Proof},
    fiat_shamir::HasherChallenger,
};
use binius_fast_compute::layer::FastCpuLayerHolder;
use binius_field::{
    arch::OptimalUnderlier, as_packed_field::PackedType,
    linear_transformation::PackedTransformationFactory, tower::CanonicalTowerFamily,
    PackedExtension, PackedFieldIndexable, PackedSubfield,
};
use binius_hal::make_portable_backend;
use binius_hash::groestl::{Groestl256, Groestl256ByteCompression, Groestl256Parallel};
use binius_m3::{
    builder::{
        ConstraintSystem, TableFiller, TableId, TableWitnessSegment, WitnessIndex, B1, B128, B64,
        B8,
    },
    gadgets::hash::keccak::{stacked::Keccakf, StateMatrix},
};
use binius_utils::checked_arithmetics::log2_ceil_usize;
use core::iter::repeat_with;
use rand::RngCore;

pub struct PermutationTable {
    table_id: TableId,
    keccakf: Keccakf,
}

impl PermutationTable {
    pub fn new(cs: &mut ConstraintSystem) -> Self {
        let mut table = cs.add_table("Keccak permutation");

        let keccakf = Keccakf::new(&mut table);

        Self {
            table_id: table.id(),
            keccakf,
        }
    }
}

impl<P> TableFiller<P> for PermutationTable
where
    P: PackedFieldIndexable<Scalar = B128>
        + PackedExtension<B1>
        + PackedExtension<B8>
        + PackedExtension<B64>,
    PackedSubfield<P, B8>: PackedTransformationFactory<PackedSubfield<P, B8>>,
{
    type Event = StateMatrix<u64>;

    fn id(&self) -> TableId {
        self.table_id
    }

    fn fill(&self, rows: &[Self::Event], witness: &mut TableWitnessSegment<P>) -> Result<()> {
        self.keccakf.populate_state_in(witness, rows)?;
        self.keccakf.populate(witness)?;
        Ok(())
    }
}

pub struct BiniusKeccak {
    num_permutations: usize,
    log_inv_rate: usize,
    security_bits: usize,
}

impl HashInSnark for BiniusKeccak {
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
        let mut allocator = CpuComputeAllocator::new(
            1 << (11 + log2_ceil_usize(self.num_permutations)
                - PackedType::<OptimalUnderlier, B128>::LOG_WIDTH),
        );
        let allocator = allocator.into_bump_allocator();
        let mut cs = ConstraintSystem::new();
        let table = PermutationTable::new(&mut cs);

        let boundaries = vec![];
        let table_sizes = vec![self.num_permutations];

        let mut rng = rand::rng();
        let events = repeat_with(|| StateMatrix::from_fn(|_| rng.next_u64()))
            .take(self.num_permutations)
            .collect::<Vec<_>>();

        let mut witness = WitnessIndex::<PackedType<OptimalUnderlier, B128>>::new(&cs, &allocator);
        witness.fill_table_parallel(&table, &events).unwrap();

        let ccs = cs.compile().unwrap();
        let cs_digest = ccs.digest::<Groestl256>();
        let witness = witness.into_multilinear_extension_index();

        let mut compute_holder =
            FastCpuLayerHolder::<CanonicalTowerFamily, PackedType<OptimalUnderlier, B128>>::new(
                1 << 20,
                1 << (13 + log2_ceil_usize(self.num_permutations)),
            );

        let proof = constraint_system::prove::<
            _,
            OptimalUnderlier,
            CanonicalTowerFamily,
            Groestl256Parallel,
            Groestl256ByteCompression,
            HasherChallenger<Groestl256>,
            _,
            _,
            _,
        >(
            &mut compute_holder.to_data(),
            &ccs,
            self.log_inv_rate,
            self.security_bits,
            &cs_digest,
            &boundaries,
            &table_sizes,
            witness,
            &make_portable_backend(),
        )
        .unwrap();

        proof
    }

    fn verify(&self, proof: &Self::Proof) -> Result<(), Self::Error> {
        let cs = ConstraintSystem::new();
        let boundaries = vec![];
        let ccs = cs.compile().unwrap();
        let cs_digest = ccs.digest::<Groestl256>();

        binius_core::constraint_system::verify::<
            OptimalUnderlier,
            CanonicalTowerFamily,
            Groestl256,
            Groestl256ByteCompression,
            HasherChallenger<Groestl256>,
        >(
            &ccs,
            self.log_inv_rate,
            self.security_bits,
            &cs_digest,
            &boundaries,
            proof.clone(),
        )?;

        Ok(())
    }

    fn serialize_proof(proof: &Self::Proof) -> Vec<u8> {
        bincode::serialize(&proof.transcript).unwrap()
    }

    fn deserialize_proof(data: &[u8]) -> Self::Proof {
        let transcript = bincode::deserialize(data).unwrap();
        Proof { transcript }
    }
}
