use crate::{circuit::Plonky3Circuit, config::Plonky3Config};
use bench::util::pcs_log_inv_rate;
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::{ExtensionField, PrimeField32, TwoAdicField};
use p3_fri::{FriConfig, TwoAdicFriPcs};
use p3_keccak::{Keccak256Hash, KeccakF, VECTOR_LEN};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{CompressionFunctionFromHasher, PaddingFreeSponge, SerializingHasher32To64};
use p3_uni_stark::{StarkConfig, StarkGenericConfig};

pub type U64Hash = PaddingFreeSponge<KeccakF, 25, 17, 4>;
pub type FieldHash = SerializingHasher32To64<U64Hash>;
pub type Compress = CompressionFunctionFromHasher<U64Hash, 2, 4>;
pub type ValMmcs<F> = MerkleTreeMmcs<[F; VECTOR_LEN], [u64; VECTOR_LEN], FieldHash, Compress, 4>;
pub type ChallengeMmcs<F, E> = ExtensionMmcs<F, E, ValMmcs<F>>;
pub type ByteHash = Keccak256Hash;
pub type Challenger<Val> = SerializingChallenger32<Val, HashChallenger<u8, ByteHash, 32>>;
pub type Dft<Val> = Radix2DitParallel<Val>;
pub type Pcs<Val, Challenge> =
    TwoAdicFriPcs<Val, Dft<Val>, ValMmcs<Val>, ChallengeMmcs<Val, Challenge>>;

pub struct KeccakMtConfig<Val, Challenge> {
    stark_config: StarkConfig<Pcs<Val, Challenge>, Challenge, Challenger<Val>>,
}

impl<Val: TwoAdicField + PrimeField32, Challenge: TwoAdicField + ExtensionField<Val>> Plonky3Config
    for KeccakMtConfig<Val, Challenge>
{
    type StarkGenericConfig = StarkConfig<Pcs<Val, Challenge>, Challenge, Challenger<Val>>;

    fn new(_: &impl Plonky3Circuit<Self::StarkGenericConfig>) -> Self
    where
        Self: Sized,
    {
        let u64_hash = U64Hash::new(KeccakF {});
        let field_hash = FieldHash::new(u64_hash);
        let compress = Compress::new(u64_hash);
        let val_mmcs = ValMmcs::new(field_hash, compress);
        let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
        let dft = Dft::default();
        // TODO: Calculate precise minimum #queries to reach 128-bits provable security.
        let log_blowup = pcs_log_inv_rate();
        let num_queries = usize::div_ceil(256, log_blowup);
        let fri_config = FriConfig {
            log_blowup,
            num_queries,
            proof_of_work_bits: 0,
            mmcs: challenge_mmcs,
        };
        let pcs = Pcs::new(dft, val_mmcs, fri_config);
        let stark_config = StarkConfig::new(pcs);
        Self { stark_config }
    }

    fn challenger(&self) -> <Self::StarkGenericConfig as StarkGenericConfig>::Challenger {
        let byte_hash = ByteHash {};
        Challenger::from_hasher(vec![], byte_hash)
    }

    fn stark_config(&self) -> &Self::StarkGenericConfig {
        &self.stark_config
    }
}
