use crate::{circuit::Plonky3Circuit, config::Plonky3Config};
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::{ExtensionField, PrimeField32, TwoAdicField};
use p3_fri::{FriConfig, TwoAdicFriPcs};
use p3_keccak::Keccak256Hash;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher32};
use p3_uni_stark::{StarkConfig, StarkGenericConfig};

pub type ByteHash = Keccak256Hash;
pub type LeafHash = SerializingHasher32<ByteHash>;
pub type Compression = CompressionFunctionFromHasher<ByteHash, 2, 32>;
pub type ValMmcs<Val> = MerkleTreeMmcs<Val, u8, LeafHash, Compression, 32>;
pub type ChallengeMmcs<Val, Challenge> = ExtensionMmcs<Val, Challenge, ValMmcs<Val>>;
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
        let byte_hash = ByteHash {};
        let leaf_hash = LeafHash::new(byte_hash);
        let compress = Compression::new(byte_hash);
        let val_mmcs = ValMmcs::new(leaf_hash, compress);
        let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
        let dft = Dft::default();
        // TODO: Calculate precise minimum #queries to reach 128-bits provable security.
        let log_blowup = 1;
        let num_queries = 256;
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
