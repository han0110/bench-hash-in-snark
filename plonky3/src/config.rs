use p3_baby_bear::BabyBear;
use p3_field::extension::BinomialExtensionField;
use p3_koala_bear::KoalaBear;
use p3_uni_stark::StarkGenericConfig;

mod keccak_mt;

pub type BabyBearKeccakMtConfig =
    keccak_mt::KeccakMtConfig<BabyBear, BinomialExtensionField<BabyBear, 4>>;
pub type KoalaBearKeccakMtConfig =
    keccak_mt::KeccakMtConfig<KoalaBear, BinomialExtensionField<KoalaBear, 4>>;

pub trait Plonky3Config {
    type StarkGenericConfig: StarkGenericConfig;

    fn new(trace_height: usize, log_blowup: usize) -> Self
    where
        Self: Sized;

    fn stark_config(&self) -> &Self::StarkGenericConfig;

    fn challenger(&self) -> <Self::StarkGenericConfig as StarkGenericConfig>::Challenger;
}
