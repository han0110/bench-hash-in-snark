use binius_core::{
    fiat_shamir::HasherChallenger,
    merkle_tree_vcs::{BinaryMerkleTreeProver, BinaryMerkleTreeScheme},
    poly_commit::{
        batch_pcs::{self, BatchPCS},
        PolyCommitScheme, FRIPCS,
    },
    tower::{PackedTop, TowerFamily, TowerUnderlier},
    transcript::{AdviceReader, AdviceWriter, TranscriptReader, TranscriptWriter},
};
use binius_field::{
    as_packed_field::{PackScalar, PackedType},
    AESTowerField8b, BinaryField128b, BinaryField128bPolyval, BinaryField8b, ExtensionField, Field,
    PackedExtension, PackedField, PackedFieldIndexable, TowerField,
};
use binius_hal::make_portable_backend;
use binius_hash::Hasher;
use binius_math::{EvaluationDomainFactory, MultilinearExtension};
use binius_ntt::NTTOptions;
use groestl_crypto::Groestl256;
use hashcaster::{field::F128, traits::CompressedPoly};
use itertools::Itertools;
use p3_challenger::{CanObserve, CanSample, HashChallenger};
use p3_keccak::Keccak256Hash;
use p3_symmetric::{CryptographicHasher, PseudoCompressionFunction};
use rayon::{
    iter::{IntoParallelRefIterator, ParallelIterator},
    slice::ParallelSlice,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug)]
pub enum Error {
    Sumcheck(SumcheckError),
    Pcs(batch_pcs::Error),
}

#[derive(Debug)]
pub enum SumcheckError {
    UnmatchedSubclaim(String),
}

impl From<SumcheckError> for Error {
    fn from(err: SumcheckError) -> Self {
        Self::Sumcheck(err)
    }
}

impl From<batch_pcs::Error> for Error {
    fn from(err: batch_pcs::Error) -> Self {
        Self::Pcs(err)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SumcheckProof {
    pub round_polys: Vec<CompressedPoly>,
    pub evals: Vec<F128>,
}

pub struct F128Challenger<H: CryptographicHasher<u8, [u8; 32]> = Keccak256Hash> {
    inner: HashChallenger<u8, H, 32>,
}

impl<H> F128Challenger<H>
where
    H: CryptographicHasher<u8, [u8; 32]>,
{
    pub fn new(initial_state: Vec<u8>, hasher: H) -> Self {
        Self {
            inner: HashChallenger::new(initial_state, hasher),
        }
    }
}

impl F128Challenger<Keccak256Hash> {
    pub fn keccak256() -> Self {
        Self::new(Vec::new(), Keccak256Hash)
    }
}

impl<H> CanObserve<F128> for F128Challenger<H>
where
    H: CryptographicHasher<u8, [u8; 32]>,
{
    fn observe(&mut self, value: F128) {
        self.inner.observe_slice(&value.raw().to_be_bytes());
    }
}

impl<H> CanObserve<BinaryField8b> for F128Challenger<H>
where
    H: CryptographicHasher<u8, [u8; 32]>,
{
    fn observe(&mut self, value: BinaryField8b) {
        self.inner.observe(u8::from(value));
    }
}

impl<H> CanObserve<AESTowerField8b> for F128Challenger<H>
where
    H: CryptographicHasher<u8, [u8; 32]>,
{
    fn observe(&mut self, value: AESTowerField8b) {
        self.inner.observe(u8::from(value));
    }
}

impl<H> CanSample<F128> for F128Challenger<H>
where
    H: CryptographicHasher<u8, [u8; 32]>,
{
    fn sample(&mut self) -> F128 {
        F128::from_raw(u128::from_be_bytes(self.inner.sample_array()))
    }
}

// Copied and modified from https://github.com/IrreducibleOSS/binius/blob/9791abc/crates/core/src/constraint_system/common.rs.
// TODO: Implement PCS directly for `BinaryField128bPolyval` instead of using isomorphic to `BinaryField128b`.

pub type FExt<Tower> = <Tower as TowerFamily>::B128;

pub type FDomain<Tower> = <Tower as TowerFamily>::B8;

pub type FEncode<Tower> = <Tower as TowerFamily>::B32;

pub type BatchFRIPCS<Tower, U, F, Digest, DomainFactory, Hash, Compress> = BatchPCS<
    <PackedType<U, FExt<Tower>> as PackedExtension<F>>::PackedSubfield,
    FExt<Tower>,
    FRIPCS<
        F,
        FDomain<Tower>,
        FEncode<Tower>,
        PackedType<U, FExt<Tower>>,
        DomainFactory,
        BinaryMerkleTreeProver<Digest, Hash, Compress>,
        BinaryMerkleTreeScheme<Digest, Hash, Compress>,
    >,
>;

pub type PackedSubfield<U, F> =
    <<U as PackScalar<F>>::Packed as PackedExtension<F>>::PackedSubfield;

pub type Commitment<Tower, U, F, Digest, DomainFactory, Hash, Compress> =
    <BatchFRIPCS<Tower, U, F, Digest, DomainFactory, Hash, Compress> as PolyCommitScheme<
        <PackedType<U, FExt<Tower>> as PackedExtension<F>>::PackedSubfield,
        FExt<Tower>,
    >>::Commitment;

pub type Committed<Tower, U, F, Digest, DomainFactory, Hash, Compress> =
    <BatchFRIPCS<Tower, U, F, Digest, DomainFactory, Hash, Compress> as PolyCommitScheme<
        <PackedType<U, FExt<Tower>> as PackedExtension<F>>::PackedSubfield,
        FExt<Tower>,
    >>::Committed;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FriPcsProof {
    transcript: Vec<u8>,
    advice: Vec<u8>,
}

pub struct BatchFRIPCS128<Tower, U, Digest, DomainFactory, Hash, Compress>
where
    U: TowerUnderlier<Tower> + PackScalar<Tower::B128>,
    Tower: TowerFamily,
    Tower::B128:
        PackedTop<Tower> + ExtensionField<Tower::B128> + PackedExtension<Tower::B128> + TowerField,
    Digest: PackedField<Scalar: TowerField>,
    DomainFactory: EvaluationDomainFactory<Tower::B8>,
    Hash: Hasher<Tower::B128, Digest = Digest> + Send + Sync,
    Compress: PseudoCompressionFunction<Digest, 2> + Default + Sync,
    PackedType<U, Tower::B128>: PackedTop<Tower> + PackedFieldIndexable,
{
    batch_fri_pcs: BatchFRIPCS<Tower, U, Tower::B128, Digest, DomainFactory, Hash, Compress>,
}

impl<Tower, U, Digest, DomainFactory, Hash, Compress>
    BatchFRIPCS128<Tower, U, Digest, DomainFactory, Hash, Compress>
where
    U: TowerUnderlier<Tower> + PackScalar<Tower::B128>,
    Tower: TowerFamily,
    Tower::B128: PackedTop<Tower>
        + ExtensionField<Tower::B128>
        + PackedExtension<Tower::B128>
        + TowerField
        + From<BinaryField128b>,
    Digest: PackedField<Scalar: TowerField>,
    DomainFactory: EvaluationDomainFactory<Tower::B8> + Default,
    Hash: Hasher<Tower::B128, Digest = Digest> + Send + Sync,
    Compress: PseudoCompressionFunction<Digest, 2> + Default + Sync,
    PackedType<U, Tower::B128>: PackedTop<Tower> + PackedFieldIndexable,
{
    pub fn new(
        security_bits: usize,
        log_inv_rate: usize,
        num_vars: usize,
        batch_size: usize,
    ) -> Self {
        let merkle_prover = BinaryMerkleTreeProver::<_, Hash, _>::new(Compress::default());
        let log_n_polys = batch_size.next_power_of_two().ilog2() as usize;
        let fri_n_vars = num_vars + log_n_polys;
        let fri_pcs = FRIPCS::<
            _,
            FDomain<Tower>,
            FEncode<Tower>,
            PackedType<U, <Tower as TowerFamily>::B128>,
            _,
            _,
            _,
        >::with_optimal_arity(
            fri_n_vars,
            log_inv_rate,
            security_bits,
            merkle_prover,
            DomainFactory::default(),
            NTTOptions::default(),
        )
        .unwrap();
        let batch_fri_pcs = BatchPCS::new(fri_pcs, num_vars, log_n_polys).unwrap();
        Self { batch_fri_pcs }
    }

    #[allow(clippy::type_complexity)]
    pub fn commit(
        &self,
        polys: &[Vec<F128>],
    ) -> (
        Vec<MultilinearExtension<PackedSubfield<U, Tower::B128>>>,
        Commitment<Tower, U, Tower::B128, Digest, DomainFactory, Hash, Compress>,
        Committed<Tower, U, Tower::B128, Digest, DomainFactory, Hash, Compress>,
    ) {
        let polys = polys
            .par_iter()
            .map(|poly| {
                MultilinearExtension::from_values(iso_slice_packed::<U, Tower::B128>(poly)).unwrap()
            })
            .collect::<Vec<_>>();
        let (commitment, committed) = self.batch_fri_pcs.commit(&polys).unwrap();
        (polys, commitment, committed)
    }

    pub fn open(
        &self,
        polys: &[MultilinearExtension<PackedSubfield<U, Tower::B128>>],
        committed: &Committed<Tower, U, Tower::B128, Digest, DomainFactory, Hash, Compress>,
        point: &[F128],
    ) -> FriPcsProof {
        let mut transcript = TranscriptWriter::<HasherChallenger<Groestl256>>::default();
        let mut advice = AdviceWriter::default();
        let point = iso_slice(point);
        self.batch_fri_pcs
            .prove_evaluation(
                &mut advice,
                &mut transcript,
                committed,
                polys,
                &point,
                &make_portable_backend(),
            )
            .unwrap();
        FriPcsProof {
            transcript: transcript.finalize(),
            advice: advice.finalize(),
        }
    }

    pub fn verify(
        &self,
        commitment: &Commitment<Tower, U, Tower::B128, Digest, DomainFactory, Hash, Compress>,
        proof: &FriPcsProof,
        point: &[F128],
        evals: &[F128],
    ) -> Result<(), Error> {
        let mut transcript =
            TranscriptReader::<HasherChallenger<Groestl256>>::new(proof.transcript.clone());
        let mut advice = AdviceReader::new(proof.advice.clone());
        let point = iso_slice(point);
        let evals = iso_slice(evals);
        self.batch_fri_pcs.verify_evaluation(
            &mut advice,
            &mut transcript,
            commitment,
            &point,
            &evals,
            &make_portable_backend(),
        )?;
        Ok(())
    }
}

#[inline(always)]
fn iso<F: From<BinaryField128b>>(value: &F128) -> F {
    F::from(BinaryField128b::from(BinaryField128bPolyval::from(
        value.raw(),
    )))
}

fn iso_slice<F: From<BinaryField128b>>(values: &[F128]) -> Vec<F> {
    values.iter().map(iso).collect()
}

fn iso_slice_packed<U: PackScalar<F>, F: Field + From<BinaryField128b>>(
    values: &[F128],
) -> Vec<PackedSubfield<U, F>> {
    values
        .par_chunks(PackedSubfield::<U, F>::WIDTH)
        .map(|scalars| PackedSubfield::<U, F>::from_scalars(scalars.iter().map(iso)))
        .collect()
}

pub fn serialize_packed<S, F: PackedField<Scalar: Into<u8>>>(
    v: &F,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_bytes(&v.iter().map_into().collect_vec())
}

pub fn deserialize_packed<'de, D, F: PackedField<Scalar: From<u8>>>(
    deserializer: D,
) -> Result<F, D::Error>
where
    D: Deserializer<'de>,
{
    Vec::<u8>::deserialize(deserializer).map(|bytes| F::from_scalars(bytes.into_iter().map_into()))
}
