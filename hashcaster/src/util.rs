use hashcaster::{field::F128, traits::CompressedPoly};
use p3_challenger::{CanObserve, CanSample, HashChallenger};
use p3_keccak::Keccak256Hash;
use p3_symmetric::CryptographicHasher;
use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub enum Error {
    Sumcheck(SumcheckError),
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

impl<H> CanSample<F128> for F128Challenger<H>
where
    H: CryptographicHasher<u8, [u8; 32]>,
{
    fn sample(&mut self) -> F128 {
        F128::from_raw(u128::from_be_bytes(self.inner.sample_array()))
    }
}
