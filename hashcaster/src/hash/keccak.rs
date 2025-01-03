// Copied and modified from https://github.com/morgana-proofs/hashcaster/blob/d9891c0/src/examples/keccak/main_protocol.rs.

use crate::util::{
    deserialize_packed, serialize_packed, BatchFRIPCS128, Error, F128Challenger, FriPcsProof,
    SumcheckError, SumcheckProof,
};
use bench::{util::pcs_log_inv_rate, HashInSnark};
use binius_core::tower::{AESTowerFamily, TowerFamily};
use binius_field::{arch::OptimalUnderlier, PackedField};
use binius_hash::{Groestl256, GroestlDigest, GroestlDigestCompression};
use binius_math::IsomorphicEvaluationDomainFactory;
use core::array::from_fn;
use hashcaster::{
    examples::keccak::{
        chi_round::{chi_round_witness, ChiPackage},
        matrices::{keccak_linround_witness, KeccakLinMatrix},
    },
    field::F128,
    protocols::{
        boolcheck::{BoolCheck, FnPackage},
        lincheck::{LinOp, Lincheck, LincheckOutput},
        multiclaim::MulticlaimCheck,
        utils::{eq_ev, eq_poly, evaluate, evaluate_univar, untwist_evals},
    },
    traits::SumcheckObject,
};
use itertools::{chain, Itertools};
use num_traits::{One, Zero};
use p3_challenger::{CanObserve, CanSample};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;

const NUM_VARS_PER_PERMUTATIONS: usize = 2;
const BOOL_CHECK_C: usize = 5;
const LIN_CHECK_NUM_VARS: usize = 10;

type U = OptimalUnderlier;
type Tower = AESTowerFamily;
type DomainFactory = IsomorphicEvaluationDomainFactory<<Tower as TowerFamily>::B8>;

#[allow(clippy::type_complexity)]
pub struct HashcasterKeccak {
    num_permutations: usize,
    pcs: BatchFRIPCS128<
        Tower,
        U,
        GroestlDigest<<Tower as TowerFamily>::B8>,
        DomainFactory,
        Groestl256<<Tower as TowerFamily>::B128, <Tower as TowerFamily>::B8>,
        GroestlDigestCompression<<Tower as TowerFamily>::B8>,
    >,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HashcasterKeccakProof {
    #[serde(
        serialize_with = "serialize_packed",
        deserialize_with = "deserialize_packed"
    )]
    input_comm: GroestlDigest<<Tower as TowerFamily>::B8>,
    initial_claims: [F128; 5],
    rounds: [(SumcheckProof, SumcheckProof, SumcheckProof); 24],
    input_open_proof: FriPcsProof,
}

impl HashInSnark for HashcasterKeccak {
    type Input = [Vec<F128>; 5];
    type Proof = HashcasterKeccakProof;
    type Error = Error;

    fn new(num_permutations: usize) -> Self
    where
        Self: Sized,
    {
        let num_vars = (num_permutations.ilog2() as usize + NUM_VARS_PER_PERMUTATIONS).max(10);
        let num_permutations = 3 << (num_vars - 3);
        let security_bits = 100;
        let log_inv_rate = pcs_log_inv_rate();
        let pcs = BatchFRIPCS128::new(security_bits, log_inv_rate, num_vars, 5);
        Self {
            num_permutations,
            pcs,
        }
    }

    fn num_permutations(&self) -> usize {
        self.num_permutations
    }

    fn generate_input(&self, mut rng: impl RngCore) -> Self::Input {
        let num_vars = self.num_vars();
        from_fn(|_| (0..1 << num_vars).map(|_| F128::rand(&mut rng)).collect())
    }

    fn prove(&self, input: Self::Input) -> Self::Proof {
        let mut challenger = F128Challenger::keccak256();

        // TODO: Add deferred iota to linear layer.
        let layers = (0..24usize).fold(vec![input], |mut layers, _| {
            let last = layers.last().unwrap();
            let lin = keccak_linround_witness(last.each_ref().map(Vec::as_slice));
            let chi = chi_round_witness(&lin);
            layers.extend([lin, chi]);
            layers
        });

        let (input_packed, input_comm, input_committed) = self.pcs.commit(&layers[0]);

        input_comm
            .iter()
            .for_each(|scalar| challenger.observe(scalar));

        let point = challenger.sample_vec(self.num_vars());
        let initial_claims: [F128; 5] = layers[layers.len() - 1]
            .each_ref()
            .map(|poly| evaluate(poly, &point));
        challenger.observe_slice(&initial_claims);

        let mut layers_rev = layers.iter().rev().skip(1);
        let mut claims = initial_claims;
        let mut point = point;

        let rounds: [_; 24] = from_fn(|_| {
            let (bool_check_proof, multi_open_proof, lin_check_proof);

            (bool_check_proof, multi_open_proof, point) =
                self.prove_chi(layers_rev.next().unwrap(), &point, &claims, &mut challenger);
            claims = multi_open_proof.evals.clone().try_into().unwrap();

            (lin_check_proof, point) = self.prove_lin(
                KeccakLinMatrix::new(),
                layers_rev.next().unwrap(),
                &point,
                &claims,
                &mut challenger,
            );
            claims = lin_check_proof.evals.clone().try_into().unwrap();

            (bool_check_proof, multi_open_proof, lin_check_proof)
        });

        let input_open_proof = self.pcs.open(&input_packed, &input_committed, &point);

        HashcasterKeccakProof {
            input_comm,
            initial_claims,
            rounds,
            input_open_proof,
        }
    }

    fn verify(&self, proof: &Self::Proof) -> Result<(), Self::Error> {
        let mut challenger = F128Challenger::keccak256();

        proof
            .input_comm
            .iter()
            .for_each(|scalar| challenger.observe(scalar));

        let point = challenger.sample_vec(self.num_vars());
        challenger.observe_slice(&proof.initial_claims);

        let mut claims = proof.initial_claims;
        let mut point = point;

        for (bool_check_proof, multi_open_proof, lin_check_proof) in &proof.rounds {
            point = self.verify_chi(
                &point,
                &claims,
                bool_check_proof,
                multi_open_proof,
                &mut challenger,
            )?;
            claims = multi_open_proof.evals.clone().try_into().unwrap();

            point = self.verify_lin(
                KeccakLinMatrix::new(),
                &point,
                &claims,
                lin_check_proof,
                &mut challenger,
            )?;
            claims = lin_check_proof.evals.clone().try_into().unwrap();
        }

        self.pcs
            .verify(&proof.input_comm, &proof.input_open_proof, &point, &claims)
    }

    fn serialize_proof(proof: &Self::Proof) -> Vec<u8> {
        bincode::serialize(proof).unwrap()
    }

    fn deserialize_proof(bytes: &[u8]) -> Self::Proof {
        bincode::deserialize(bytes).unwrap()
    }
}

impl HashcasterKeccak {
    fn num_vars(&self) -> usize {
        self.num_permutations.ilog2() as usize + NUM_VARS_PER_PERMUTATIONS
    }

    fn prove_chi(
        &self,
        input: &[Vec<F128>; 5],
        point: &[F128],
        claims: &[F128; 5],
        challenger: &mut F128Challenger,
    ) -> (SumcheckProof, SumcheckProof, Vec<F128>) {
        let (bool_check_proof, multi_open_proof);
        let mut point = Cow::Borrowed(point);

        (bool_check_proof, point) = {
            let f = ChiPackage {};
            let gamma = challenger.sample();

            let prover = BoolCheck::new(f, input.clone(), BOOL_CHECK_C, *claims, point.to_vec());
            let mut prover = prover.folding_challenge(gamma);

            let mut claim = evaluate_univar(claims, gamma);
            let mut round_polys = vec![];
            let mut rs = vec![];
            for _ in 0..self.num_vars() {
                let round_poly = prover.round_msg();

                challenger.observe_slice(&round_poly.compressed_coeffs);
                let r = challenger.sample();

                claim = evaluate_univar(&round_poly.coeffs(claim), r);
                prover.bind(r);

                round_polys.push(round_poly);
                rs.push(r);
            }

            let evals = prover.finish().frob_evals;

            challenger.observe_slice(&evals);

            (SumcheckProof { round_polys, evals }, rs.into())
        };

        (multi_open_proof, point) = {
            let gamma = challenger.sample();

            let claims = &bool_check_proof.evals;
            let prover = MulticlaimCheck::new(input, point.to_vec(), claims.clone());
            let mut prover = prover.folding_challenge(gamma);

            let mut claim = evaluate_univar(claims, gamma);
            let mut round_polys = vec![];
            let mut rs = vec![];
            for _ in 0..self.num_vars() {
                let round_poly = prover.round_msg();

                challenger.observe_slice(&round_poly.compressed_coeffs);
                let r = challenger.sample();

                claim = evaluate_univar(&round_poly.coeffs(claim), r);
                prover.bind(r);

                round_polys.push(round_poly.clone());
                rs.push(r);
            }

            let evals = prover.finish();

            challenger.observe_slice(&evals);

            (SumcheckProof { round_polys, evals }, rs.into())
        };

        (bool_check_proof, multi_open_proof, point.into())
    }

    fn prove_lin(
        &self,
        matrix: impl LinOp,
        input: &[Vec<F128>; 5],
        point: &[F128],
        claims: &[F128; 5],
        challenger: &mut F128Challenger,
    ) -> (SumcheckProof, Vec<F128>) {
        let gamma = challenger.sample();

        let prover = Lincheck::new(
            input.clone(),
            point.to_vec(),
            matrix,
            LIN_CHECK_NUM_VARS,
            *claims,
        );
        let mut prover = prover.folding_challenge(gamma);

        let mut claim = evaluate_univar(claims, gamma);
        let mut round_polys = vec![];
        let mut rs = vec![];
        for _ in 0..LIN_CHECK_NUM_VARS {
            let round_poly = prover.round_msg();

            challenger.observe_slice(&round_poly.compressed_coeffs);
            let r = challenger.sample();

            claim = evaluate_univar(&round_poly.coeffs(claim), r);
            prover.bind(r);

            round_polys.push(round_poly);
            rs.push(r);
        }

        let LincheckOutput { p_evs: evals, .. } = prover.finish();

        challenger.observe_slice(&evals);

        (
            SumcheckProof { round_polys, evals },
            chain![rs, point[LIN_CHECK_NUM_VARS..].iter().copied()].collect(),
        )
    }

    fn verify_chi(
        &self,
        point: &[F128],
        claims: &[F128; 5],
        bool_check_proof: &SumcheckProof,
        multi_open_proof: &SumcheckProof,
        challenger: &mut F128Challenger,
    ) -> Result<Vec<F128>, SumcheckError> {
        assert_eq!(bool_check_proof.round_polys.len(), self.num_vars());
        assert_eq!(multi_open_proof.round_polys.len(), self.num_vars());
        assert_eq!(bool_check_proof.evals.len(), 128 * 5);
        assert_eq!(multi_open_proof.evals.len(), 5);

        let mut point = Cow::Borrowed(point);

        point = {
            let f = ChiPackage {};
            let gamma = challenger.sample();

            let mut claim = evaluate_univar(claims, gamma);
            let mut rs = vec![];
            for round_poly in &bool_check_proof.round_polys {
                assert_eq!(round_poly.compressed_coeffs.len(), 3);

                challenger.observe_slice(&round_poly.compressed_coeffs);
                let r = challenger.sample();

                claim = evaluate_univar(&round_poly.coeffs(claim), r);

                rs.push(r);
            }

            let frob_evals = &bool_check_proof.evals;
            challenger.observe_slice(frob_evals);

            let mut coord_evals = frob_evals.clone();
            coord_evals.chunks_mut(128).for_each(untwist_evals);

            coord_evals.push(F128::zero()); // Ugly hack.
            let claimed_ev = f.exec_alg(&coord_evals, 0, 1)[0];

            let folded_claimed_ev = evaluate_univar(&claimed_ev, gamma);
            (folded_claimed_ev * eq_ev(&point, &rs) == claim)
                .then(|| rs.into())
                .ok_or_else(|| SumcheckError::UnmatchedSubclaim("BoolCheck".to_string()))?
        };

        point = {
            let gamma = challenger.sample();

            let mut claim = evaluate_univar(&bool_check_proof.evals, gamma);
            let mut rs = vec![];
            for round_poly in &multi_open_proof.round_polys {
                assert_eq!(round_poly.compressed_coeffs.len(), 2);

                challenger.observe_slice(&round_poly.compressed_coeffs);
                let r = challenger.sample();

                claim = evaluate_univar(&round_poly.coeffs(claim), r);

                rs.push(r);
            }

            let evals = &multi_open_proof.evals;

            challenger.observe_slice(evals);

            let mut pt_inv_orbit = vec![];

            let mut tmp = point.to_vec();
            for _ in 0..128 {
                tmp.iter_mut().for_each(|x| *x *= *x);
                pt_inv_orbit.push(tmp.clone())
            }
            pt_inv_orbit.reverse();

            let mut gamma128 = gamma;
            for _ in 0..7 {
                gamma128 *= gamma128;
            }

            let eq_evs: Vec<_> = pt_inv_orbit.iter().map(|pt| eq_ev(pt, &rs)).collect();

            let eq_ev = evaluate_univar(&eq_evs, gamma);
            let eval = evaluate_univar(evals, gamma128);

            (eval * eq_ev == claim)
                .then(|| rs.into())
                .ok_or_else(|| SumcheckError::UnmatchedSubclaim("MulticlaimCheck".to_string()))?
        };

        Ok(point.into())
    }

    fn verify_lin(
        &self,
        matrix: impl LinOp,
        point: &[F128],
        claims: &[F128; 5],
        lin_check_proof: &SumcheckProof,
        challenger: &mut F128Challenger,
    ) -> Result<Vec<F128>, SumcheckError> {
        assert_eq!(lin_check_proof.round_polys.len(), LIN_CHECK_NUM_VARS);
        assert_eq!(lin_check_proof.evals.len(), 5);

        let gamma = challenger.sample();

        let mut claim = evaluate_univar(claims, gamma);
        let mut rs = vec![];
        for round_poly in &lin_check_proof.round_polys {
            assert_eq!(round_poly.compressed_coeffs.len(), 2);

            challenger.observe_slice(&round_poly.compressed_coeffs);
            let r = challenger.sample();

            claim = evaluate_univar(&round_poly.coeffs(claim), r);

            rs.push(r);
        }

        let evals = &lin_check_proof.evals;

        challenger.observe_slice(evals);

        let eq1 = eq_poly(&point[..LIN_CHECK_NUM_VARS]);
        let eq0 = eq_poly(&rs);
        let mut adj_eq_vec = vec![];

        let mut mult = F128::one();
        for _ in 0..5 {
            adj_eq_vec.extend(eq1.iter().map(|x| *x * mult));
            mult *= gamma;
        }

        let mut target = vec![F128::zero(); 5 * (1 << LIN_CHECK_NUM_VARS)];
        matrix.apply_transposed(&adj_eq_vec, &mut target);

        let mut eq_evals = vec![];
        for i in 0..5 {
            eq_evals.push(
                target[i * (1 << LIN_CHECK_NUM_VARS)..(i + 1) * (1 << LIN_CHECK_NUM_VARS)]
                    .iter()
                    .zip(eq0.iter())
                    .map(|(a, b)| *a * b)
                    .fold(F128::zero(), |a, b| a + b),
            );
        }

        let expected_claim = evals
            .iter()
            .zip_eq(eq_evals.iter())
            .map(|(a, b)| *a * b)
            .fold(F128::zero(), |a, b| a + b);

        (expected_claim == claim)
            .then(|| chain![rs, point[LIN_CHECK_NUM_VARS..].iter().copied()].collect())
            .ok_or_else(|| SumcheckError::UnmatchedSubclaim("LinCheck".to_string()))
    }
}

#[cfg(test)]
mod test {
    use crate::hash::HashcasterKeccak;
    use bench::{test, util::po2};

    #[test]
    fn keccak() {
        for num_permutations in po2(10..13) {
            test::<HashcasterKeccak>(num_permutations).unwrap();
        }
    }
}
