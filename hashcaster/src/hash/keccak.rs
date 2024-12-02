// Copied and modified from https://github.com/morgana-proofs/hashcaster/blob/d9891c0/src/examples/keccak/main_protocol.rs.

use crate::util::{
    deserialize_packed, serialize_packed, BatchFRIPCS128, Error, F128Challenger, FriPcsProof,
    SumcheckError, SumcheckProof,
};
use bench::HashInSnark;
use binius_core::tower::{AESTowerFamily, TowerFamily};
use binius_field::{
    arch::OptimalUnderlier,
    as_packed_field::{PackScalar, PackedType},
    BinaryField, PackedField,
};
use binius_hash::{Groestl256, GroestlDigestCompression};
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

const NUM_VARS_PER_PERMUTATIONS: usize = 10 + 3 - 7;
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
        PackedType<U, <Tower as TowerFamily>::B8>,
        DomainFactory,
        Groestl256<<Tower as TowerFamily>::B128, <Tower as TowerFamily>::B8>,
        GroestlDigestCompression<<Tower as TowerFamily>::B8>,
    >,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HashcasterKeccakProof<F: BinaryField + From<u8> + Into<u8>>
where
    U: PackScalar<F>,
{
    #[serde(
        serialize_with = "serialize_packed::<_, U, F>",
        deserialize_with = "deserialize_packed::<_, U, F>",
        bound = "U: PackScalar<F>, F: BinaryField + From<u8> + Into<u8>"
    )]
    layer0_comm: PackedType<U, F>,
    layer2_claims: [F128; 5],
    bool_check_proof: SumcheckProof,
    multi_open_proof: SumcheckProof,
    lin_check_proof: SumcheckProof,
    layer0_open_proof: FriPcsProof,
}

impl HashInSnark for HashcasterKeccak {
    type Input = [Vec<F128>; 5];
    type Proof = HashcasterKeccakProof<<Tower as TowerFamily>::B8>;
    type Error = Error;

    fn new(num_permutations: usize) -> Self
    where
        Self: Sized,
    {
        let num_permutations = num_permutations.next_power_of_two();
        let security_bits = 100;
        let log_inv_rate = 1;
        let num_vars = num_permutations.ilog2() as usize + NUM_VARS_PER_PERMUTATIONS;
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

        let layer0 = input;
        let layer1 = keccak_linround_witness(layer0.each_ref().map(|poly| poly.as_slice()));
        let layer2 = chi_round_witness(&layer1);

        let (layer0_packed, layer0_comm, layer0_committed) = self.pcs.commit(&layer0);

        layer0_comm
            .iter()
            .for_each(|scalar| challenger.observe(scalar));

        let layer2_point = challenger.sample_vec(self.num_vars());
        let layer2_claims: [F128; 5] = layer2.each_ref().map(|poly| evaluate(poly, &layer2_point));
        challenger.observe_slice(&layer2_claims);

        let (bool_check_proof, multi_open_proof, layer1_point) =
            self.prove_layer2(&layer1, &layer2_point, &layer2_claims, &mut challenger);

        let (lin_check_proof, layer0_point) = {
            let layer1_claims = multi_open_proof.evals.clone().try_into().unwrap();
            self.prove_layer1(&layer0, &layer1_point, &layer1_claims, &mut challenger)
        };

        let layer0_open_proof = self
            .pcs
            .open(&layer0_packed, &layer0_committed, &layer0_point);

        HashcasterKeccakProof {
            layer0_comm,
            layer2_claims,
            bool_check_proof,
            multi_open_proof,
            lin_check_proof,
            layer0_open_proof,
        }
    }

    fn verify(&self, proof: &Self::Proof) -> Result<(), Self::Error> {
        let mut challenger = F128Challenger::keccak256();

        proof
            .layer0_comm
            .iter()
            .for_each(|scalar| challenger.observe(scalar));

        let layer2_point = challenger.sample_vec(self.num_vars());
        challenger.observe_slice(&proof.layer2_claims);

        let layer1_point = self.verify_layer2(
            &layer2_point,
            &proof.layer2_claims,
            &proof.bool_check_proof,
            &proof.multi_open_proof,
            &mut challenger,
        )?;

        let layer0_point = {
            let layer1_claims = proof.multi_open_proof.evals.clone().try_into().unwrap();
            self.verify_layer1(
                &layer1_point,
                &layer1_claims,
                &proof.lin_check_proof,
                &mut challenger,
            )?
        };

        self.pcs.verify(
            &proof.layer0_comm,
            &proof.layer0_open_proof,
            &layer0_point,
            &proof.lin_check_proof.evals,
        )
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

    fn prove_layer2(
        &self,
        layer1: &[Vec<F128>; 5],
        point: &[F128],
        claims: &[F128; 5],
        challenger: &mut F128Challenger,
    ) -> (SumcheckProof, SumcheckProof, Vec<F128>) {
        let (bool_check_proof, multi_open_point) = {
            let f = ChiPackage {};
            let gamma = challenger.sample();

            let prover = BoolCheck::new(f, layer1.clone(), BOOL_CHECK_C, *claims, point.to_vec());
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

            (SumcheckProof { round_polys, evals }, rs)
        };

        let (multi_open_proof, layer1_point) = {
            let gamma = challenger.sample();

            let multi_open_claims = bool_check_proof.evals.clone();
            let prover = MulticlaimCheck::new(layer1, multi_open_point.clone(), multi_open_claims);
            let mut prover = prover.folding_challenge(gamma);

            let mut claim = evaluate_univar(&bool_check_proof.evals, gamma);
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

            (SumcheckProof { round_polys, evals }, rs)
        };

        (bool_check_proof, multi_open_proof, layer1_point)
    }

    fn prove_layer1(
        &self,
        layer0: &[Vec<F128>; 5],
        point: &[F128],
        claims: &[F128; 5],
        challenger: &mut F128Challenger,
    ) -> (SumcheckProof, Vec<F128>) {
        let matrix = KeccakLinMatrix::new();
        let gamma = challenger.sample();

        let prover = Lincheck::new(
            layer0.clone(),
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

    fn verify_layer2(
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

        let multi_open_point = {
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
            (folded_claimed_ev * eq_ev(point, &rs) == claim)
                .then_some(rs)
                .ok_or_else(|| SumcheckError::UnmatchedSubclaim("BoolCheck".to_string()))?
        };

        let layer1_point = {
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

            let mut tmp = multi_open_point.clone();
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
                .then_some(rs)
                .ok_or_else(|| SumcheckError::UnmatchedSubclaim("MulticlaimCheck".to_string()))?
        };

        Ok(layer1_point)
    }

    fn verify_layer1(
        &self,
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

        let m = KeccakLinMatrix::new();
        let mut target = vec![F128::zero(); 5 * (1 << LIN_CHECK_NUM_VARS)];
        m.apply_transposed(&adj_eq_vec, &mut target);

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
