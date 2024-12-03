use bench::HashInSnark;
use expander_arith::FieldSerde;
use expander_circuit::Circuit;
use expander_config::{Config, FiatShamirHashType, GKRConfig, GKRScheme};
use expander_gkr::{gkr_verify, Prover};
use expander_transcript::{BytesHashTranscript, Keccak256hasher, SHA256hasher, Transcript};
use rand::RngCore;
use rayon::{current_num_threads, prelude::*};
use std::{cell::RefCell, io::Cursor, iter::repeat_with};

pub mod circuit;

pub trait ExpanderCircuit {
    const CIRCUIT_DIR: &str;

    type Config: GKRConfig;

    fn scheme() -> GKRScheme;
}

pub struct Expander<C: ExpanderCircuit> {
    num_permutations: usize,
    config: Config<C::Config>,
    circuit: Circuit<C::Config>,
    provers: RefCell<Vec<Prover<C::Config>>>,
}

impl<C: ExpanderCircuit> HashInSnark for Expander<C> {
    type Input = Vec<Circuit<C::Config>>;
    type Proof = Vec<(<C::Config as GKRConfig>::ChallengeField, Vec<u8>)>;
    type Error = ();

    fn new(num_permutations: usize) -> Self
    where
        Self: Sized,
    {
        let current_num_threads = current_num_threads();
        let log_permutations_per_thread = (num_permutations / current_num_threads)
            .next_power_of_two()
            .ilog2();
        let num_permutations = current_num_threads << log_permutations_per_thread;
        let log_packing_size = C::Config::get_field_pack_size().ilog2();
        let circuit_path = format!(
            "{}/{}.txt",
            C::CIRCUIT_DIR,
            log_permutations_per_thread - log_packing_size
        );
        let circuit = Circuit::load_circuit(&circuit_path);
        let config = Config::new(C::scheme(), Default::default());
        let provers = repeat_with(|| {
            let mut prover = Prover::new(&config);
            prover.prepare_mem(&circuit);
            prover
        })
        .take(current_num_threads)
        .collect::<Vec<_>>();
        Self {
            num_permutations,
            config,
            circuit,
            provers: provers.into(),
        }
    }

    fn num_permutations(&self) -> usize {
        self.num_permutations
    }

    fn generate_input(&self, _: impl RngCore) -> Self::Input {
        repeat_with(|| {
            let mut circuit = self.circuit.clone();
            circuit.set_random_input_for_test();
            circuit.evaluate();
            circuit
        })
        .take(self.provers.borrow().len())
        .collect()
    }

    fn prove(&self, circuits: Self::Input) -> Self::Proof {
        self.provers
            .borrow_mut()
            .par_iter_mut()
            .zip(circuits.into_par_iter())
            .map(|(prover, mut circuit)| {
                let (claimed_v, transcript) = prover.prove(&mut circuit);
                (claimed_v, transcript.bytes)
            })
            .collect()
    }

    fn verify(&self, proofs: &Self::Proof) -> Result<(), Self::Error> {
        proofs
            .iter()
            .all(|(claimed_v, proof)| {
                match C::Config::FIAT_SHAMIR_HASH {
                    FiatShamirHashType::Keccak256 => {
                        let mut transcript = BytesHashTranscript::<_, Keccak256hasher>::new();
                        let proof = Cursor::new(&proof);
                        gkr_verify(
                            &self.config,
                            &self.circuit,
                            &[],
                            claimed_v,
                            &mut transcript,
                            proof,
                        )
                    }
                    FiatShamirHashType::SHA256 => {
                        let mut transcript = BytesHashTranscript::<_, SHA256hasher>::new();
                        let proof = Cursor::new(&proof);
                        gkr_verify(
                            &self.config,
                            &self.circuit,
                            &[],
                            claimed_v,
                            &mut transcript,
                            proof,
                        )
                    }
                    _ => unreachable!(),
                }
                .0
            })
            .then_some(())
            .ok_or(())
    }

    fn serialize_proof(proofs: &Self::Proof) -> Vec<u8> {
        bincode::serialize(&proofs.iter().map(|(claimed_v, proof)| {
            let mut claimed_v_bytes =
                vec![0; <<C as ExpanderCircuit>::Config as GKRConfig>::ChallengeField::SERIALIZED_SIZE];
            claimed_v.serialize_into(&mut claimed_v_bytes).unwrap();
            (claimed_v_bytes, proof)
        }).collect::<Vec<_>>()).unwrap()
    }

    fn deserialize_proof(bytes: &[u8]) -> Self::Proof {
        let proofs: Vec<(Vec<u8>, Vec<u8>)> = bincode::deserialize(bytes).unwrap();
        proofs
            .into_iter()
            .map(|(claimed_v_bytes, proof)| {
                let claimed_v = <_>::deserialize_from(claimed_v_bytes.as_slice()).unwrap();
                (claimed_v, proof)
            })
            .collect()
    }
}
