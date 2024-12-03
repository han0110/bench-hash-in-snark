use bench::HashInSnark;
use expander_arith::FieldSerde;
use expander_circuit::Circuit;
use expander_config::{Config, FiatShamirHashType, GKRConfig, GKRScheme};
use expander_gkr::{gkr_verify, Prover};
use expander_transcript::{BytesHashTranscript, Keccak256hasher, SHA256hasher, Transcript};
use rand::RngCore;
use std::{cell::RefCell, io::Cursor};

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
    prover: RefCell<Prover<C::Config>>,
}

impl<C: ExpanderCircuit> HashInSnark for Expander<C> {
    type Input = Circuit<C::Config>;
    type Proof = (<C::Config as GKRConfig>::ChallengeField, Vec<u8>);
    type Error = ();

    fn new(num_permutations: usize) -> Self
    where
        Self: Sized,
    {
        let num_permutations = num_permutations.next_power_of_two();
        let circuit_path = format!("{}/{}.txt", C::CIRCUIT_DIR, num_permutations.ilog2());
        let circuit = Circuit::load_circuit(&circuit_path);
        let config = Config::new(C::scheme(), Default::default());
        let mut prover = Prover::new(&config);
        prover.prepare_mem(&circuit);
        Self {
            num_permutations,
            config,
            circuit,
            prover: prover.into(),
        }
    }

    fn num_permutations(&self) -> usize {
        self.num_permutations
    }

    fn generate_input(&self, _: impl RngCore) -> Self::Input {
        let mut circuit = self.circuit.clone();
        circuit.set_random_input_for_test();
        circuit
    }

    fn prove(&self, mut circuit: Self::Input) -> Self::Proof {
        let (claimed_v, transcript) = self.prover.borrow_mut().prove(&mut circuit);
        (claimed_v, transcript.bytes)
    }

    fn verify(&self, (claimed_v, proof): &Self::Proof) -> Result<(), Self::Error> {
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
        .then_some(())
        .ok_or(())
    }

    fn serialize_proof((claimed_v, proof): &Self::Proof) -> Vec<u8> {
        let mut claimed_v_bytes =
            vec![0; <<C as ExpanderCircuit>::Config as GKRConfig>::ChallengeField::SERIALIZED_SIZE];
        claimed_v.serialize_into(&mut claimed_v_bytes).unwrap();
        bincode::serialize(&(claimed_v_bytes, proof)).unwrap()
    }

    fn deserialize_proof(bytes: &[u8]) -> Self::Proof {
        let (claimed_v_bytes, proof): (Vec<u8>, _) = bincode::deserialize(bytes).unwrap();
        let claimed_v =
            <<C as ExpanderCircuit>::Config as GKRConfig>::ChallengeField::deserialize_from(
                claimed_v_bytes.as_slice(),
            )
            .unwrap();
        (claimed_v, proof)
    }
}
