use bench::HashInSnark;
use expander_circuit::Circuit;
use expander_config::{Config, GKRConfig, GKRScheme, MPIConfig};
use expander_gkr::Prover;
use rand::RngCore;
use std::cell::RefCell;

pub mod circuit;

pub trait ExpanderCircuit {
    const CIRCUIT_DIR: &str;

    type Config: GKRConfig;

    fn scheme() -> GKRScheme;
}

pub struct Expander<C: ExpanderCircuit> {
    num_permutations: usize,
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
        let mut prover = Prover::new(&Config::new(C::scheme(), MPIConfig::new()));
        prover.prepare_mem(&circuit);
        Self {
            num_permutations,
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
        let (claim, transcript) = self.prover.borrow_mut().prove(&mut circuit);
        (claim, transcript.bytes)
    }

    fn verify(&self, _proof: &Self::Proof) -> Result<(), Self::Error> {
        todo!()
    }

    fn serialize_proof(_proof: &Self::Proof) -> Vec<u8> {
        todo!()
    }

    fn deserialize_proof(_bytes: &[u8]) -> Self::Proof {
        todo!()
    }
}
