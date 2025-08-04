use crate::{circuit::Plonky3Circuit, config::Plonky3Config};
use bench::{HashInSnark, util::pcs_log_inv_rate};
use p3_uni_stark::{PcsError, Proof, VerificationError, prove, verify};
use rand::RngCore;
use tracing_forest::{ForestLayer, util::LevelFilter};
use tracing_subscriber::{EnvFilter, Registry, prelude::*};

pub mod circuit;
pub mod config;

pub struct Plonky3<Config, Circuit> {
    config: Config,
    circuit: Circuit,
}

impl<Config, Circuit> HashInSnark for Plonky3<Config, Circuit>
where
    Config: Plonky3Config,
    Circuit: Plonky3Circuit<Config::StarkGenericConfig>,
{
    type Input = Circuit::Input;
    type Proof = Proof<Config::StarkGenericConfig>;
    type Error = VerificationError<PcsError<Config::StarkGenericConfig>>;

    fn new(num_permutations: usize) -> Self
    where
        Self: Sized,
    {
        let log_blowup = pcs_log_inv_rate();
        let circuit = Circuit::new(num_permutations, log_blowup);
        let config = Config::new(circuit.trace_height(), log_blowup);
        Self { config, circuit }
    }

    fn num_permutations(&self) -> usize {
        self.circuit.num_permutations()
    }

    fn generate_input(&self, rng: impl RngCore) -> Self::Input {
        self.circuit.generate_input(rng)
    }

    fn prove(&self, input: Self::Input) -> Self::Proof {
        let trace = self.circuit.generate_trace(input);
        prove(
            self.config.stark_config(),
            self.circuit.air(),
            trace,
            &vec![],
        )
    }

    fn verify(&self, proof: &Self::Proof) -> Result<(), Self::Error> {
        verify(
            self.config.stark_config(),
            self.circuit.air(),
            proof,
            &vec![],
        )
    }

    fn serialize_proof(proof: &Self::Proof) -> Vec<u8> {
        bincode::serialize(proof).unwrap()
    }

    fn deserialize_proof(bytes: &[u8]) -> Self::Proof {
        bincode::deserialize(bytes).unwrap()
    }
}

pub fn setup_trace() {
    let env_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();
    Registry::default()
        .with(env_filter)
        .with(ForestLayer::default())
        .init();
}
