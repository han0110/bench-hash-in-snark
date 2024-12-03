use crate::ExpanderCircuit;
use expander_config::{GKRScheme, M31ExtConfigSha2};

pub struct M31Poseidon;

impl ExpanderCircuit for M31Poseidon {
    const CIRCUIT_DIR: &str = "./circuit/m31_poseidon";

    type Config = M31ExtConfigSha2;

    fn scheme() -> GKRScheme {
        GKRScheme::Vanilla
    }
}
