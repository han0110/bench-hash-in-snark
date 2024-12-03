use crate::ExpanderCircuit;
use expander_config::{GKRScheme, M31ExtConfigSha2};

pub struct M31Keccak;

impl ExpanderCircuit for M31Keccak {
    const CIRCUIT_DIR: &str = "./circuit/m31_keccak";

    type Config = M31ExtConfigSha2;

    fn scheme() -> GKRScheme {
        GKRScheme::Vanilla
    }
}
