use crate::ExpanderCircuit;
use expander_config::{GF2ExtConfigSha2, GKRScheme};

pub struct Gf2Keccak;

impl ExpanderCircuit for Gf2Keccak {
    const CIRCUIT_DIR: &str = "./circuit/gf2_keccak";

    type Config = GF2ExtConfigSha2;

    fn scheme() -> GKRScheme {
        GKRScheme::Vanilla
    }
}
