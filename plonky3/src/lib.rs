use crate::{circuit::Plonky3Circuit, config::Plonky3Config};
use bench::HashInSnark;
use core::fmt::Debug;
use p3_uni_stark::{prove, verify, Proof};
use rand::RngCore;

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

    fn new(num_permutations: usize) -> Self
    where
        Self: Sized,
    {
        let circuit = Circuit::new(num_permutations);
        let config = Config::new(&circuit);
        Self { config, circuit }
    }

    fn num_permutations(&self) -> usize {
        self.circuit.num_permutations()
    }

    fn generate_input(&self, rng: impl RngCore) -> Self::Input {
        self.circuit.generate_input(rng)
    }

    fn prove(&self, input: Self::Input) -> Self::Proof {
        let mut challenger = self.config.challenger();
        let trace = self.circuit.generate_trace(input);
        prove(
            self.config.stark_config(),
            self.circuit.air(),
            &mut challenger,
            trace,
            &vec![],
        )
    }

    fn verify(&self, proof: &Self::Proof) -> Result<(), impl Debug> {
        let mut challenger = self.config.challenger();
        verify(
            self.config.stark_config(),
            self.circuit.air(),
            &mut challenger,
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

#[cfg(test)]
mod test {
    use crate::{
        circuit::{Blake3Circuit, KeccakCircuit, KoalaBearPoseidon2Circuit},
        config::{BabyBearKeccakMtConfig, KoalaBearKeccakMtConfig},
        Plonky3,
    };
    use bench::assert_proof_size;

    #[test]
    fn keccak_proof_size() {
        type H = Plonky3<BabyBearKeccakMtConfig, KeccakCircuit>;
        assert_proof_size::<H>([(1 << 10, 1_671_012)]);
    }

    #[test]
    fn blake3_proof_size() {
        type H = Plonky3<BabyBearKeccakMtConfig, Blake3Circuit>;
        assert_proof_size::<H>([(1 << 10, 4_241_972)]);
    }

    #[test]
    fn koala_bear_poseidon2_proof_size() {
        type H = Plonky3<KoalaBearKeccakMtConfig, KoalaBearPoseidon2Circuit>;
        assert_proof_size::<H>([(1 << 20, 1_227_060), (1 << 21, 1_293_492)]);
    }
}
