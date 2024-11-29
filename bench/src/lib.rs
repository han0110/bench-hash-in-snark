use core::{fmt::Debug, hint::black_box};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::time::{Duration, Instant};

pub mod criterion;
pub mod util;

pub trait HashInSnark {
    type Input;
    type Proof;

    fn new(num_permutations: usize) -> Self
    where
        Self: Sized;

    fn num_permutations(&self) -> usize;

    fn generate_input(&self, rng: impl RngCore) -> Self::Input;

    fn prove(&self, input: Self::Input) -> Self::Proof;

    fn verify(&self, proof: &Self::Proof) -> Result<(), impl Debug>;

    fn serialize_proof(proof: &Self::Proof) -> Vec<u8>;

    fn deserialize_proof(data: &[u8]) -> Self::Proof;

    fn proof_size(&self) -> usize {
        let mut rng = StdRng::from_entropy();
        let input = self.generate_input(&mut rng);
        let proof = self.prove(input);
        self.verify(&proof).unwrap();
        let bytes = Self::serialize_proof(&proof);
        let proof = Self::deserialize_proof(&bytes);
        self.verify(&proof).unwrap();
        bytes.len()
    }
}

fn routine<H: HashInSnark>(snark: &H, mut rng: impl RngCore) -> (Duration, usize) {
    let input = black_box(snark.generate_input(&mut rng));

    let start = Instant::now();
    let proof = snark.prove(input);
    let elapsed = start.elapsed();

    let proof_size = H::serialize_proof(&proof).len();
    drop(black_box(proof));

    (elapsed, proof_size)
}

fn warm_up<H: HashInSnark>(snark: &H, mut rng: impl RngCore) {
    let mut total_elapsed = Duration::default();
    while total_elapsed.as_secs_f64() < 3.0 {
        total_elapsed += routine(snark, &mut rng).0;
    }
}

pub fn run<H: HashInSnark>(num_permutations: usize) {
    let snark = H::new(num_permutations);
    let input = black_box(snark.generate_input(StdRng::from_entropy()));
    let proof = snark.prove(input);
    drop(black_box(proof));
}

pub fn bench<H: HashInSnark>(
    num_permutations: usize,
    sample_size: usize,
) -> (usize, Duration, f64, f64) {
    let mut rng = StdRng::from_entropy();
    let snark = H::new(num_permutations);

    warm_up(&snark, &mut rng);

    let mut total_elapsed = Duration::default();
    let mut total_proof_size = 0;
    for _ in 0..sample_size {
        let (elapsed, proof_size) = routine(&snark, &mut rng);
        total_elapsed += elapsed;
        total_proof_size += proof_size;
    }

    let num_permutations = snark.num_permutations();
    let time = total_elapsed / sample_size as u32;
    let throughput = num_permutations as f64 / time.as_secs_f64();
    let proof_size = total_proof_size as f64 / sample_size as f64;
    (num_permutations, time, throughput, proof_size)
}

#[macro_export]
macro_rules! main {
    ($($variant:ident => $snark:ty,)*) => {
        #[derive(Clone, Debug, clap::ValueEnum)]
        enum Hash {
            $($variant,)*
        }

        #[derive(Clone, Debug, clap::Parser)]
        #[command(version, about)]
        struct Args {
            #[arg(long, value_enum)]
            hash: Hash,
            #[arg(long)]
            log_permutations: usize,
            #[arg(long)]
            sample_size: Option<usize>,
        }

        fn main() {
            let args: Args = clap::Parser::parse();

            let Some(sample_size) = args.sample_size else {
                match args.hash {
                    $(Hash::$variant => $crate::run::<$snark>(1 << args.log_permutations),)*
                }
                return;
            };

            let num_permutations = 1 << args.log_permutations;
            let (_, time, throughput, proof_size) = match args.hash {
                $(Hash::$variant => $crate::bench::<$snark>(num_permutations, sample_size),)*
            };
            println!(
                "      time: {}\nthroughput: {}\nproof size: {}",
                $crate::util::human_time(time),
                $crate::util::human_throughput(throughput),
                $crate::util::human_size(proof_size),
            );
        }
    };
}
