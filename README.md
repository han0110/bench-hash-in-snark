# Benchmark Hash in SNARK

## Usage

```sh
RAYON_NUM_THREADS=<num_threads> ./bench.sh <package> <hash> <log_permutations>
```

Available `package` and `hash`:

- `binius` - `keccak`, `vision`
- `expander` - `keccak`, `poseidon`
- `hashcaster` - `keccak`
- `plonky3` - `keccak`, `blake3`, `poseidon2`
- `stwo` - `blake2s`, `poseidon2`

The script `bench.sh` collects 10 proving samples and outputs:

- `time`
- `throughput`
- `proof size`
- `peak mem`

The output will be written to `./<package>/report/t<num_threads>_<hash>_lp<log_permutations>`.

Or one can get into any `<package>` and run `RAYON_NUM_THREADS=<num_threads> cargo bench`.
