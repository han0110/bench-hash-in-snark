pub mod circuit;

#[cfg(test)]
mod test {
    use crate::circuit::{StwoBlake2s, StwoPoseidon2};
    use bench::assert_proof_size;

    #[test]
    fn blake3_proof_size() {
        type H = StwoBlake2s;
        assert_proof_size::<H>([(1 << 10, 3_434_316), (1 << 11, 3_438_728)]);
    }

    #[test]
    fn m31_poseidon2_proof_size() {
        type H = StwoPoseidon2;
        assert_proof_size::<H>([(1 << 20, 2_227_864), (1 << 21, 2_349_424)]);
    }
}
