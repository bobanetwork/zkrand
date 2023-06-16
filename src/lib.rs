mod dkg;
mod dkg_n;
mod poseidon;
mod utils;

pub use halo2_ecc::integer::NUMBER_OF_LOOKUP_LIMBS;
const BIT_LEN_LIMB: usize = 68;
const NUMBER_OF_LIMBS: usize = 4;
const POSEIDON_WIDTH: usize = 3;
const POSEIDON_RATE: usize = 2;
const POSEIDON_LEN: usize = 2;

// recommended numbers (closest to 2^n):
// num = 6, k = 20
// num = 13, k = 21
const THRESHOLD: usize = 7;
const NUMBER_OF_MEMBERS: usize = 13;
const DEGREE: usize = 21;