mod dkg;
mod poseidon;
mod utils;

pub use halo2_ecc::integer::NUMBER_OF_LOOKUP_LIMBS;
const BIT_LEN_LIMB: usize = 68;
const NUMBER_OF_LIMBS: usize = 4;
const POSEIDON_WIDTH: usize = 3;
const POSEIDON_RATE: usize = 2;
const POSEIDON_LEN: usize = 2;

const THRESHOLD: usize = 3;
const NUMBER: usize = 5;
