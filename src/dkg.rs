use rand_core::RngCore;

use crate::poseidon::P128Pow5T3Bn;
use crate::utils::mod_n;
use halo2_gadgets::poseidon::primitives::{ConstantLength, Hash};
use halo2wrong::curves::bn256::{pairing, Fr as BnScalar, G1Affine as BnG1, G2Affine as BnG2};
use halo2wrong::curves::group::prime::PrimeCurveAffine;
use halo2wrong::curves::group::{Curve, GroupEncoding};
use halo2wrong::halo2::arithmetic::Field;
use sha3::digest::DynDigest;
use sha3::{Digest, Keccak256};

pub fn keygen(mut rng: impl RngCore) -> (BnScalar, BnG1) {
    let g = BnG1::generator();
    let sk = BnScalar::random(&mut rng);
    let pk = (g * sk).to_affine();

    (sk, pk)
}

pub fn get_public_key(sk: BnScalar) -> BnG1 {
    let g = BnG1::generator();
    let pk = (g * sk).to_affine();

    pk
}

// todo: integrate this verification to dkg circuit verification
// check if ga and g2a have the same exponent a
pub fn verify_public_coeffs(ga: BnG1, g2a: BnG2) {
    let g = BnG1::generator();
    let g2 = BnG2::generator();

    let left = pairing(&g, &g2a);
    let right = pairing(&ga, &g2);

    assert_eq!(left, right);
}

// evaluate a polynomial at index i
fn evaluate(coeffs: &[BnScalar], i: usize) -> BnScalar {
    assert!(coeffs.len() >= 1);

    let mut x = i;
    let mut eval = coeffs[0];

    for a in coeffs.iter().skip(1) {
        eval += a * BnScalar::from(x as u64);
        x = x * i;
    }

    eval
}

// compute secret shares for n parties
pub fn compute_shares<const THRESHOLD: usize, const NUMBER_OF_MEMBERS: usize>(
    coeffs: &[BnScalar],
) -> [BnScalar; NUMBER_OF_MEMBERS] {
    assert_eq!(coeffs.len(), THRESHOLD);

    let mut shares = vec![];
    let s1 = coeffs.iter().sum();
    shares.push(s1);

    for i in 2..=NUMBER_OF_MEMBERS {
        let s = evaluate(coeffs, i);
        shares.push(s);
    }

    shares.try_into().unwrap()
}

fn get_public_shares(shares: &[BnScalar]) -> Vec<BnG1> {
    let g = BnG1::generator();
    let public_shares: Vec<_> = shares.iter().map(|s| (g * s).to_affine()).collect();
    public_shares
}

fn encrypt_shares<const THRESHOLD: usize, const NUMBER_OF_MEMBERS: usize>(
    shares: &[BnScalar],
    public_keys: &[BnG1],
    mut rng: impl RngCore,
) -> (BnScalar, BnG1, Vec<BnScalar>) {
    assert_eq!(shares.len(), NUMBER_OF_MEMBERS);
    assert_eq!(public_keys.len(), NUMBER_OF_MEMBERS);

    let g = BnG1::generator();

    // Draw arandomness for encryption
    let r = BnScalar::random(&mut rng);
    let gr = (g * r).to_affine();

    let poseidon = Hash::<_, P128Pow5T3Bn, ConstantLength<2>, 3, 2>::init();

    let mut ciphers = vec![];
    for i in 0..NUMBER_OF_MEMBERS {
        // Encrypt
        let pkr = (public_keys[i] * r).to_affine();
        let message = [mod_n::<BnG1>(pkr.x), mod_n::<BnG1>(pkr.y)];
        let key = poseidon.clone().hash(message);
        let cipher = key + shares[i];
        ciphers.push(cipher)
    }

    (r, gr, ciphers)
}

fn decrypt_share(sk: BnScalar, gr: BnG1, cipher: BnScalar) -> BnScalar {
    let pkr = (gr * sk).to_affine();
    let poseidon = Hash::<_, P128Pow5T3Bn, ConstantLength<2>, 3, 2>::init();
    let message = [mod_n::<BnG1>(pkr.x), mod_n::<BnG1>(pkr.y)];
    let key = poseidon.clone().hash(message);
    let plaintext = cipher - key;

    plaintext
}

// combine shares received from other members
// verification key is computed as vk = g^s
fn combine_shares(shares: &[BnScalar]) -> BnScalar {
    shares.iter().sum()
}

// compute global public key g2a and verification keys vk_i for each member i
fn combine_public_params(gas: &[BnG1], g2as: &[BnG2]) -> (BnG1, BnG2) {
    let ga = gas
        .iter()
        .skip(1)
        .fold(gas[0], |sum, h| (sum + h).to_affine());
    let g2a = g2as
        .iter()
        .skip(1)
        .fold(g2as[0], |sum, h| (sum + h).to_affine());

    (ga, g2a)
}
