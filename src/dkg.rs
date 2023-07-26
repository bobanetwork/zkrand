use blake2b_simd::{blake2b, State as Blake2bState};
use halo2_ecc::halo2::halo2curves::bn256::G2Prepared;
use halo2_maingate::halo2::halo2curves::bn256::multi_miller_loop;
use halo2wrong::curves::bn256::{Fr as BnScalar, G1Affine as BnG1, G2Affine as BnG2};
use halo2wrong::curves::ff::FromUniformBytes;
use halo2wrong::curves::group::{Curve, Group, GroupEncoding};
use halo2wrong::curves::pairing::MillerLoopResult;
use halo2wrong::halo2::arithmetic::Field;
use rand_core::RngCore;

use crate::error::Error;
use crate::utils::hash_to_curve_bn;

pub const EVAL_PREFIX: &str = "partial evaluation for creating randomness";

// evaluate a polynomial at index i
fn evaluate_poly(coeffs: &[BnScalar], i: usize) -> BnScalar {
    assert!(coeffs.len() >= 1);

    let x = BnScalar::from(i as u64);
    let mut prod = x;
    let mut eval = coeffs[0];

    for a in coeffs.iter().skip(1) {
        eval += a * prod;
        prod = prod * x;
    }

    eval
}

// compute secret shares for n parties
pub fn get_shares<const THRESHOLD: usize, const NUMBER_OF_MEMBERS: usize>(
    coeffs: &[BnScalar],
) -> [BnScalar; NUMBER_OF_MEMBERS] {
    assert_eq!(coeffs.len(), THRESHOLD);

    let mut shares = vec![];
    let s1 = coeffs.iter().sum();
    shares.push(s1);

    for i in 2..=NUMBER_OF_MEMBERS {
        let s = evaluate_poly(coeffs, i);
        shares.push(s);
    }

    shares
        .try_into()
        .expect("cannot convert share vector to array")
}

pub struct DkgShareKey<const THRESHOLD: usize, const NUMBER_OF_MEMBERS: usize> {
    index: usize,
    sk: BnScalar,
    vk: BnG1,
}

impl<const THRESHOLD: usize, const NUMBER_OF_MEMBERS: usize>
    DkgShareKey<THRESHOLD, NUMBER_OF_MEMBERS>
{
    pub fn new(index: usize, sk: BnScalar, vk: BnG1) -> Self {
        DkgShareKey { index, sk, vk }
    }

    pub fn get_verification_key(&self) -> BnG1 {
        self.vk
    }

    pub fn get_index(&self) -> usize {
        self.index
    }

    // verify the index and verification key is correct w.r.t. a list of public verification keys
    pub fn verify(&self, vks: &[BnG1]) -> Result<(), Error> {
        if self.index < 1 || self.index > NUMBER_OF_MEMBERS {
            return Err(Error::InvalidIndex { index: self.index });
        }

        if self.vk != vks[self.index - 1] {
            return Err(Error::VerifyFailed);
        }

        Ok(())
    }

    // compute H(x)^sk to create partial evaluation and create a schnorr style proof
    pub fn evaluate(
        &self,
        input: &[u8],
        mut rng: impl RngCore,
    ) -> PartialEval<THRESHOLD, NUMBER_OF_MEMBERS> {
        let hasher = hash_to_curve_bn(EVAL_PREFIX);
        let h: BnG1 = hasher(input).to_affine();
        let v = (h * self.sk).to_affine();

        let g = BnG1::generator();
        let r = BnScalar::random(&mut rng);
        let cap_r_1 = (g * r).to_affine();
        let cap_r_2 = (h * r).to_affine();

        let mut hash_state = Blake2bState::new();
        hash_state
            .update(g.to_bytes().as_ref())
            .update(h.to_bytes().as_ref())
            .update(cap_r_1.to_bytes().as_ref())
            .update(cap_r_2.to_bytes().as_ref())
            .update(self.vk.to_bytes().as_ref())
            .update(v.to_bytes().as_ref());
        let data: [u8; 64] = hash_state
            .finalize()
            .as_ref()
            .try_into()
            .expect("cannot convert hash result to array");

        let c = BnScalar::from_uniform_bytes(&data);
        let z = c * self.sk + r;
        let proof = (z, c);

        PartialEval {
            index: self.index,
            v,
            proof,
        }
    }
}

pub struct PartialEval<const THRESHOLD: usize, const NUMBER_OF_MEMBERS: usize> {
    index: usize,
    v: BnG1,
    proof: (BnScalar, BnScalar),
}

impl<const THRESHOLD: usize, const NUMBER_OF_MEMBERS: usize>
    PartialEval<THRESHOLD, NUMBER_OF_MEMBERS>
{
    pub fn verify(&self, input: &[u8], vk: &BnG1) -> Result<(), Error> {
        if self.index > NUMBER_OF_MEMBERS || self.index < 1 {
            return Err(Error::InvalidIndex { index: self.index });
        };

        let hasher = hash_to_curve_bn(EVAL_PREFIX);
        let h: BnG1 = hasher(input).to_affine();

        let g = BnG1::generator();
        let z = self.proof.0;
        let c = self.proof.1;
        let v = self.v;

        let cap_r_1 = ((g * z) - (vk * c)).to_affine();
        let cap_r_2 = ((h * z) - (v * c)).to_affine();

        let mut hash_state = Blake2bState::new();
        hash_state
            .update(g.to_bytes().as_ref())
            .update(h.to_bytes().as_ref())
            .update(cap_r_1.to_bytes().as_ref())
            .update(cap_r_2.to_bytes().as_ref())
            .update(vk.to_bytes().as_ref())
            .update(v.to_bytes().as_ref());
        let data: [u8; 64] = hash_state
            .finalize()
            .as_ref()
            .try_into()
            .expect("cannot convert hash result to array");
        let c_tilde = BnScalar::from_uniform_bytes(&data);

        if c != c_tilde {
            return Err(Error::VerifyFailed);
        }

        Ok(())
    }
}

pub struct PseudoRandom {
    proof: BnG1,
    value: Vec<u8>,
}

// check if the indices are in the range and sorted
fn check_indices<const NUMBER_OF_MEMBERS: usize>(indices: &[usize]) -> Result<(), Error> {
    for i in 0..indices.len() {
        if i < indices.len() - 1 {
            if indices[i] >= indices[i + 1] {
                return Err(Error::InvalidOrder { index: i });
            };
        }
        if indices[i] > NUMBER_OF_MEMBERS || indices[i] < 1 {
            return Err(Error::InvalidIndex { index: indices[i] });
        };
    }

    Ok(())
}

// obtain final random
pub fn combine_partial_evaluations<const THRESHOLD: usize, const NUMBER_OF_MEMBERS: usize>(
    sigmas: &[PartialEval<THRESHOLD, NUMBER_OF_MEMBERS>],
) -> Result<PseudoRandom, Error> {
    assert_eq!(sigmas.len(), THRESHOLD);

    let indices: Vec<_> = sigmas.iter().map(|sigma| sigma.index).collect();
    check_indices::<NUMBER_OF_MEMBERS>(&indices)?;

    // compute Lagrange coefficients
    let indices: Vec<_> = indices.iter().map(|i| BnScalar::from(*i as u64)).collect();
    let mut lambdas = vec![];
    for i in indices.iter() {
        let mut numerator = BnScalar::one();
        let mut denominator = BnScalar::one();
        for k in indices.iter() {
            if !k.eq(i) {
                numerator = numerator * k;
                denominator = denominator * (k - i);
            }
        }
        let lambda = numerator * denominator.invert().expect("cannot divide zero");
        lambdas.push(lambda);
    }

    // compute pi
    let pis: Vec<_> = sigmas
        .iter()
        .zip(lambdas.iter())
        .map(|(sigma, lambda)| sigma.v * lambda)
        .collect();
    let sum = pis.iter().skip(1).fold(pis[0], |sum, p| sum + p);

    let proof = sum.to_affine();
    let value = blake2b(proof.to_bytes().as_ref()).as_bytes().to_vec();

    Ok(PseudoRandom { proof, value })
}

impl PseudoRandom {
    pub fn new(proof: BnG1, value: Vec<u8>) -> Self {
        Self { proof, value }
    }

    pub fn get_value(&self) -> &[u8] {
        &self.value
    }

    pub fn get_proof(&self) -> &BnG1 {
        &self.proof
    }

    pub fn verify(&self, input: &[u8], gpk: &BnG2) -> Result<(), Error> {
        let g2 = BnG2::generator();

        let hasher = hash_to_curve_bn(EVAL_PREFIX);
        let h: BnG1 = hasher(input).to_affine();

        let gpk_prepared = G2Prepared::from_affine(gpk.clone());
        let g2_prepared = G2Prepared::from_affine(g2);

        let t = multi_miller_loop(&[(&-h, &gpk_prepared), (&self.proof, &g2_prepared)])
            .final_exponentiation();

        if !bool::from(t.is_identity()) {
            return Err(Error::VerifyFailed);
        }

        if !self
            .value
            .as_slice()
            .eq(blake2b(self.proof.to_bytes().as_ref()).as_ref())
        {
            return Err(Error::VerifyFailed);
        }

        Ok(())
    }
}

pub fn keygen(mut rng: impl RngCore) -> (BnScalar, BnG1) {
    let g = BnG1::generator();
    let sk = BnScalar::random(&mut rng);
    let pk = (g * sk).to_affine();

    (sk, pk)
}

// check if ga and g2a have the same exponent a
pub fn is_dl_equal(ga: &BnG1, g2a: &BnG2) -> Result<(), Error> {
    let g = BnG1::generator();
    let g2 = BnG2::generator();

    let g2a_prepared = G2Prepared::from_affine(g2a.clone());
    let g2_prepared = G2Prepared::from_affine(g2);

    let t = multi_miller_loop(&[(&-g, &g2a_prepared), (ga, &g2_prepared)]).final_exponentiation();

    if !bool::from(t.is_identity()) {
        return Err(Error::VerifyFailed);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::{end_timer, start_timer};
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    const THRESHOLD: usize = 9;
    const NUMBER_OF_MEMBERS: usize = 16;

    #[test]
    fn test_partial_evaluation() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let index = 1;
        let (sk, vk) = keygen(&mut rng);
        let key = DkgShareKey::<THRESHOLD, NUMBER_OF_MEMBERS> { index, sk, vk };
        let x = b"the first random 20230626";

        let start =
            start_timer!(|| format!("partial evaluations ({}, {})", THRESHOLD, NUMBER_OF_MEMBERS));
        let sigma = key.evaluate(x, &mut rng);
        end_timer!(start);

        sigma.verify(x, &vk).unwrap();
    }

    fn pseudo_random<const THRESHOLD: usize, const NUMBER_OF_MEMBERS: usize>() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        //  let index = 1;

        let g = BnG1::generator();
        let g2 = BnG2::generator();

        let coeffs: Vec<_> = (0..THRESHOLD).map(|_| BnScalar::random(&mut rng)).collect();
        let shares = get_shares::<THRESHOLD, NUMBER_OF_MEMBERS>(&coeffs);
        let keys: Vec<_> = shares
            .iter()
            .enumerate()
            .map(|(i, s)| DkgShareKey::<THRESHOLD, NUMBER_OF_MEMBERS> {
                index: i + 1,
                sk: *s,
                vk: (g * s).to_affine(),
            })
            .collect();
        let vks: Vec<_> = keys.iter().map(|key| key.vk).collect();

        let gpk = (g2 * coeffs[0]).to_affine();
        let input = b"test first random";

        let evals: Vec<_> = keys
            .iter()
            .map(|key| key.evaluate(input, &mut rng))
            .collect();

        let res = evals
            .iter()
            .zip(vks.iter())
            .all(|(e, vk)| e.verify(input, vk).is_ok());

        assert!(res);

        let start = start_timer!(|| format!(
            "combine partial evaluations ({}, {})",
            THRESHOLD, NUMBER_OF_MEMBERS
        ));
        let pseudo_random = combine_partial_evaluations(&evals[0..THRESHOLD]).unwrap();
        end_timer!(start);

        let start = start_timer!(|| format!(
            "verify pseudo random value ({}, {})",
            THRESHOLD, NUMBER_OF_MEMBERS
        ));
        pseudo_random.verify(input, &gpk).unwrap();
        end_timer!(start);
    }

    #[test]
    fn test_pseudo_random() {
        pseudo_random::<4, 6>();
        pseudo_random::<7, 13>();
        pseudo_random::<14, 27>();
        pseudo_random::<28, 55>();
        pseudo_random::<57, 112>();
    }
}
