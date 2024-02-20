use crate::error::Error;
use crate::hash_to_curve_evm::from_be_bytes;
use crate::utils::hash_to_curve_bn;
use halo2_ecc::halo2::halo2curves::bn256::G2Prepared;
use halo2_maingate::halo2::halo2curves::bn256::multi_miller_loop;
use halo2wrong::curves::bn256::{Fr as BnScalar, G1Affine as BnG1, G2Affine as BnG2};
use halo2wrong::curves::group::{Curve, Group};
use halo2wrong::curves::pairing::MillerLoopResult;
use halo2wrong::halo2::arithmetic::Field;
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

pub const EVAL_PREFIX: &str = "DVRF pseudorandom generation 2023";

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

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct DkgConfig {
    threshold: usize,
    number_of_members: usize,
}

impl DkgConfig {
    pub fn new(threshold: usize, number_of_members: usize) -> Result<DkgConfig, Error> {
        if threshold > 0 && threshold <= number_of_members {
            return Ok(DkgConfig {
                threshold,
                number_of_members,
            });
        };

        return Err(Error::InvalidParams {
            threshold,
            number_of_members,
        });
    }

    pub fn threshold(&self) -> usize {
        return self.threshold;
    }

    pub fn number_of_members(&self) -> usize {
        return self.number_of_members;
    }

    pub fn circuit_instance_size(&self) -> usize {
        let mut length = 7 * self.number_of_members() + 6;
        #[cfg(feature = "g2chip")]
        {
            length += 8;
        }

        length
    }
}

// compute secret shares for n parties
pub fn shares(number_of_members: usize, coeffs: &[BnScalar]) -> Vec<BnScalar> {
    let mut shares = vec![];
    let s1 = coeffs.iter().sum();
    shares.push(s1);

    for i in 2..=number_of_members {
        let s = evaluate_poly(coeffs, i);
        shares.push(s);
    }

    shares
}

pub struct DkgShareKey {
    index: usize,
    sk: BnScalar,
    vk: BnG1,
}

impl DkgShareKey {
    pub fn new(index: usize, sk: BnScalar, vk: BnG1) -> Self {
        DkgShareKey { index, sk, vk }
    }
    pub fn secret_key(&self) -> BnScalar {
        self.sk
    }
    pub fn verify_key(&self) -> BnG1 {
        self.vk
    }

    pub fn index(&self) -> usize {
        self.index
    }

    // verify the index and verification key is correct w.r.t. a list of public verification keys
    pub fn verify(&self, dkg_config: &DkgConfig, vks: &[BnG1]) -> Result<(), Error> {
        if self.index < 1 || self.index > dkg_config.number_of_members {
            return Err(Error::InvalidIndex { index: self.index });
        }

        if self.vk != vks[self.index - 1] {
            return Err(Error::VerifyFailed);
        }

        Ok(())
    }

    // compute H(x)^sk to create partial evaluation and create a schnorr style proof
    pub fn evaluate(&self, input: &[u8], mut rng: impl RngCore) -> PartialEval {
        let hasher = hash_to_curve_bn(EVAL_PREFIX);
        let h: BnG1 = hasher(input).to_affine();
        let v = (h * self.sk).to_affine();

        let g = BnG1::generator();
        let r = BnScalar::random(&mut rng);
        let cap_r_1 = (g * r).to_affine();
        let cap_r_2 = (h * r).to_affine();

        let mut bytes = v.y.to_bytes().to_vec();
        bytes.extend(v.x.to_bytes());
        bytes.extend(self.vk.y.to_bytes());
        bytes.extend(self.vk.x.to_bytes());
        bytes.extend(cap_r_2.y.to_bytes());
        bytes.extend(cap_r_2.x.to_bytes());
        bytes.extend(cap_r_1.y.to_bytes());
        bytes.extend(cap_r_1.x.to_bytes());
        bytes.extend(h.y.to_bytes());
        bytes.extend(h.x.to_bytes());
        bytes.extend(g.y.to_bytes());
        bytes.extend(g.x.to_bytes());
        bytes.reverse();

        let hash_state: [u8; 32] = Keccak256::new()
            .chain_update(&bytes)
            .finalize()
            .to_vec()
            .try_into()
            .unwrap();
        let c = BnScalar::from_raw(from_be_bytes(&hash_state));
        let z = c * self.sk + r;
        let proof = (z, c);

        PartialEval {
            index: self.index,
            value: v,
            proof,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PartialEval {
    pub index: usize,
    pub value: BnG1,
    pub proof: (BnScalar, BnScalar),
}

impl PartialEval {
    pub fn verify(&self, dkg_config: &DkgConfig, input: &[u8], vk: &BnG1) -> Result<(), Error> {
        if self.index > dkg_config.number_of_members || self.index < 1 {
            return Err(Error::InvalidIndex { index: self.index });
        };

        let hasher = hash_to_curve_bn(EVAL_PREFIX);
        let h: BnG1 = hasher(input).to_affine();

        let g = BnG1::generator();
        let z = self.proof.0;
        let c = self.proof.1;
        let v = self.value;

        let cap_r_1 = ((g * z) - (vk * c)).to_affine();
        let cap_r_2 = ((h * z) - (v * c)).to_affine();

        // reverse order to match solidity version
        let mut bytes = v.y.to_bytes().to_vec();
        bytes.extend(v.x.to_bytes());
        bytes.extend(vk.y.to_bytes());
        bytes.extend(vk.x.to_bytes());
        bytes.extend(cap_r_2.y.to_bytes());
        bytes.extend(cap_r_2.x.to_bytes());
        bytes.extend(cap_r_1.y.to_bytes());
        bytes.extend(cap_r_1.x.to_bytes());
        bytes.extend(h.y.to_bytes());
        bytes.extend(h.x.to_bytes());
        bytes.extend(g.y.to_bytes());
        bytes.extend(g.x.to_bytes());
        bytes.reverse();

        let hash_state: [u8; 32] = Keccak256::new()
            .chain_update(&bytes)
            .finalize()
            .to_vec()
            .try_into()
            .unwrap();
        let c_tilde = BnScalar::from_raw(from_be_bytes(&hash_state));

        if c != c_tilde {
            return Err(Error::VerifyFailed);
        }

        Ok(())
    }
}

pub struct PseudoRandom {
    pub proof: BnG1,
    pub value: Vec<u8>,
}

// check if the indices are in the range and sorted
fn check_indices(number_of_members: usize, indices: &[usize]) -> Result<(), Error> {
    for i in 0..indices.len() {
        if i < indices.len() - 1 {
            if indices[i] >= indices[i + 1] {
                return Err(Error::InvalidOrder { index: i });
            };
        }
        if indices[i] > number_of_members || indices[i] < 1 {
            return Err(Error::InvalidIndex { index: indices[i] });
        };
    }

    Ok(())
}

// obtain final random
pub fn combine_partial_evaluations(
    dkg_config: &DkgConfig,
    sigmas: &[PartialEval],
) -> Result<PseudoRandom, Error> {
    assert_eq!(sigmas.len(), dkg_config.threshold);

    let indices: Vec<_> = sigmas.iter().map(|sigma| sigma.index).collect();
    check_indices(dkg_config.number_of_members, &indices)?;

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
        .map(|(sigma, lambda)| sigma.value * lambda)
        .collect();
    let sum = pis.iter().skip(1).fold(pis[0], |sum, p| sum + p);

    let proof = sum.to_affine();
    let value = Keccak256::new()
        .chain_update(proof.x.to_bytes())
        .chain_update(proof.y.to_bytes())
        .finalize()
        .to_vec();

    Ok(PseudoRandom { proof, value })
}

impl PseudoRandom {
    pub fn new(proof: BnG1, value: Vec<u8>) -> Self {
        Self { proof, value }
    }

    pub fn value(&self) -> &[u8] {
        &self.value
    }

    pub fn proof(&self) -> &BnG1 {
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

        let value = Keccak256::new()
            .chain_update(self.proof.x.to_bytes())
            .chain_update(self.proof.y.to_bytes())
            .finalize()
            .to_vec();

        if !self.value.as_slice().eq(&value) {
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
    use rand_core::{OsRng, SeedableRng};

    #[test]
    fn test_partial_evaluation() {
        //let mut rng = ChaCha20Rng::seed_from_u64(42);
        let mut rng = OsRng;
        let dkg_config = DkgConfig::new(9, 16).unwrap(); // can be any numbers here
        let index = 1;
        let (sk, vk) = keygen(&mut rng);
        let key = DkgShareKey { index, sk, vk };
        let x = b"the first random 20230626";

        let start = start_timer!(|| format!("partial evaluations {:?}", dkg_config));
        let sigma = key.evaluate(x, &mut rng);
        end_timer!(start);

        sigma.verify(&dkg_config, x, &vk).unwrap();
    }

    fn pseudo_random(threshold: usize, number_of_members: usize) {
        //let mut rng = ChaCha20Rng::seed_from_u64(42);
        let mut rng = OsRng;

        let g = BnG1::generator();
        let g2 = BnG2::generator();

        let dkg_config = DkgConfig::new(threshold, number_of_members).unwrap();
        let coeffs: Vec<_> = (0..dkg_config.threshold())
            .map(|_| BnScalar::random(&mut rng))
            .collect();
        let shares = shares(dkg_config.number_of_members(), &coeffs);
        let keys: Vec<_> = shares
            .iter()
            .enumerate()
            .map(|(i, s)| DkgShareKey {
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
            .all(|(e, vk)| e.verify(&dkg_config, input, vk).is_ok());

        assert!(res);

        let start = start_timer!(|| format!("combine partial evaluations {:?}", dkg_config));
        let pseudo_random =
            combine_partial_evaluations(&dkg_config, &evals[0..dkg_config.threshold()]).unwrap();
        end_timer!(start);

        let start = start_timer!(|| format!("verify pseudo random value {:?}", dkg_config));
        pseudo_random.verify(input, &gpk).unwrap();
        end_timer!(start);
    }

    #[test]
    fn test_pseudo_random() {
        pseudo_random(4, 6);
        pseudo_random(7, 13);
        pseudo_random(14, 27);
        pseudo_random(28, 55);
        pseudo_random(57, 112);
    }
}
