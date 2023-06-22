mod dkg;
mod dkg_circuit;
mod poseidon;
mod utils;

use rand_core::RngCore;
use std::rc::Rc;

pub use halo2_ecc::integer::NUMBER_OF_LOOKUP_LIMBS;
use halo2_ecc::Point;
use halo2_gadgets::poseidon::primitives::{ConstantLength, Hash};
use halo2wrong::curves::bn256::{pairing, Fr as BnScalar, G1Affine as BnG1, G2Affine as BnG2};
use halo2wrong::curves::group::Curve;
use halo2wrong::halo2::arithmetic::Field;
use halo2wrong::halo2::circuit::Value;

use crate::dkg::{compute_shares, keygen};
use crate::dkg_circuit::CircuitDkg;
use crate::poseidon::P128Pow5T3Bn;
use crate::utils::{mod_n, setup};

const BIT_LEN_LIMB: usize = 68;
const NUMBER_OF_LIMBS: usize = 4;
const POSEIDON_WIDTH: usize = 3;
const POSEIDON_RATE: usize = 2;
const POSEIDON_LEN: usize = 2;

// recommended numbers (closest to 2^n):
// t = 4, num = 6, k = 20
// t = 7, num = 13, k = 21

/*
const THRESHOLD: usize = 4;
const NUMBER_OF_MEMBERS: usize = 6;
const DEGREE: usize = 20;


const THRESHOLD: usize = 7;
const NUMBER_OF_MEMBERS: usize = 13;
const DEGREE: usize = 21;
 */

pub struct MemberKey {
    sk: BnScalar,
    pk: BnG1,
}

impl MemberKey {
    pub fn new(mut rng: impl RngCore) -> Self {
        let (sk, pk) = keygen(rng);

        MemberKey { sk, pk }
    }
}

pub struct DkgParams<const THRESHOLD: usize, const NUMBER_OF_MEMBERS: usize> {
    // each member is indexed using a number between 0..NUMBER_OF_MEMBERS-1
    index: usize,
    coeffs: [BnScalar; THRESHOLD],
    shares: [BnScalar; NUMBER_OF_MEMBERS],
    public_shares: [BnG1; NUMBER_OF_MEMBERS],
    member_public_keys: [BnG1; NUMBER_OF_MEMBERS],
    ciphers: [BnScalar; NUMBER_OF_MEMBERS],
    r: BnScalar,
    gr: BnG1,
    ga: BnG1,
    g2a: BnG2,
}

impl<const THRESHOLD: usize, const NUMBER_OF_MEMBERS: usize>
    DkgParams<THRESHOLD, NUMBER_OF_MEMBERS>
{
    pub fn new(index: usize, member_public_keys: &[BnG1], mut rng: impl RngCore) -> Self {
        assert!(index < NUMBER_OF_MEMBERS);
        assert_eq!(member_public_keys.len(), NUMBER_OF_MEMBERS);

        // generate random coefficients for polynomial
        let mut coeffs: Vec<_> = (0..THRESHOLD).map(|_| BnScalar::random(&mut rng)).collect();

        let g = BnG1::generator();
        let g2 = BnG2::generator();

        // compute main public coefficients
        let ga = (g * coeffs[0]).to_affine();
        let g2a = (g2 * coeffs[0]).to_affine();

        // compute secret shares for members
        let shares = compute_shares::<THRESHOLD, NUMBER_OF_MEMBERS>(&coeffs);
        let public_shares: Vec<_> = shares.iter().map(|s| (g * s).to_affine()).collect();

        // draw arandomness for encryption
        let r = BnScalar::random(&mut rng);
        let gr = (g * r).to_affine();

        // encrypt shares
        let poseidon = Hash::<_, P128Pow5T3Bn, ConstantLength<2>, 3, 2>::init();
        let mut ciphers = vec![];
        for i in 0..NUMBER_OF_MEMBERS {
            let pkr = (member_public_keys[i] * r).to_affine();
            let message = [mod_n::<BnG1>(pkr.x), mod_n::<BnG1>(pkr.y)];
            let key = poseidon.clone().hash(message);
            let cipher = key + shares[i];
            ciphers.push(cipher);
        }

        DkgParams {
            index,
            coeffs: coeffs
                .try_into()
                .expect("unable to convert coefficient vector"),
            shares,
            public_shares: public_shares
                .try_into()
                .expect("unable to convert public share vector"),
            member_public_keys: member_public_keys
                .try_into()
                .expect("unable to convert public key vector"),
            ciphers: ciphers.try_into().expect("unable to convert cipher vector"),
            r,
            gr,
            ga,
            g2a,
        }
    }

    pub fn get_dkg_circuit(
        &self,
        mut rng: impl RngCore,
    ) -> (CircuitDkg<THRESHOLD, NUMBER_OF_MEMBERS>, Vec<Vec<BnScalar>>) {
        let (rns_base, _) = setup::<BnG1>(0);
        let rns_base = Rc::new(rns_base);

        let ga_point = Point::new(Rc::clone(&rns_base), self.ga);
        let mut public_data = ga_point.public();

        let gr_point = Point::new(Rc::clone(&rns_base), self.gr);
        public_data.extend(gr_point.public());

        for i in 0..NUMBER_OF_MEMBERS {
            let gs_point = Point::new(Rc::clone(&rns_base), self.public_shares[i]);
            public_data.extend(gs_point.public());
        }

        for c in self.ciphers.iter() {
            public_data.push(*c);
        }

        // todo: replace with hash_to_curve
        let aux_generator = BnG1::random(&mut rng);
        let coeffs: Vec<_> = self.coeffs.iter().map(|a| Value::known(*a)).collect();
        let public_keys: Vec<_> = self
            .member_public_keys
            .iter()
            .map(|pk| Value::known(*pk))
            .collect();

        let circuit = CircuitDkg::<THRESHOLD, NUMBER_OF_MEMBERS>::new(
            coeffs,
            Value::known(self.r),
            public_keys,
            aux_generator,
            4,
        );
        let instance = vec![public_data];

        (circuit, instance)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2wrong::utils::{mock_prover_verify, DimensionMeasurement};
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    fn init_dkg_circuit<const THRESHOLD: usize, const NUMBER_OF_MEMBERS: usize>() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let g = BnG1::generator();

        let mut sks = vec![];
        let mut pks = vec![];
        for _ in 0..NUMBER_OF_MEMBERS {
            let sk = BnScalar::random(&mut rng);
            let pk = (g * sk).to_affine();

            sks.push(sk);
            pks.push(pk);
        }

        let dkg_params = DkgParams::<THRESHOLD, NUMBER_OF_MEMBERS>::new(1, &pks, &mut rng);
        let (circuit, instance) = dkg_params.get_dkg_circuit(&mut rng);
        mock_prover_verify(&circuit, instance);
        let dimension = DimensionMeasurement::measure(&circuit).unwrap();
        println!("dimention: {:?}", dimension);
    }

    #[test]
    fn test_dkg_circuit() {
        init_dkg_circuit::<4, 6>();
        init_dkg_circuit::<7, 13>();
    }
}
