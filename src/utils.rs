use halo2_ecc::integer::rns::Rns;
use halo2wrong::curves::bn256::Fr as BnScalar;
use halo2wrong::curves::CurveAffine;
use halo2wrong::utils::{big_to_fe, fe_to_big};

use crate::{BIT_LEN_LIMB, NUMBER_OF_LIMBS, NUMBER_OF_LOOKUP_LIMBS, NUMBER_OF_MEMBERS, THRESHOLD};

pub fn mod_n<C: CurveAffine>(x: C::Base) -> C::Scalar {
    let x_big = fe_to_big(x);
    big_to_fe(x_big)
}

pub fn rns<C: CurveAffine>() -> Rns<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
    Rns::construct()
}

pub fn setup<C: CurveAffine>(
    k_override: u32,
) -> (Rns<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, u32) {
    let rns = rns::<C>();
    let bit_len_lookup = BIT_LEN_LIMB / NUMBER_OF_LOOKUP_LIMBS;
    let mut k: u32 = (bit_len_lookup + 1) as u32;
    if k_override != 0 {
        k = k_override;
    }
    (rns, k)
}

/*
#[allow(clippy::type_complexity)]
fn setup<
    C: CurveAffine,
    N: PrimeField,
    const NUMBER_OF_LIMBS: usize,
    const BIT_LEN_LIMB: usize,
>(
    k_override: u32,
) -> (
    Rns<C::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    Rns<C::Scalar, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    u32,
) {
    let (rns_base, rns_scalar) = GeneralEccChip::<C, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::rns();
    let bit_len_lookup = BIT_LEN_LIMB / NUMBER_OF_LOOKUP_LIMBS;
    let mut k: u32 = (bit_len_lookup + 1) as u32;
    if k_override != 0 {
        k = k_override;
    }
    (rns_base, rns_scalar, k)
}

 */

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

// create secret shares for n parties
pub fn create_shares(coeffs: &[BnScalar]) -> [BnScalar; NUMBER_OF_MEMBERS] {
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
