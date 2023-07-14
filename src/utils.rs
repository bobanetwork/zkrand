use halo2_ecc::integer::rns::Rns;
use halo2wrong::curves::{bn256, grumpkin, CurveAffine, CurveExt};
use halo2wrong::utils::{big_to_fe, fe_to_big};

use crate::hash_to_curve::svdw_hash_to_curve;
use crate::{BIT_LEN_LIMB, NUMBER_OF_LIMBS, NUMBER_OF_LOOKUP_LIMBS};

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

pub fn hash_to_curve_bn<'a>(domain_prefix: &'a str) -> Box<dyn Fn(&[u8]) -> bn256::G1 + 'a> {
    svdw_hash_to_curve::<bn256::G1>(
        "bn256_g1",
        domain_prefix,
        <bn256::G1 as CurveExt>::Base::one(),
    )
}

pub fn hash_to_curve_grumpkin<'a>(
    domain_prefix: &'a str,
) -> Box<dyn Fn(&[u8]) -> grumpkin::G1 + 'a> {
    svdw_hash_to_curve::<grumpkin::G1>(
        "grumpkin_g1",
        domain_prefix,
        <grumpkin::G1 as CurveExt>::Base::one(),
    )
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_to_curve() {
        let hasher = hash_to_curve_bn("another generator");
        let h = hasher(b"second generator h");
        assert!(bool::from(h.is_on_curve()));

        let hasher = hash_to_curve_grumpkin("another generator");
        let h = hasher(b"second generator h");
        assert!(bool::from(h.is_on_curve()));
    }
}
