mod fix_mul;
pub use fix_mul::FixedPointChip;

use halo2wrong::curves::bn256::{Fq as Base, G1Affine as Point};

pub const AUX_GENERATOR: Point = Point {
    x: Base::from_raw([
        0xc552bb41dfa2ba0d,
        0x691f7d5660b8fa62,
        0xbee345f4407f92ee,
        0x16097d51a463fa51,
    ]),
    y: Base::from_raw([
        0x5bed59dd2ef9fb53,
        0xa0f30dda198abe8b,
        0x82ba6900b8e98ee8,
        0x1be3e56d90c3a2cb,
    ]),
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash_to_curve_bn;
    use halo2wrong::curves::bn256::{Fq as Base, Fr as Scalar, G1Affine as Point};
    use halo2wrong::curves::{group::Curve, CurveAffine};

    #[test]
    fn test_bn_aux_generator() {
        let hasher = hash_to_curve_bn("another generator for Bn256 curve");
        let input = b"auxiliary generator reserved for scalar multiplication; please do not use it for anything else";
        let h: Point = hasher(input).to_affine();
        assert!(bool::from(h.is_on_curve()));

        assert_eq!(h, AUX_GENERATOR);
    }
}
