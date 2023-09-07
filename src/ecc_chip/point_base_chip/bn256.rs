use crate::ecc_chip::point_base_chip::AuxGen;
use crate::hash_to_curve_bn;
use halo2wrong::curves::bn256::G1Affine;
use halo2wrong::curves::group::Curve;

impl AuxGen for G1Affine {
    fn aux_generator(bytes: &[u8]) -> Self {
        let hasher =
            hash_to_curve_bn("auxiliary generator for windowed scalar multiplication on bn256");
        let aux_generator = hasher(bytes).to_affine();
        aux_generator
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash_to_curve_bn;
    use halo2wrong::curves::bn256::Fq;
    use halo2wrong::curves::CurveAffine;

    const AUX_GENERATOR: G1Affine = G1Affine {
        x: Fq::from_raw([
            0xc552bb41dfa2ba0d,
            0x691f7d5660b8fa62,
            0xbee345f4407f92ee,
            0x16097d51a463fa51,
        ]),
        y: Fq::from_raw([
            0x5bed59dd2ef9fb53,
            0xa0f30dda198abe8b,
            0x82ba6900b8e98ee8,
            0x1be3e56d90c3a2cb,
        ]),
    };

    #[test]
    fn test_bn_aux_generator() {
        let hasher = hash_to_curve_bn("another generator for Bn256 curve");
        let input = b"auxiliary generator reserved for scalar multiplication; please do not use it for anything else";
        let h: G1Affine = hasher(input).to_affine();
        assert!(bool::from(h.is_on_curve()));

        assert_eq!(h, AUX_GENERATOR);
    }
}
