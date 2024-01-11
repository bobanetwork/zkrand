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

    // generator
    // 0x1985b5324411a90c6204e1743b0b24d8a185890d7b3f47e198826ff8332addb2
    // 0x193340b18eb589e2ca74aef63bb4b57647cf2ec80a7e8035310ffe2ba96ea335
    const AUX_GENERATOR: G1Affine = G1Affine {
        x: Fq::from_raw([
            0x98826ff8332addb2,
            0xa185890d7b3f47e1,
            0x6204e1743b0b24d8,
            0x1985b5324411a90c,
        ]),
        y: Fq::from_raw([
            0x310ffe2ba96ea335,
            0x47cf2ec80a7e8035,
            0xca74aef63bb4b576,
            0x193340b18eb589e2,
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
