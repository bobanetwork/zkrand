use crate::ecc_chip::point2_base_chip::{AuxGen, SplitBase};
use halo2wrong::curves::bn256::{Fq, Fq2, G2Affine};

const AUX_GENERATOR_X: Fq2 = Fq2 {
    c0: Fq::from_raw([
        0x52ae1752bfef0341,
        0x3eafccb9064851de,
        0x4254ea57f4d42897,
        0x09f8420d06b98979,
    ]),
    c1: Fq::from_raw([
        0x2539ba3aaf68dd60,
        0xcb7cb3129ef4c5be,
        0x9af0f58f79fa917f,
        0x0abc3efe977fbc31,
    ]),
};

const AUX_GENERATOR_Y: Fq2 = Fq2 {
    c0: Fq::from_raw([
        0x52d06d3250ae0d77,
        0x2d1f603c5980314e,
        0x65df3370b88dfe83,
        0x08f5aa2b908fe1da,
    ]),
    c1: Fq::from_raw([
        0x62c32645e3efa47d,
        0x643b45c796efc026,
        0x7a82d7da0d30c5d7,
        0x0532943195a597e4,
    ]),
};

const AUX_GENERATOR: G2Affine = G2Affine {
    x: AUX_GENERATOR_X,
    y: AUX_GENERATOR_Y,
};

impl SplitBase<Fq2, Fq> for G2Affine {
    fn split_base(base: Fq2) -> (Fq, Fq) {
        let c0 = base.c0;
        let c1 = base.c1;
        (c0, c1)
    }
}

impl AuxGen for G2Affine {
    fn aux_generator() -> Self {
        AUX_GENERATOR
    }
}

#[cfg(test)]
mod tests {
    use crate::ecc_chip::bn256::AUX_GENERATOR;
    use halo2wrong::curves::bn256::{Fq, Fq2, G2Affine};
    use halo2wrong::curves::group::cofactor::{CofactorCurveAffine, CofactorGroup};
    use halo2wrong::curves::CurveExt;
    use rand_chacha::ChaCha20Rng;
    use rand_core::{OsRng, SeedableRng};

    #[test]
    fn test_g2_aux_generator() {
        let h = AUX_GENERATOR.to_curve();
        assert!(bool::from(h.is_on_curve()));
        assert!(bool::from(h.is_torsion_free()));
    }

    #[test]
    #[ignore]
    fn test_g2_random() {
        //   let mut rng = ChaCha20Rng::seed_from_u64(42);
        let mut rng = OsRng;
        let h = G2Affine::random(&mut rng);
        let hh = h.to_curve();
        assert!(bool::from(hh.is_on_curve()));
        assert!(bool::from(hh.is_torsion_free()));

        println!("random h = {:?}", h);
    }
}
