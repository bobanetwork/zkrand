use crate::ecc_chip::integer2::Integer2Chip;
use crate::ecc_chip::point2::AssignedPoint2;
use halo2_ecc::halo2::halo2curves::ff::PrimeField;
use halo2_ecc::integer::rns::Rns;
use halo2_ecc::integer::IntegerConfig;

use halo2_maingate::{AssignedCondition, MainGate, MainGateInstructions};
use halo2wrong::curves::group::cofactor::{CofactorCurveAffine, CofactorGroup};
use halo2wrong::curves::CurveAffine;
use halo2wrong::halo2::circuit::Layouter;
use halo2wrong::halo2::plonk::Error as PlonkError;
use halo2wrong::RegionCtx;
use std::rc::Rc;

mod add;
mod fix_mul;

pub trait SplitBase<B, W: PrimeField> {
    fn split_base(base: B) -> (W, W);
}

pub trait AuxGen {
    fn aux_generator() -> Self;
}

// windowed fix point multiplication
pub struct FixedPoint2Chip<
    W: PrimeField,
    C: CurveAffine + CofactorCurveAffine + SplitBase<C::Base, W> + AuxGen,
    const NUMBER_OF_LIMBS: usize,
    const BIT_LEN_LIMB: usize,
> {
    integer2_chip: Integer2Chip<W, C::ScalarExt, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    assigned_table:
        Option<Vec<Vec<AssignedPoint2<W, C::ScalarExt, NUMBER_OF_LIMBS, BIT_LEN_LIMB>>>>,
    window_size: Option<usize>,
}

impl<
        W: PrimeField,
        C: CurveAffine + CofactorCurveAffine + SplitBase<C::Base, W> + AuxGen,
        const NUMBER_OF_LIMBS: usize,
        const BIT_LEN_LIMB: usize,
    > FixedPoint2Chip<W, C, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
{
    pub fn new(config: IntegerConfig) -> Self {
        Self {
            integer2_chip: Integer2Chip::new(config, Rc::new(Rns::construct())),
            assigned_table: None,
            window_size: None,
        }
    }

    pub fn rns(&self) -> Rc<Rns<W, C::ScalarExt, NUMBER_OF_LIMBS, BIT_LEN_LIMB>> {
        self.integer2_chip.rns()
    }

    pub fn integer2_chip(&self) -> &Integer2Chip<W, C::ScalarExt, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        &self.integer2_chip
    }

    pub fn main_gate(&self) -> &MainGate<C::ScalarExt> {
        self.integer2_chip.main_gate()
    }
}

impl<
        W: PrimeField,
        C: CurveAffine + CofactorCurveAffine + SplitBase<C::Base, W> + AuxGen,
        const NUMBER_OF_LIMBS: usize,
        const BIT_LEN_LIMB: usize,
    > FixedPoint2Chip<W, C, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
{
    pub fn expose_public(
        &self,
        mut layouter: impl Layouter<C::ScalarExt>,
        point: AssignedPoint2<W, C::ScalarExt, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        offset: usize,
    ) -> Result<(), PlonkError> {
        let main_gate = self.main_gate();

        let x0 = &point.x().i0;
        let x1 = &point.x().i1;
        let y0 = &point.y().i0;
        let y1 = &point.y().i1;

        let mut offset = offset;
        for a in [x0, x1, y0, y1] {
            for limb in a.limbs().iter() {
                main_gate.expose_public(layouter.namespace(|| "x coords"), limb.into(), offset)?;
                offset += 1;
            }
        }

        Ok(())
    }

    pub fn assign_constant(
        &self,
        ctx: &mut RegionCtx<'_, C::ScalarExt>,
        point: C,
    ) -> Result<AssignedPoint2<W, C::ScalarExt, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, PlonkError> {
        // point is on curve
        assert!(bool::from(point.is_on_curve()));
        // point is in subgroup
        assert!(bool::from(
            CofactorCurveAffine::to_curve(&point).is_torsion_free()
        ));
        // disallow point of infinity
        let coords = point.coordinates().unwrap();

        let integer2_chip = self.integer2_chip();
        let x_split = C::split_base(*coords.x());
        let y_split = C::split_base(*coords.y());
        let x = integer2_chip.assign_constant(ctx, x_split)?;
        let y = integer2_chip.assign_constant(ctx, y_split)?;
        Ok(AssignedPoint2 { x, y })
    }

    pub fn assert_equal(
        &self,
        ctx: &mut RegionCtx<'_, C::ScalarExt>,
        p0: &AssignedPoint2<W, C::ScalarExt, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        p1: &AssignedPoint2<W, C::ScalarExt, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<(), PlonkError> {
        let integer2_chip = self.integer2_chip();
        integer2_chip.assert_equal(ctx, p0.x(), p1.x())?;
        integer2_chip.assert_equal(ctx, p0.y(), p1.y())
    }

    pub fn select(
        &self,
        ctx: &mut RegionCtx<'_, C::ScalarExt>,
        c: &AssignedCondition<C::ScalarExt>,
        p1: &AssignedPoint2<W, C::ScalarExt, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        p2: &AssignedPoint2<W, C::ScalarExt, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedPoint2<W, C::ScalarExt, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, PlonkError> {
        let integer2_chip = self.integer2_chip();
        let x = integer2_chip.select(ctx, p1.x(), p2.x(), c)?;
        let y = integer2_chip.select(ctx, p1.y(), p2.y(), c)?;
        Ok(AssignedPoint2 { x, y })
    }

    pub fn normalize(
        &self,
        ctx: &mut RegionCtx<'_, C::ScalarExt>,
        point: &AssignedPoint2<W, C::ScalarExt, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedPoint2<W, C::ScalarExt, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, PlonkError> {
        let integer2_chip = self.integer2_chip();
        let x = integer2_chip.reduce(ctx, point.x())?;
        let y = integer2_chip.reduce(ctx, point.y())?;
        Ok(AssignedPoint2 { x, y })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecc_chip::point2_base_chip::{FixedPoint2Chip, SplitBase};
    use crate::{BIT_LEN_LIMB, NUMBER_OF_LIMBS};
    use halo2_ecc::halo2::halo2curves::group::cofactor::CofactorCurveAffine;
    use halo2_ecc::integer::rns::Rns;
    use halo2_ecc::integer::IntegerConfig;
    use halo2_maingate::{
        MainGate, MainGateConfig, MainGateInstructions, RangeChip, RangeConfig, RangeInstructions,
    };
    use halo2wrong::curves::ff::PrimeField;
    use halo2wrong::curves::CurveAffine;
    use halo2wrong::halo2::arithmetic::Field;
    use halo2wrong::halo2::circuit::{Layouter, SimpleFloorPlanner, Value};
    use halo2wrong::halo2::plonk::{Circuit, ConstraintSystem};
    use halo2wrong::RegionCtx;
    use rand_chacha::ChaCha20Rng;
    use rand_core::{OsRng, SeedableRng};
    use std::marker::PhantomData;

    #[derive(Clone, Debug)]
    struct TestCircuitConfig<W: PrimeField> {
        main_gate_config: MainGateConfig,
        range_config: RangeConfig,
        _marker: PhantomData<W>,
    }

    impl<W: PrimeField> TestCircuitConfig<W> {
        fn integer_config(&self) -> IntegerConfig {
            IntegerConfig::new(self.range_config.clone(), self.main_gate_config.clone())
        }

        fn new<C: CurveAffine>(meta: &mut ConstraintSystem<C::ScalarExt>) -> Self {
            let rns = Rns::<W, C::ScalarExt, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::construct();

            let main_gate_config = MainGate::<C::ScalarExt>::configure(meta);
            let overflow_bit_lens = rns.overflow_lengths();
            let composition_bit_lens = vec![BIT_LEN_LIMB / NUMBER_OF_LIMBS];

            let range_config = RangeChip::<C::ScalarExt>::configure(
                meta,
                &main_gate_config,
                composition_bit_lens,
                overflow_bit_lens,
            );

            TestCircuitConfig {
                main_gate_config,
                range_config,
                _marker: PhantomData,
            }
        }

        fn config_range<N: PrimeField>(
            &self,
            layouter: &mut impl Layouter<N>,
        ) -> Result<(), PlonkError> {
            let range_chip = RangeChip::<N>::new(self.range_config.clone());
            range_chip.load_table(layouter)?;

            Ok(())
        }
    }

    #[derive(Default, Clone, Debug)]
    struct TestEccAdd<
        W: PrimeField,
        C: CurveAffine + CofactorCurveAffine + SplitBase<C::Base, W> + AuxGen,
    > {
        g: C::CurveExt,
        h: C::CurveExt,
        _marker: PhantomData<W>,
    }

    impl<W: PrimeField, C: CurveAffine + CofactorCurveAffine + SplitBase<C::Base, W> + AuxGen>
        Circuit<C::ScalarExt> for TestEccAdd<W, C>
    {
        type Config = TestCircuitConfig<W>;
        type FloorPlanner = SimpleFloorPlanner;
        #[cfg(feature = "circuit-params")]
        type Params = ();

        fn without_witnesses(&self) -> Self {
            unimplemented!();
        }

        fn configure(meta: &mut ConstraintSystem<C::ScalarExt>) -> Self::Config {
            TestCircuitConfig::new::<C>(meta)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<C::ScalarExt>,
        ) -> Result<(), PlonkError> {
            let integer_config = config.integer_config();
            let fixed_chip =
                FixedPoint2Chip::<W, C, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::new(integer_config);

            let g = self.g;
            let h = self.h;

            let add = g + h;
            let double = g + g;

            let (g_assigned, h_assigned) = layouter.assign_region(
                || "region constant points",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);

                    let g_assigned = fixed_chip.assign_constant(ctx, g.into())?;
                    let h_assigned = fixed_chip.assign_constant(ctx, h.into())?;

                    Ok((g_assigned, h_assigned))
                },
            )?;

            layouter.assign_region(
                || "region add",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);

                    let result0 = fixed_chip.assign_constant(ctx, add.into())?;
                    let result1 = fixed_chip.add(ctx, &g_assigned, &h_assigned)?;
                    let result2 = fixed_chip.add_incomplete(ctx, &g_assigned, &h_assigned)?;

                    fixed_chip.assert_equal(ctx, &result0, &result1)?;
                    fixed_chip.assert_equal(ctx, &result0, &result2)?;

                    Ok(())
                },
            )?;

            layouter.assign_region(
                || "region double",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);

                    let result0 = fixed_chip.assign_constant(ctx, double.into())?;
                    let result1 = fixed_chip.double(ctx, &g_assigned)?;
                    let result2 = fixed_chip.double_incomplete(ctx, &g_assigned)?;

                    fixed_chip.assert_equal(ctx, &result0, &result1)?;
                    fixed_chip.assert_equal(ctx, &result0, &result2)?;

                    Ok(())
                },
            )?;

            config.config_range(&mut layouter)?;

            Ok(())
        }
    }

    #[derive(Default, Clone, Debug)]
    struct TestEccMulFix<
        W: PrimeField,
        C: CurveAffine + CofactorCurveAffine + SplitBase<C::Base, W> + AuxGen,
    > {
        window_size: usize,
        scalar: C::ScalarExt,
        generator: C,
        _marker: PhantomData<W>,
    }

    impl<W: PrimeField, C: CurveAffine + CofactorCurveAffine + SplitBase<C::Base, W> + AuxGen>
        Circuit<C::ScalarExt> for TestEccMulFix<W, C>
    {
        type Config = TestCircuitConfig<W>;
        type FloorPlanner = SimpleFloorPlanner;
        #[cfg(feature = "circuit-params")]
        type Params = ();

        fn without_witnesses(&self) -> Self {
            unimplemented!();
        }

        fn configure(meta: &mut ConstraintSystem<C::ScalarExt>) -> Self::Config {
            TestCircuitConfig::new::<C>(meta)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<C::ScalarExt>,
        ) -> Result<(), PlonkError> {
            let integer_config = config.integer_config();
            let mut fixed_chip =
                FixedPoint2Chip::<W, C, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::new(integer_config);
            let main_gate = MainGate::<C::ScalarExt>::new(config.main_gate_config.clone());

            let g = self.generator;
            let s = self.scalar;

            layouter.assign_region(
                || "assign fixed point window table",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    fixed_chip.assign_fixed_point(ctx, &g, self.window_size)?;
                    Ok(())
                },
            )?;

            let out = layouter.assign_region(
                || "region mul",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);

                    let s = main_gate.assign_value(ctx, Value::known(s))?;
                    let result = fixed_chip.mul(ctx, &s)?;
                    let out = fixed_chip.normalize(ctx, &result)?;

                    Ok(out)
                },
            )?;

            fixed_chip.expose_public(layouter.namespace(|| "g2^s"), out, 0)?;

            config.config_range(&mut layouter)?;

            Ok(())
        }
    }

    use crate::ecc_chip::point2::Point2;
    use halo2wrong::curves::bn256::{Fq, Fr, G2Affine, G2};
    use halo2wrong::curves::group::{Curve, Group};
    use halo2wrong::utils::{mock_prover_verify, DimensionMeasurement};

    #[test]
    fn test_bn_add2() {
        //let mut rng = ChaCha20Rng::seed_from_u64(42);
        let mut rng = OsRng;

        let g = G2::random(&mut rng);
        let h = G2::random(&mut rng);
        let circuit = TestEccAdd::<Fq, G2Affine> {
            g,
            h,
            _marker: PhantomData,
        };
        let instance = vec![vec![]];
        mock_prover_verify(&circuit, instance);
    }

    #[test]
    fn test_bn_mul_fix2() {
        //let mut rng = ChaCha20Rng::seed_from_u64(42);
        let mut rng = OsRng;

        let rns = Rns::<Fq, Fr, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::construct();
        let rns = Rc::new(rns);

        for window_size in 2..6 {
            let s = Fr::random(&mut rng);
            let g = G2Affine::random(&mut rng);
            let gs = (g * s).to_affine();
            let public_data = Point2::new(rns.clone(), gs).public();

            let circuit = TestEccMulFix {
                window_size: window_size,
                scalar: s,
                generator: g,
                _marker: PhantomData,
            };
            let instance = vec![public_data];
            mock_prover_verify(&circuit, instance);

            let dimension = DimensionMeasurement::measure(&circuit).unwrap();
            println!("window size: {:?}, mul fix: {:?}", window_size, dimension);
        }
    }
}
