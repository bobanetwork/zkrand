use halo2_maingate::{
    AssignedCondition, AssignedValue, MainGate, MainGateConfig, MainGateInstructions,
};
use halo2wrong::curves::ff::PrimeField;
use halo2wrong::curves::grumpkin::{Fq as Base, G1Affine as Point};
use halo2wrong::curves::CurveAffine;
use halo2wrong::halo2::circuit::Layouter;
use halo2wrong::halo2::{circuit::Value, plonk::Error as PlonkError};
use halo2wrong::utils::decompose;
use halo2wrong::RegionCtx;

mod add;
mod mul;

#[derive(Clone, Debug)]
/// point that is assumed to be on curve and not infinity
pub struct AssignedPoint {
    pub(crate) x: AssignedValue<Base>,
    pub(crate) y: AssignedValue<Base>,
}

impl AssignedPoint {
    pub fn new(x: AssignedValue<Base>, y: AssignedValue<Base>) -> Self {
        Self { x, y }
    }

    pub fn x(&self) -> &AssignedValue<Base> {
        &self.x
    }

    pub fn y(&self) -> &AssignedValue<Base> {
        &self.y
    }

    pub fn value(&self) -> Value<Point> {
        self.x
            .value()
            .zip(self.y.value())
            .map(|(x, y)| Point { x: *x, y: *y })
    }
}

#[derive(Clone, Debug)]
pub struct GrumpkinChip {
    main_gate: MainGate<Base>,
    aux_generator: Option<AssignedPoint>,
    aux_correction: Option<AssignedPoint>,
}

impl GrumpkinChip {
    pub fn new(main_gate_config: MainGateConfig) -> Self {
        let main_gate = MainGate::<Base>::new(main_gate_config);
        Self {
            main_gate,
            aux_generator: None,
            aux_correction: None,
        }
    }

    pub fn main_gate(&self) -> &MainGate<Base> {
        &self.main_gate
    }

    pub fn curve_b() -> Base {
        Point::b()
    }

    pub fn expose_public(
        &self,
        mut layouter: impl Layouter<Base>,
        point: AssignedPoint,
        offset: &mut usize,
    ) -> Result<(), PlonkError> {
        let main_gate = self.main_gate();

        main_gate.expose_public(layouter.namespace(|| "x coord"), point.x().clone(), *offset)?;
        main_gate.expose_public(
            layouter.namespace(|| "y coord"),
            point.y().clone(),
            *offset + 1,
        )?;
        *offset += 2;

        Ok(())
    }

    pub fn assign_constant(
        &self,
        ctx: &mut RegionCtx<'_, Base>,
        point: Point,
    ) -> Result<AssignedPoint, PlonkError> {
        let main_gate = self.main_gate();
        let x = point.x;
        let y = point.y;

        let x_assigned = main_gate.assign_constant(ctx, x)?;
        let y_assigned = main_gate.assign_constant(ctx, y)?;
        let point = AssignedPoint::new(x_assigned, y_assigned);

        Ok(point)
    }

    pub fn assign_aux_generator(
        &mut self,
        ctx: &mut RegionCtx<'_, Base>,
        aux_generator: Value<Point>,
    ) -> Result<(), PlonkError> {
        let aux_generator_assigned = self.assign_point(ctx, aux_generator)?;
        self.aux_generator = Some(aux_generator_assigned);
        Ok(())
    }

    pub fn assign_aux_correction(
        &mut self,
        ctx: &mut RegionCtx<'_, Base>,
    ) -> Result<(), PlonkError> {
        match &self.aux_generator {
            Some(aux) => {
                let aux_correction = self.neg(ctx, aux)?;
                self.aux_correction = Some(aux_correction);
                Ok(())
            }
            // aux generator is not assigned yet
            None => Err(PlonkError::Synthesis),
        }
    }

    pub fn assign_point(
        &self,
        ctx: &mut RegionCtx<'_, Base>,
        point: Value<Point>,
    ) -> Result<AssignedPoint, PlonkError> {
        let main_gate = self.main_gate();
        let (x, y) = point.map(|point| (point.x, point.y)).unzip();

        let x = main_gate.assign_value(ctx, x)?;
        let y = main_gate.assign_value(ctx, y)?;
        let point = AssignedPoint::new(x, y);
        self.assert_is_on_curve(ctx, &point)?;
        Ok(point)
    }

    pub fn assert_is_on_curve(
        &self,
        ctx: &mut RegionCtx<'_, Base>,
        point: &AssignedPoint,
    ) -> Result<(), PlonkError> {
        let main_gate = self.main_gate();
        let x = point.x();
        let y = point.y();

        let y2 = main_gate.mul(ctx, y, y)?;
        let x2 = main_gate.mul(ctx, x, x)?;
        let x3 = main_gate.mul(ctx, &x2, x)?;
        let x3b = main_gate.add_constant(ctx, &x3, Self::curve_b())?;

        main_gate.assert_equal(ctx, &y2, &x3b)?;
        Ok(())
    }

    pub fn assert_equal(
        &self,
        ctx: &mut RegionCtx<'_, Base>,
        p0: &AssignedPoint,
        p1: &AssignedPoint,
    ) -> Result<(), PlonkError> {
        let main_gate = self.main_gate();
        main_gate.assert_equal(ctx, p0.x(), p1.x())?;
        main_gate.assert_equal(ctx, p0.y(), p1.y())
    }

    pub fn neg(
        &self,
        ctx: &mut RegionCtx<'_, Base>,
        p: &AssignedPoint,
    ) -> Result<AssignedPoint, PlonkError> {
        let main_gate = self.main_gate();
        let y_neg = main_gate.neg_with_constant(ctx, p.y(), Base::zero())?;
        Ok(AssignedPoint::new(p.x().clone(), y_neg))
    }

    // select p1 if c is true, or p2 if c is false
    pub fn select(
        &self,
        ctx: &mut RegionCtx<'_, Base>,
        c: &AssignedCondition<Base>,
        p1: &AssignedPoint,
        p2: &AssignedPoint,
    ) -> Result<AssignedPoint, PlonkError> {
        let main_gate = self.main_gate();
        let x = main_gate.select(ctx, p1.x(), p2.x(), c)?;
        let y = main_gate.select(ctx, p1.y(), p2.y(), c)?;

        Ok(AssignedPoint::new(x, y))
    }

    pub fn select_or_assign(
        &self,
        ctx: &mut RegionCtx<'_, Base>,
        c: &AssignedCondition<Base>,
        p1: &AssignedPoint,
        p2: Point,
    ) -> Result<AssignedPoint, PlonkError> {
        let main_gate = self.main_gate();
        let x = main_gate.select_or_assign(ctx, p1.x(), p2.x, c)?;
        let y = main_gate.select_or_assign(ctx, p1.y(), p2.y, c)?;
        Ok(AssignedPoint::new(x, y))
    }

    pub fn to_bits(
        &self,
        ctx: &mut RegionCtx<'_, Base>,
        value: &AssignedValue<Base>,
    ) -> Result<Vec<AssignedCondition<Base>>, PlonkError> {
        let main_gate = self.main_gate();
        let decomposed = main_gate.to_bits(ctx, value, Base::NUM_BITS as usize)?;

        Ok(decomposed)
    }

    // convert into bits without checking the bits compose back to the original value
    pub fn to_bits_unsafe(
        &self,
        ctx: &mut RegionCtx<'_, Base>,
        value: &Value<Base>,
    ) -> Result<Vec<AssignedCondition<Base>>, PlonkError> {
        let main_gate = self.main_gate();
        let number_of_bits = Base::NUM_BITS as usize;

        let decomposed_value = value.map(|value| decompose(value, number_of_bits, 1));

        let bits: Vec<_> = (0..number_of_bits)
            .map(|i| {
                let bit = decomposed_value.as_ref().map(|bits| bits[i]);
                let bit = main_gate.assign_bit(ctx, bit)?;
                Ok(bit)
            })
            .collect::<Result<Vec<_>, PlonkError>>()?;

        Ok(bits)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2wrong::curves::ff::PrimeField;
    use halo2wrong::curves::group::Curve;
    use halo2wrong::curves::grumpkin::Fr as Scalar;

    use halo2wrong::halo2::arithmetic::Field;
    use halo2wrong::halo2::circuit::SimpleFloorPlanner;
    use halo2wrong::halo2::plonk::{Circuit, ConstraintSystem};
    use halo2wrong::utils::{mock_prover_verify, DimensionMeasurement};
    use rand_chacha::ChaCha20Rng;
    use rand_core::{OsRng, SeedableRng};

    #[derive(Clone, Debug, Default)]
    struct TestGrumpkin;

    impl Circuit<Base> for TestGrumpkin {
        type Config = MainGateConfig;
        type FloorPlanner = SimpleFloorPlanner;
        #[cfg(feature = "circuit-params")]
        type Params = ();

        fn without_witnesses(&self) -> Self {
            unimplemented!();
        }

        fn configure(meta: &mut ConstraintSystem<Base>) -> Self::Config {
            MainGate::<Base>::configure(meta)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Base>,
        ) -> Result<(), PlonkError> {
            let mut ecc = GrumpkinChip::new(config);
            layouter.assign_region(
                || "region point",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);

                    // let mut rng = ChaCha20Rng::seed_from_u64(42);
                    let mut rng = OsRng;

                    let p0 = Point::random(&mut rng);
                    let p1 = Point::random(&mut rng);

                    let add = (p0 + p1).to_affine();
                    let double = (p0 + p0).to_affine();

                    let p0_assigned = &ecc.assign_point(ctx, Value::known(p0))?;
                    let p1_assigned = &ecc.assign_point(ctx, Value::known(p1))?;
                    let add_assigned = ecc.assign_point(ctx, Value::known(add))?;
                    let double_assigned = ecc.assign_point(ctx, Value::known(double))?;

                    let r = Base::random(&mut rng);
                    let r_value = Value::known(r);
                    // base can fit in scalar for Grumpkin
                    let rr = Scalar::from_repr(r.to_repr()).unwrap();
                    let mul = (p0 * rr).to_affine();
                    let mul_assigned = ecc.assign_point(ctx, Value::known(mul))?;

                    let aux = Point::random(&mut rng);
                    ecc.assign_aux_generator(ctx, Value::known(aux))?;
                    ecc.assign_aux_correction(ctx)?;

                    let main_gate = ecc.main_gate();

                    // test point addition incomplete
                    {
                        let d = ecc.add_incomplete(ctx, p0_assigned, p1_assigned)?;
                        ecc.assert_equal(ctx, &add_assigned, &d)?;
                    }

                    // test point addition
                    {
                        let d = ecc.add(ctx, p0_assigned, p1_assigned)?;
                        ecc.assert_equal(ctx, &add_assigned, &d)?;
                    }

                    // test point incomplete double
                    {
                        let d = ecc.double_incomplete(ctx, p0_assigned)?;
                        ecc.assert_equal(ctx, &double_assigned, &d)?;
                    }

                    // test point double
                    {
                        let d = ecc.double(ctx, p0_assigned)?;
                        ecc.assert_equal(ctx, &double_assigned, &d)?;
                    }

                    // test mul
                    {
                        let r_assigned = &main_gate.assign_value(ctx, r_value)?;
                        let d = ecc.mul(ctx, p0_assigned, r_assigned)?;
                        ecc.assert_equal(ctx, &mul_assigned, &d)?;
                    }

                    // test mul bits
                    {
                        let bits = ecc.to_bits_unsafe(ctx, &r_value)?;
                        let d = ecc.mul_bits(ctx, p0_assigned, &bits)?;
                        ecc.assert_equal(ctx, &mul_assigned, &d)?;
                    }

                    Ok(())
                },
            )?;

            Ok(())
        }
    }

    #[test]
    fn test_grumpkin_chip() {
        let circuit = TestGrumpkin;
        let instance = vec![vec![]];

        mock_prover_verify(&circuit, instance);
    }

    #[derive(Clone, Debug, Default)]
    struct TestMul;

    impl Circuit<Base> for TestMul {
        type Config = MainGateConfig;
        type FloorPlanner = SimpleFloorPlanner;
        #[cfg(feature = "circuit-params")]
        type Params = ();

        fn without_witnesses(&self) -> Self {
            unimplemented!();
        }

        fn configure(meta: &mut ConstraintSystem<Base>) -> Self::Config {
            MainGate::<Base>::configure(meta)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Base>,
        ) -> Result<(), PlonkError> {
            let mut ecc = GrumpkinChip::new(config);

            let mut rng = OsRng;

            let p0 = Point::random(&mut rng);
            let r = Base::random(&mut rng);
            let aux = Point::random(&mut rng);

            layouter.assign_region(
                || "region aux generator",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);

                    ecc.assign_aux_generator(ctx, Value::known(aux))?;
                    ecc.assign_aux_correction(ctx)?;

                    Ok(())
                },
            )?;

            layouter.assign_region(
                || "region point mul",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);

                    let p0_assigned = &ecc.assign_point(ctx, Value::known(p0))?;
                    let bits = ecc.to_bits_unsafe(ctx, &Value::known(r))?;
                    let _d = ecc.mul_bits(ctx, p0_assigned, &bits)?;

                    Ok(())
                },
            )?;

            Ok(())
        }
    }

    #[test]
    fn test_grumpkin_mul() {
        let circuit = TestMul;
        let instance = vec![vec![]];

        let dimension = DimensionMeasurement::measure(&circuit).unwrap();
        println!("\n\ndimension = {:?}", dimension);

        mock_prover_verify(&circuit, instance);
    }
}
