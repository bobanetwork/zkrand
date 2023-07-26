use crate::base_field_chip::AUX_GENERATOR;
use halo2_ecc::integer::IntegerInstructions;
use halo2_ecc::{AssignedPoint, BaseFieldEccChip};
use halo2_maingate::{AssignedCondition, AssignedValue, MainGate, MainGateInstructions};
use halo2wrong::curves::bn256::{Fq as Base, Fr as Scalar, G1Affine as Point};
use halo2wrong::curves::ff::{Field, PrimeField};
use halo2wrong::curves::group::Curve;
use halo2wrong::curves::CurveAffine;
use halo2wrong::halo2::plonk::Error as PlonkError;
use halo2wrong::RegionCtx;

// windowed fix point multiplication
pub struct FixedPointChip<const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize> {
    ecc_chip: BaseFieldEccChip<Point, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    assigned_fixed_point: Option<AssignedPoint<Base, Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>>,
    assigned_table: Option<Vec<Vec<AssignedPoint<Base, Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>>>>,
    assigned_correction: Option<AssignedPoint<Base, Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>>,
    window_size: Option<usize>,
}

impl<const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize>
    FixedPointChip<NUMBER_OF_LIMBS, BIT_LEN_LIMB>
{
    pub fn new(ecc_chip: BaseFieldEccChip<Point, NUMBER_OF_LIMBS, BIT_LEN_LIMB>) -> Self {
        Self {
            ecc_chip,
            assigned_fixed_point: None,
            assigned_table: None,
            assigned_correction: None,
            window_size: None,
        }
    }

    pub fn base_field_chip(&self) -> &BaseFieldEccChip<Point, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        &self.ecc_chip
    }

    pub fn main_gate(&self) -> &MainGate<Scalar> {
        self.ecc_chip.main_gate()
    }

    fn prepare_fixed_point_table(
        window_size: usize,
        fixed_point: &Point,
    ) -> (Vec<Vec<Point>>, Point) {
        // The algorithm cannot be applied when the window_size = 1 due to the lack of monotonicity.
        assert!(window_size > 1);

        let num_bits = Scalar::NUM_BITS as usize;
        let n = (num_bits + window_size - 1) / window_size;
        let mut last = num_bits % window_size;
        if last == 0 {
            last = window_size;
        }
        let window: usize = 1 << window_size;
        let window_last: usize = 1 << last;

        // for the first n-1 rows T[0..(n−1))[0..2^w): T[i][k]=[(k+2)⋅(2^w)^i]P
        let mut t = vec![];
        for k in 0..window {
            let k2 = Scalar::from((k + 2) as u64);
            let p = (fixed_point * &k2).to_affine();
            t.push(p);
        }

        let mut table = vec![t];

        for i in 1..n - 1 {
            let mut t = vec![];
            for k in 0..window {
                let mut p = table[i - 1][k].clone();
                for _ in 0..window_size {
                    p = (p + p).to_affine();
                }
                t.push(p);
            }
            table.push(t);
        }

        // for the last row, we use auxiliary generator:
        // the last row has 2^last elements instead of 2^window
        // T[n-1][k]=[(k+2)⋅(2^w)^{n-1}]P + aux
        let mut t = vec![];
        for k in 0..window_last {
            let mut p = table[n - 2][k].clone();
            for _ in 0..window_size {
                p = (p + p).to_affine();
            }
            p = (p + AUX_GENERATOR).to_affine();
            t.push(p);
        }

        table.push(t);

        // compute the correction point
        // C = [\sum_{j=0}^{n-1} 2^{wj+1}]B + [1+2^w]aux
        let mut correction = table[0][0];
        for i in 1..n {
            correction = (&correction + &table[i][0]).to_affine();
        }

        (table, -correction)
    }

    // algorithm from https://github.com/privacy-scaling-explorations/halo2wrong/blob/v2023_04_20/ecc/src/base_field_ecc/add.rs#L17
    fn add_incomplete(
        &self,
        ctx: &mut RegionCtx<'_, Scalar>,
        a: &AssignedPoint<Base, Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        b: &AssignedPoint<Base, Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedPoint<Base, Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, PlonkError> {
        let ecc_chip = self.base_field_chip();
        let ch = ecc_chip.integer_chip();

        // lambda = b_y - a_y / b_x - a_x
        let numerator = &ch.sub(ctx, &b.y(), &a.y())?;
        let denominator = &ch.sub(ctx, &b.x(), &a.x())?;

        let lambda = &ch.div_incomplete(ctx, numerator, denominator)?;

        // c_x =  lambda * lambda - a_x - b_x
        let lambda_square = &ch.square(ctx, lambda)?;
        let x = &ch.sub_sub(ctx, lambda_square, &a.x(), &b.x())?;

        // c_y = lambda * (a_x - c_x) - a_y
        let t = &ch.sub(ctx, &a.x(), x)?;
        let t = &ch.mul(ctx, t, lambda)?;
        let y = ch.sub(ctx, t, &a.y())?;

        let p_0 = AssignedPoint::new(x.clone(), y);

        Ok(p_0)
    }

    pub fn assign_fixed_point(
        &mut self,
        ctx: &mut RegionCtx<'_, Scalar>,
        fixed_point: &Point,
        window_size: usize,
    ) -> Result<(), PlonkError> {
        if !bool::from(fixed_point.is_on_curve()) {
            return Err(PlonkError::Synthesis);
        };

        let (table, correction) = Self::prepare_fixed_point_table(window_size, &fixed_point);

        // check if the last row is on curve
        for p in table[table.len() - 1].iter() {
            if !bool::from(p.is_on_curve()) {
                return Err(PlonkError::Synthesis);
            };
        }

        if !bool::from(correction.is_on_curve()) {
            return Err(PlonkError::Synthesis);
        };

        let mut assigned_table = vec![];
        let ecc_chip = self.base_field_chip();
        for t in table.iter() {
            let mut assigned_t = vec![];
            for p in t.iter() {
                let ap = ecc_chip.assign_constant(ctx, p.clone())?;
                assigned_t.push(ap);
            }
            assigned_table.push(assigned_t);
        }

        let assigned_fixed_point = ecc_chip.assign_constant(ctx, fixed_point.clone())?;
        let assigned_correction = ecc_chip.assign_constant(ctx, correction)?;

        self.assigned_fixed_point = Some(assigned_fixed_point);
        self.assigned_table = Some(assigned_table);
        self.assigned_correction = Some(assigned_correction);
        self.window_size = Some(window_size);

        Ok(())
    }

    // algorithm from https://github.com/privacy-scaling-explorations/halo2wrong/blob/v2023_04_20/ecc/src/base_field_ecc/mul.rs#L69
    fn select_multi(
        &self,
        ctx: &mut RegionCtx<'_, Scalar>,
        selector: &[AssignedCondition<Scalar>],
        table: &[AssignedPoint<Base, Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>],
    ) -> Result<AssignedPoint<Base, Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, PlonkError> {
        let number_of_points = table.len();
        let number_of_selectors = selector.len();
        assert_eq!(number_of_points, 1 << number_of_selectors);

        let ecc_chip = self.base_field_chip();
        let mut reducer = table.to_vec();
        for (i, selector) in selector.iter().enumerate() {
            let n = 1 << (number_of_selectors - 1 - i);
            for j in 0..n {
                let k = 2 * j;
                reducer[j] = ecc_chip.select(ctx, selector, &reducer[k + 1], &reducer[k])?;
            }
        }
        Ok(reducer[0].clone())
    }

    pub fn mul(
        &self,
        ctx: &mut RegionCtx<'_, Scalar>,
        scalar: &AssignedValue<Scalar>,
    ) -> Result<AssignedPoint<Base, Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, PlonkError> {
        let num_bits = Scalar::NUM_BITS as usize;
        let window_size = match self.window_size {
            Some(w) => Ok(w),
            None => Err(PlonkError::Synthesis),
        }?;
        let n = (num_bits + window_size - 1) / window_size;
        let mut last = num_bits % window_size;
        if last == 0 {
            last = window_size;
        }
        let table = match &self.assigned_table {
            Some(table) => Ok(table),
            None => Err(PlonkError::Synthesis),
        }?;

        assert_eq!(n, table.len());
        assert_eq!(1 << last, table[n - 1].len());

        let main_gate = self.main_gate();
        let decomposed = &main_gate.to_bits(ctx, scalar, num_bits)?;

        // add_incomplete for the first n-1 rows
        let mut acc = {
            let selector = &decomposed[0..window_size];
            self.select_multi(ctx, selector, &table[0])?
        };

        let mut begin = window_size;
        let mut end = begin + window_size;
        for i in 1..n - 1 {
            let selector = &decomposed[begin..end];
            let q = self.select_multi(ctx, selector, &table[i])?;
            acc = self.add_incomplete(ctx, &acc, &q)?;

            begin += window_size;
            end += window_size;
        }

        // add for the last row
        let selector = &decomposed[begin..];
        let q = self.select_multi(ctx, selector, &table[n - 1])?;
        acc = self.ecc_chip.add(ctx, &acc, &q)?;

        // add correcton point
        let correction = match &self.assigned_correction {
            Some(c) => Ok(c),
            None => Err(PlonkError::Synthesis),
        }?;
        acc = self.ecc_chip.add(ctx, &acc, correction)?;

        Ok(acc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::{rns, setup};
    use crate::{BIT_LEN_LIMB, NUMBER_OF_LIMBS};
    use ark_std::{end_timer, start_timer};
    use halo2_ecc::integer::rns::Rns;
    use halo2_ecc::EccConfig;
    use halo2_maingate::{MainGateConfig, RangeChip, RangeConfig, RangeInstructions};
    use halo2wrong::curves::bn256::Bn256;
    use halo2wrong::halo2::circuit::{Layouter, SimpleFloorPlanner, Value};
    use halo2wrong::halo2::plonk::{keygen_vk, Circuit, ConstraintSystem};
    use halo2wrong::halo2::poly::commitment::ParamsProver;
    use halo2wrong::halo2::poly::kzg::commitment::{ParamsKZG, ParamsVerifierKZG};
    use halo2wrong::halo2::SerdeFormat;
    use halo2wrong::utils::{mock_prover_verify, DimensionMeasurement};
    use rand_chacha::ChaCha20Rng;
    use rand_core::{OsRng, SeedableRng};
    use std::ffi::OsStr;

    #[derive(Clone, Debug)]
    struct TestCircuitConfig {
        main_gate_config: MainGateConfig,
        range_config: RangeConfig,
    }

    impl TestCircuitConfig {
        fn ecc_chip_config(&self) -> EccConfig {
            EccConfig::new(self.range_config.clone(), self.main_gate_config.clone())
        }
    }

    impl TestCircuitConfig {
        fn new<C: CurveAffine>(meta: &mut ConstraintSystem<C::Scalar>) -> Self {
            let rns = Rns::<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::construct();

            let main_gate_config = MainGate::<C::Scalar>::configure(meta);
            let overflow_bit_lens = rns.overflow_lengths();
            let composition_bit_lens = vec![BIT_LEN_LIMB / NUMBER_OF_LIMBS];

            let range_config = RangeChip::<C::Scalar>::configure(
                meta,
                &main_gate_config,
                composition_bit_lens,
                overflow_bit_lens,
            );

            TestCircuitConfig {
                main_gate_config,
                range_config,
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
    struct TestEccMulFix {
        window_size: usize,
        generator: Point,
    }

    impl Circuit<Scalar> for TestEccMulFix {
        type Config = TestCircuitConfig;
        type FloorPlanner = SimpleFloorPlanner;
        #[cfg(feature = "circuit-params")]
        type Params = ();

        fn without_witnesses(&self) -> Self {
            unimplemented!();
        }

        fn configure(meta: &mut ConstraintSystem<Scalar>) -> Self::Config {
            TestCircuitConfig::new::<Point>(meta)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Scalar>,
        ) -> Result<(), PlonkError> {
            let ecc_chip_config = config.ecc_chip_config();
            let ecc_chip =
                BaseFieldEccChip::<Point, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::new(ecc_chip_config);
            let mut fixed_chip = FixedPointChip::new(ecc_chip);
            let main_gate = MainGate::<Scalar>::new(config.main_gate_config.clone());

            let g = self.generator;

            //   let mut rng = ChaCha20Rng::seed_from_u64(42);
            let mut rng = OsRng;

            layouter.assign_region(
                || "assign fixed point window table",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    fixed_chip.assign_fixed_point(ctx, &g, self.window_size)?;
                    Ok(())
                },
            )?;

            for _ in 0..2 {
                layouter.assign_region(
                    || "region mul",
                    |region| {
                        let offset = 0;
                        let ctx = &mut RegionCtx::new(region, offset);

                        let s = Scalar::random(&mut rng);
                        let result = (&g * &s).to_affine();

                        let ecc_chip = fixed_chip.base_field_chip();

                        let s = main_gate.assign_value(ctx, Value::known(s))?;
                        let result_0 = ecc_chip.assign_point(ctx, Value::known(result.into()))?;

                        let result_1 = fixed_chip.mul(ctx, &s)?;
                        ecc_chip.assert_equal(ctx, &result_0, &result_1)?;

                        Ok(())
                    },
                )?;
            }

            config.config_range(&mut layouter)?;

            Ok(())
        }
    }

    #[test]
    fn test_mul_fix() {
        let mut rng = OsRng;
        //    let mut rng = ChaCha20Rng::seed_from_u64(42);
        let g = Point::random(&mut rng);

        let circuit = TestEccMulFix {
            window_size: 3,
            generator: g,
        };
        let instance = vec![vec![]];
        mock_prover_verify(&circuit, instance);

        let dimension = DimensionMeasurement::measure(&circuit).unwrap();
        println!("mul fix dimention: {:?}", dimension);
    }

    #[test]
    #[ignore]
    fn test_fix_vk() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let g = Point::random(&mut rng);

        let circuit1 = TestEccMulFix {
            window_size: 3,
            generator: g,
        };
        let circuit2 = TestEccMulFix {
            window_size: 3,
            generator: g,
        };
        let circuit3 = TestEccMulFix {
            window_size: 4,
            generator: g,
        };
        let circuit4 = TestEccMulFix {
            window_size: 3,
            generator: Point::random(&mut rng),
        };

        let degree = 18;
        let setup_message = format!("dkg setup with degree = {}", degree);
        let start1 = start_timer!(|| setup_message);
        let general_params = ParamsKZG::<Bn256>::setup(degree as u32, &mut rng);
        let _verifier_params: ParamsVerifierKZG<Bn256> = general_params.verifier_params().clone();
        end_timer!(start1);

        let vk1 = keygen_vk(&general_params, &circuit1).expect("keygen_vk should not fail");
        let vk2 = keygen_vk(&general_params, &circuit2).expect("keygen_vk should not fail");
        let vk3 = keygen_vk(&general_params, &circuit3).expect("keygen_vk should not fail");
        let vk4 = keygen_vk(&general_params, &circuit4).expect("keygen_vk should not fail");

        assert_eq!(
            vk1.to_bytes(SerdeFormat::RawBytes),
            vk2.to_bytes(SerdeFormat::RawBytes)
        );

        assert_ne!(
            vk1.to_bytes(SerdeFormat::RawBytes),
            vk3.to_bytes(SerdeFormat::RawBytes)
        );

        assert_ne!(
            vk1.to_bytes(SerdeFormat::RawBytes),
            vk4.to_bytes(SerdeFormat::RawBytes)
        )
    }
}
