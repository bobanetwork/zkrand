use crate::ecc_chip::{point_base_chip::AuxGen, FixedPointChip, Selector, Windowed};
use halo2_ecc::AssignedPoint;
use halo2_maingate::{AssignedCondition, AssignedValue, MainGateInstructions};
use halo2wrong::curves::ff::PrimeField;
use halo2wrong::curves::{CurveAffine, CurveExt};
use halo2wrong::halo2::plonk::Error as PlonkError;
use halo2wrong::RegionCtx;

// windowed scalar mul for fixed point on bn256 curve
impl<C: CurveAffine + AuxGen, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize>
    FixedPointChip<C, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
{
    fn prepare_fixed_point_table(window_size: usize, fixed_point: &C) -> Vec<Vec<C::CurveExt>> {
        // The algorithm cannot be applied when the window_size = 1 due to the lack of monotonicity.
        assert!(window_size > 1);

        let num_bits = C::Scalar::NUM_BITS as usize;
        let number_of_windows = (num_bits + window_size - 1) / window_size;
        let mut last = num_bits % window_size;
        if last == 0 {
            last = window_size;
        }
        let window: usize = 1 << window_size;
        let window_last: usize = 1 << last;

        // T[0..n)[0..2^w): T[i][k]=[(k+2)⋅(2^w)^i]P
        let fp = fixed_point.to_curve();
        let mut t = vec![];
        for k in 0..window {
            let k2 = C::Scalar::from((k + 2) as u64);
            let p = fp * &k2;
            t.push(p);
        }

        let mut table = vec![t];

        for i in 1..number_of_windows {
            let mut w = window;
            if i == number_of_windows - 1 {
                w = window_last;
            }

            let mut t = vec![];
            for k in 0..w {
                let mut p = table[i - 1][k].clone();
                for _ in 0..window_size {
                    p = p + p;
                }
                t.push(p);
            }
            table.push(t);
        }

        // for the last two rows, we use auxiliary generator:
        // T[n-2][k]=[(k+2)⋅(2^w)^{n-2}]P + aux
        // T[n-1][k]=[(k+2)⋅(2^w)^{n-1}]P + C where C = -[\sum_{j=0}^{n-1} 2^{wj+1}]B - aux
        // the last row has 2^last elements instead of 2^window
        let aux_generator = C::aux_generator(fixed_point.to_bytes().as_ref()).to_curve();

        let mut correction = table[0][0];
        for i in 1..number_of_windows {
            correction = correction + &table[i][0];
        }
        correction = correction + &aux_generator;
        correction = -correction;

        assert!(bool::from(correction.is_on_curve()));

        for k in 0..window {
            table[number_of_windows - 2][k] = table[number_of_windows - 2][k] + &aux_generator;
        }

        for k in 0..window_last {
            table[number_of_windows - 1][k] = table[number_of_windows - 1][k] + &correction;
        }

        table
    }

    pub fn assign_fixed_point(
        &mut self,
        ctx: &mut RegionCtx<'_, C::Scalar>,
        fixed_point: &C,
        window_size: usize,
    ) -> Result<(), PlonkError> {
        if !bool::from(fixed_point.is_on_curve()) {
            return Err(PlonkError::Synthesis);
        };

        let table = Self::prepare_fixed_point_table(window_size, &fixed_point);

        let mut assigned_table = vec![];
        let ecc_chip = self.base_field_chip();
        for t in table.iter() {
            let mut assigned_t = vec![];
            for p in t.iter() {
                let ap = ecc_chip.assign_constant(ctx, (*p).into())?;
                assigned_t.push(ap);
            }
            assigned_table.push(assigned_t);
        }

        let assigned_fixed_point = ecc_chip.assign_constant(ctx, fixed_point.clone())?;
        self.assigned_fixed_point = Some(assigned_fixed_point);
        self.assigned_table = Some(assigned_table);
        self.window_size = Some(window_size);

        Ok(())
    }

    fn window(
        bits: &[AssignedCondition<C::ScalarExt>],
        window_size: usize,
    ) -> Windowed<C::ScalarExt> {
        let last = bits.len() % window_size;
        let num = bits.len() / window_size;

        let mut windows: Vec<_> = (0..num)
            .map(|i| {
                let k = i * window_size;
                Selector(bits[k..k + window_size].to_vec())
            })
            .collect();

        if last != 0 {
            let last_start = bits.len() - last;
            windows.push(Selector(bits[last_start..].to_vec()));
        }

        Windowed(windows)
    }

    // algorithm from https://github.com/privacy-scaling-explorations/halo2wrong/blob/v2023_04_20/ecc/src/base_field_ecc/mul.rs#L69
    fn select_multi(
        &self,
        ctx: &mut RegionCtx<'_, C::Scalar>,
        selector: &Selector<C::Scalar>,
        table: &[AssignedPoint<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>],
    ) -> Result<AssignedPoint<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, PlonkError> {
        let number_of_points = table.len();
        let number_of_selectors = selector.0.len();
        assert_eq!(number_of_points, 1 << number_of_selectors);

        let mut reducer = table.to_vec();
        for (i, selector) in selector.0.iter().enumerate() {
            let n = 1 << (number_of_selectors - 1 - i);
            for j in 0..n {
                let k = 2 * j;
                reducer[j] =
                    self.base_field_chip
                        .select(ctx, selector, &reducer[k + 1], &reducer[k])?;
            }
        }
        Ok(reducer[0].clone())
    }

    pub fn mul(
        &self,
        ctx: &mut RegionCtx<'_, C::Scalar>,
        scalar: &AssignedValue<C::Scalar>,
    ) -> Result<AssignedPoint<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, PlonkError> {
        let num_bits = C::Scalar::NUM_BITS as usize;
        let window_size = match self.window_size {
            Some(w) => Ok(w),
            None => Err(PlonkError::Synthesis),
        }?;
        let number_of_windows = (num_bits + window_size - 1) / window_size;
        let mut last = num_bits % window_size;
        if last == 0 {
            last = window_size;
        }
        let table = match &self.assigned_table {
            Some(table) => Ok(table),
            None => Err(PlonkError::Synthesis),
        }?;

        assert_eq!(number_of_windows, table.len());
        assert_eq!(1 << last, table[number_of_windows - 1].len());

        let main_gate = self.main_gate();
        let decomposed = &main_gate.to_bits(ctx, scalar, num_bits)?;
        let windowed = Self::window(&decomposed, window_size);

        // add_incomplete for the first n-2 rows
        let mut acc = self.select_multi(ctx, &windowed.0[0], &table[0])?;
        for i in 1..number_of_windows - 2 {
            let q = self.select_multi(ctx, &windowed.0[i], &table[i])?;
            acc = self.add_incomplete(ctx, &acc, &q)?;
        }

        // add for the last two row
        for i in number_of_windows - 2..number_of_windows {
            let q = self.select_multi(ctx, &windowed.0[i], &table[i])?;
            acc = self.base_field_chip.add(ctx, &acc, &q)?;
        }

        Ok(acc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BIT_LEN_LIMB, NUMBER_OF_LIMBS};
    use ark_std::{end_timer, start_timer};
    use halo2_ecc::integer::rns::Rns;
    use halo2_ecc::EccConfig;
    use halo2_maingate::{MainGate, MainGateConfig, RangeChip, RangeConfig, RangeInstructions};

    use halo2wrong::curves::ff::Field;
    use halo2wrong::halo2::circuit::{Layouter, SimpleFloorPlanner, Value};
    use halo2wrong::halo2::plonk::{keygen_vk, Circuit, ConstraintSystem};
    use halo2wrong::halo2::poly::commitment::ParamsProver;
    use halo2wrong::halo2::poly::kzg::commitment::{ParamsKZG, ParamsVerifierKZG};
    use halo2wrong::halo2::SerdeFormat;
    use halo2wrong::utils::{mock_prover_verify, DimensionMeasurement};
    use rand_chacha::ChaCha20Rng;
    use rand_core::{OsRng, SeedableRng};

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
    struct TestEccMulFix<C: CurveAffine + AuxGen> {
        window_size: usize,
        generator: C,
    }

    impl<C: CurveAffine + AuxGen> Circuit<C::Scalar> for TestEccMulFix<C> {
        type Config = TestCircuitConfig;
        type FloorPlanner = SimpleFloorPlanner;
        #[cfg(feature = "circuit-params")]
        type Params = ();

        fn without_witnesses(&self) -> Self {
            unimplemented!();
        }

        fn configure(meta: &mut ConstraintSystem<C::Scalar>) -> Self::Config {
            TestCircuitConfig::new::<C>(meta)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<C::Scalar>,
        ) -> Result<(), PlonkError> {
            let ecc_chip_config = config.ecc_chip_config();
            let mut fixed_chip =
                FixedPointChip::<C, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::new(ecc_chip_config);
            let main_gate = MainGate::<C::Scalar>::new(config.main_gate_config.clone());

            let g = self.generator;

            // let mut rng = ChaCha20Rng::seed_from_u64(42);
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

            for _ in 0..1 {
                layouter.assign_region(
                    || "region mul",
                    |region| {
                        let offset = 0;
                        let ctx = &mut RegionCtx::new(region, offset);

                        let s = C::Scalar::random(&mut rng);
                        let result = g * &s;

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

    use halo2wrong::curves::bn256::{Bn256, G1Affine as Point};

    #[test]
    fn test_mul_fix() {
        // let mut rng = ChaCha20Rng::seed_from_u64(42);
        let mut rng = OsRng;
        let g = Point::random(&mut rng);

        for window_size in 2..6 {
            let circuit = TestEccMulFix {
                window_size: window_size,
                generator: g,
            };
            let instance = vec![vec![]];
            mock_prover_verify(&circuit, instance);

            let dimension = DimensionMeasurement::measure(&circuit).unwrap();
            println!("window size {:?}, mul fix: {:?}", window_size, dimension);
        }
    }

    #[test]
    #[ignore]
    fn test_fix_vk() {
        // let mut rng = ChaCha20Rng::seed_from_u64(42);
        let mut rng = OsRng;
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
