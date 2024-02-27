use crate::ecc_chip::point2::AssignedPoint2;
use crate::ecc_chip::point2_base_chip::{AuxGen, FixedPoint2Chip, SplitBase};
use crate::ecc_chip::{Selector, Windowed};
use halo2_maingate::{AssignedCondition, AssignedValue, MainGateInstructions};
use halo2wrong::curves::ff::PrimeField;
use halo2wrong::curves::group::cofactor::{CofactorCurveAffine, CofactorGroup};
use halo2wrong::curves::group::prime::PrimeCurveAffine;
use halo2wrong::curves::CurveAffine;
use halo2wrong::halo2::plonk::Error as PlonkError;
use halo2wrong::RegionCtx;

impl<
        W: PrimeField,
        C: CurveAffine + CofactorCurveAffine + SplitBase<C::Base, W> + AuxGen,
        const NUMBER_OF_LIMBS: usize,
        const BIT_LEN_LIMB: usize,
    > FixedPoint2Chip<W, C, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
{
    fn prepare_fixed_point_table(window_size: usize, fixed_point: &C) -> Vec<Vec<C::CurveExt>> {
        // The algorithm cannot be applied when the window_size = 1 due to the lack of monotonicity.
        assert!(window_size > 1);

        let num_bits = C::ScalarExt::NUM_BITS as usize;
        let number_of_windows = (num_bits + window_size - 1) / window_size;
        let mut last = num_bits % window_size;
        if last == 0 {
            last = window_size;
        }
        let window: usize = 1 << window_size;
        let window_last: usize = 1 << last;

        // T[0..n)[0..2^w): T[i][k]=[(k+2)⋅(2^w)^i]P
        let fp = PrimeCurveAffine::to_curve(fixed_point);
        let mut t = vec![];
        for k in 0..window {
            let k2 = C::ScalarExt::from((k + 2) as u64);
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
                // [2^w]p
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
        let aux_generator = PrimeCurveAffine::to_curve(&C::aux_generator());
        let mut correction = table[0][0];
        for i in 1..number_of_windows {
            correction = correction + &table[i][0];
        }
        correction = correction + &aux_generator;
        correction = -correction;

        let c = <C as From<_>>::from(correction);
        assert!(bool::from(c.is_on_curve()));
        assert!(bool::from(
            CofactorCurveAffine::to_curve(&c).is_torsion_free()
        ));

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
        ctx: &mut RegionCtx<'_, C::ScalarExt>,
        fixed_point: &C,
        window_size: usize,
    ) -> Result<(), PlonkError> {
        if !bool::from(fixed_point.is_on_curve())
            || !bool::from(CofactorCurveAffine::to_curve(fixed_point).is_torsion_free())
        {
            return Err(PlonkError::Synthesis);
        };

        let table = Self::prepare_fixed_point_table(window_size, fixed_point);

        let mut assigned_table = vec![];
        for t in table.iter() {
            let mut assigned = vec![];
            for p in t.iter() {
                let ap = self.assign_constant(ctx, (*p).into())?;
                assigned.push(ap);
            }
            assigned_table.push(assigned);
        }

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

    fn select_multi(
        &self,
        ctx: &mut RegionCtx<'_, C::ScalarExt>,
        selector: &Selector<C::ScalarExt>,
        table: &[AssignedPoint2<W, C::ScalarExt, NUMBER_OF_LIMBS, BIT_LEN_LIMB>],
    ) -> Result<AssignedPoint2<W, C::ScalarExt, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, PlonkError> {
        let number_of_points = table.len();
        let number_of_selectors = selector.0.len();
        assert_eq!(number_of_points, 1 << number_of_selectors);

        let mut reducer = table.to_vec();
        for (i, selector) in selector.0.iter().enumerate() {
            let n = 1 << (number_of_selectors - 1 - i);
            for j in 0..n {
                let k = 2 * j;
                reducer[j] = self.select(ctx, selector, &reducer[k + 1], &reducer[k])?;
            }
        }
        Ok(reducer[0].clone())
    }

    pub fn mul(
        &self,
        ctx: &mut RegionCtx<'_, C::ScalarExt>,
        scalar: &AssignedValue<C::ScalarExt>,
    ) -> Result<AssignedPoint2<W, C::ScalarExt, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, PlonkError> {
        let num_bits = C::ScalarExt::NUM_BITS as usize;
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
            acc = self.add(ctx, &acc, &q)?;
        }

        Ok(acc)
    }
}
