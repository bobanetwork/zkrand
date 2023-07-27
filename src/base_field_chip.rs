mod fix_mul;

use halo2_ecc::integer::IntegerInstructions;
use halo2_ecc::{AssignedPoint, BaseFieldEccChip, EccConfig};
use halo2_maingate::{AssignedCondition, MainGate};
use halo2wrong::curves::CurveAffine;
use halo2wrong::halo2::circuit::Layouter;
use halo2wrong::halo2::plonk::Error as PlonkError;
use halo2wrong::RegionCtx;

// windowed fix point multiplication
pub struct FixedPointChip<C: CurveAffine, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize> {
    base_field_chip: BaseFieldEccChip<C, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    assigned_fixed_point: Option<AssignedPoint<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>>,
    assigned_table:
        Option<Vec<Vec<AssignedPoint<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>>>>,
    assigned_correction: Option<AssignedPoint<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>>,
    window_size: Option<usize>,
}

impl<C: CurveAffine, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize>
    FixedPointChip<C, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
{
    pub fn new(config: EccConfig) -> Self {
        let base_field_chip = BaseFieldEccChip::<C, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::new(config);
        Self {
            base_field_chip,
            assigned_fixed_point: None,
            assigned_table: None,
            assigned_correction: None,
            window_size: None,
        }
    }

    pub fn base_field_chip(&self) -> &BaseFieldEccChip<C, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        &self.base_field_chip
    }

    pub fn main_gate(&self) -> &MainGate<C::Scalar> {
        self.base_field_chip.main_gate()
    }

    pub fn expose_public(
        &self,
        mut layouter: impl Layouter<C::Scalar>,
        point: AssignedPoint<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        offset: usize,
    ) -> Result<(), PlonkError> {
        self.base_field_chip.expose_public(layouter, point, offset)
    }

    pub fn normalize(
        &self,
        ctx: &mut RegionCtx<'_, C::Scalar>,
        point: &AssignedPoint<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedPoint<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, PlonkError> {
        self.base_field_chip.normalize(ctx, point)
    }

    // algorithm from https://github.com/privacy-scaling-explorations/halo2wrong/blob/v2023_04_20/ecc/src/base_field_ecc/add.rs#L17
    fn add_incomplete(
        &self,
        ctx: &mut RegionCtx<'_, C::Scalar>,
        a: &AssignedPoint<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        b: &AssignedPoint<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedPoint<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, PlonkError> {
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

    // algorithm from https://github.com/privacy-scaling-explorations/halo2wrong/blob/v2023_04_20/ecc/src/base_field_ecc/mul.rs#L69
    fn select_multi(
        &self,
        ctx: &mut RegionCtx<'_, C::Scalar>,
        selector: &[AssignedCondition<C::Scalar>],
        table: &[AssignedPoint<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>],
    ) -> Result<AssignedPoint<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, PlonkError> {
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
}
