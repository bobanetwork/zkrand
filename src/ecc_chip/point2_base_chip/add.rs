use crate::ecc_chip::point2::AssignedPoint2;
use crate::ecc_chip::point2_base_chip::{AuxGen, FixedPoint2Chip, SplitBase};
use halo2wrong::curves::ff::PrimeField;
use halo2wrong::curves::group::cofactor::CofactorCurveAffine;
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
    pub fn add(
        &self,
        ctx: &mut RegionCtx<'_, C::ScalarExt>,
        a: &AssignedPoint2<W, C::ScalarExt, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        b: &AssignedPoint2<W, C::ScalarExt, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedPoint2<W, C::ScalarExt, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, PlonkError> {
        let integer2_chip = self.integer2_chip();
        integer2_chip.assert_not_equal(ctx, &a.x(), &b.x())?;
        self.add_incomplete(ctx, a, b)
    }

    pub(crate) fn add_incomplete(
        &self,
        ctx: &mut RegionCtx<'_, C::ScalarExt>,
        a: &AssignedPoint2<W, C::ScalarExt, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        b: &AssignedPoint2<W, C::ScalarExt, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedPoint2<W, C::ScalarExt, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, PlonkError> {
        let integer2_chip = self.integer2_chip();

        // lambda = b_y - a_y / b_x - a_x
        let numerator = &integer2_chip.sub(ctx, &b.y, &a.y)?;
        let denominator = &integer2_chip.sub(ctx, &b.x, &a.x)?;
        let lambda = &integer2_chip.div_incomplete(ctx, numerator, denominator)?;

        // c_x =  lambda * lambda - a_x - b_x
        let lambda_square = &integer2_chip.square(ctx, lambda)?;
        let x = integer2_chip.sub_sub(ctx, lambda_square, &a.x, &b.x)?;

        // c_y = lambda * (a_x - c_x) - a_y
        let t = &integer2_chip.sub(ctx, &a.x, &x)?;
        let t = &integer2_chip.mul(ctx, t, lambda)?;
        let y = integer2_chip.sub(ctx, t, &a.y)?;

        Ok(AssignedPoint2 { x, y })
    }

    pub fn double(
        &self,
        ctx: &mut RegionCtx<'_, C::ScalarExt>,
        point: &AssignedPoint2<W, C::ScalarExt, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedPoint2<W, C::ScalarExt, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, PlonkError> {
        let integer2_chip = self.integer2_chip();
        integer2_chip.assert_not_zero(ctx, &point.x)?;
        self.double_incomplete(ctx, point)
    }

    pub(crate) fn double_incomplete(
        &self,
        ctx: &mut RegionCtx<'_, C::ScalarExt>,
        point: &AssignedPoint2<W, C::ScalarExt, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedPoint2<W, C::ScalarExt, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, PlonkError> {
        let integer2_chip = self.integer2_chip();

        // lambda = (3 * a_x^2) / 2 * a_y
        let x_0_square = &integer2_chip.square(ctx, &point.x)?;
        let numerator = &integer2_chip.mul3(ctx, x_0_square)?;
        let denominator = &integer2_chip.mul2(ctx, &point.y)?;
        let lambda = &integer2_chip.div_incomplete(ctx, numerator, denominator)?;

        // c_x = lambda * lambda - 2 * a_x
        let lambda_square = &integer2_chip.square(ctx, lambda)?;
        let x = integer2_chip.sub_sub(ctx, lambda_square, &point.x, &point.x)?;

        // c_y = lambda * (a_x - c_x) - a_y
        let t = &integer2_chip.sub(ctx, &point.x, &x)?;
        let t = &integer2_chip.mul(ctx, lambda, t)?;
        let y = integer2_chip.sub(ctx, t, &point.y)?;

        Ok(AssignedPoint2 { x, y })
    }
}
