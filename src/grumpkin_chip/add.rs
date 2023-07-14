use crate::grumpkin_chip::{AssignedPoint, Base, GrumpkinChip, PlonkError};
use halo2_maingate::MainGateInstructions;
use halo2wrong::RegionCtx;

impl GrumpkinChip {
    // a + b assuming a.x != b.x
    pub fn add_incomplete(
        &self,
        ctx: &mut RegionCtx<'_, Base>,
        a: &AssignedPoint,
        b: &AssignedPoint,
    ) -> Result<AssignedPoint, PlonkError> {
        let main_gate = self.main_gate();

        // lambda = (ya - yb)/(xa - xb)
        let numerator = &main_gate.sub(ctx, &a.y, &b.y)?;
        let denominator = &main_gate.sub(ctx, &a.x, &b.x)?;

        let lambda = main_gate.div_unsafe(ctx, numerator, denominator)?;
        // xc =  lambda * lambda - xa - xb
        let lambda2 = main_gate.mul(ctx, &lambda, &lambda)?;
        let x = main_gate.sub_sub_with_constant(ctx, &lambda2, a.x(), b.x(), Base::zero())?;

        // yc = lambda * (xa - xc) - ya
        let sub = main_gate.sub(ctx, a.x(), &x)?;
        let z = main_gate.mul(ctx, &lambda, &sub)?;
        let y = main_gate.sub(ctx, &z, a.y())?;

        let c = AssignedPoint::new(x, y);
        Ok(c)
    }

    // a + b with assertion a.x != b.x
    pub fn add(
        &self,
        ctx: &mut RegionCtx<'_, Base>,
        a: &AssignedPoint,
        b: &AssignedPoint,
    ) -> Result<AssignedPoint, PlonkError> {
        let main_gate = self.main_gate();

        // lambda = (ya - yb)/(xa - xb)
        let numerator = &main_gate.sub(ctx, &a.y, &b.y)?;
        let denominator = &main_gate.sub(ctx, &a.x, &b.x)?;
        let inv = &main_gate.invert_unsafe(ctx, denominator)?;
        let lambda = main_gate.mul(ctx, numerator, inv)?;

        // xc =  lambda * lambda - xa - xb
        let lambda2 = main_gate.mul(ctx, &lambda, &lambda)?;
        let x = main_gate.sub_sub_with_constant(ctx, &lambda2, a.x(), b.x(), Base::zero())?;

        // yc = lambda * (xa - xc) - ya
        let sub = main_gate.sub(ctx, a.x(), &x)?;
        let z = main_gate.mul(ctx, &lambda, &sub)?;
        let y = main_gate.sub(ctx, &z, a.y())?;

        let c = AssignedPoint::new(x, y);
        Ok(c)
    }

    // point double assuming point.y != 0
    pub fn double_incomplete(
        &self,
        ctx: &mut RegionCtx<'_, Base>,
        point: &AssignedPoint,
    ) -> Result<AssignedPoint, PlonkError> {
        let main_gate = self.main_gate();

        // lambda = 3x^2/(2y)
        let x2 = main_gate.mul(ctx, point.x(), point.x())?;
        let numerator = main_gate.mul3(ctx, &x2)?;
        let denominator = main_gate.mul2(ctx, point.y())?;
        let lambda = main_gate.div_unsafe(ctx, &numerator, &denominator)?;

        // xc = lambda * lambda - 2 * x
        let lambda2 = main_gate.mul(ctx, &lambda, &lambda)?;
        let x =
            main_gate.sub_sub_with_constant(ctx, &lambda2, point.x(), point.x(), Base::zero())?;

        // yc = lambda * (x - xc) - y
        let sub = main_gate.sub(ctx, point.x(), &x)?;
        let z = main_gate.mul(ctx, &lambda, &sub)?;
        let y = main_gate.sub(ctx, &z, point.y())?;

        let c = AssignedPoint::new(x, y);
        Ok(c)
    }

    // point double with assertion point.y != 0
    pub fn double(
        &self,
        ctx: &mut RegionCtx<'_, Base>,
        point: &AssignedPoint,
    ) -> Result<AssignedPoint, PlonkError> {
        let main_gate = self.main_gate();

        // lambda = 3x^2/(2y)
        let x2 = &main_gate.mul(ctx, point.x(), point.x())?;
        let numerator = &main_gate.mul3(ctx, x2)?;
        let denominator = &main_gate.mul2(ctx, point.y())?;
        let inv = &main_gate.invert_unsafe(ctx, denominator)?;
        let lambda = main_gate.mul(ctx, numerator, inv)?;

        // xc = lambda * lambda - 2 * x
        let lambda2 = main_gate.mul(ctx, &lambda, &lambda)?;
        let x =
            main_gate.sub_sub_with_constant(ctx, &lambda2, point.x(), point.x(), Base::zero())?;

        // yc = lambda * (x - xc) - y
        let sub = main_gate.sub(ctx, point.x(), &x)?;
        let z = main_gate.mul(ctx, &lambda, &sub)?;
        let y = main_gate.sub(ctx, &z, point.y())?;

        let c = AssignedPoint::new(x, y);
        Ok(c)
    }
}
