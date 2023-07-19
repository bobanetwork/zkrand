use crate::grumpkin_chip::{AssignedPoint, Base, GrumpkinChip, PlonkError};
use halo2_gadgets::utilities::FieldValue;
use halo2_maingate::{
    AssignedValue, CombinationOption, CombinationOptionCommon, MainGate, MainGateInstructions, Term,
};
use halo2wrong::curves::ff::Field;
use halo2wrong::RegionCtx;

// constant 3/2
const THREE_OVER_TWO: Base = Base::from_raw([
    0xa1f0fac9f8000002,
    0x9419f4243cdcb848,
    0xdc2822db40c0ac2e,
    0x183227397098d014,
]);

// d = a*b-c
fn mul_sub(
    main_gate: &MainGate<Base>,
    ctx: &mut RegionCtx<'_, Base>,
    a: &AssignedValue<Base>,
    b: &AssignedValue<Base>,
    c: &AssignedValue<Base>,
) -> Result<AssignedValue<Base>, PlonkError> {
    let d = a
        .value()
        .zip(b.value())
        .zip(c.value())
        .map(|((a, b), c)| a * b - c);

    Ok(main_gate
        .apply(
            ctx,
            [
                Term::assigned_to_mul(a),
                Term::assigned_to_mul(b),
                Term::assigned_to_sub(c),
                Term::unassigned_to_sub(d),
            ],
            Base::zero(),
            CombinationOptionCommon::OneLinerMul.into(),
        )?
        .swap_remove(3))
}

// e = a*b - c - d
fn mul_sub_sub(
    main_gate: &MainGate<Base>,
    ctx: &mut RegionCtx<'_, Base>,
    a: &AssignedValue<Base>,
    b: &AssignedValue<Base>,
    c: &AssignedValue<Base>,
    d: &AssignedValue<Base>,
) -> Result<AssignedValue<Base>, PlonkError> {
    let e = a
        .value()
        .zip(b.value())
        .zip(c.value())
        .zip(d.value())
        .map(|(((a, b), c), d)| a * b - c - d);

    // Witness layout:
    // | A  | B  | C | D | E |
    // | -- | -- | --| --| --|
    // | a  | b  | c | d | e |

    // a * b - c - d - e = 0
    Ok(main_gate
        .apply(
            ctx,
            [
                Term::assigned_to_mul(a),
                Term::assigned_to_mul(b),
                Term::assigned_to_sub(c),
                Term::assigned_to_sub(d),
                Term::unassigned_to_sub(e),
            ],
            Base::ZERO,
            CombinationOptionCommon::OneLinerMul.into(),
        )?
        .swap_remove(4))
}

// c = 1/(a-b)
// if a == b then a valid witness cannot be found
fn sub_invert_unsafe(
    main_gate: &MainGate<Base>,
    ctx: &mut RegionCtx<'_, Base>,
    a: &AssignedValue<Base>,
    b: &AssignedValue<Base>,
) -> Result<AssignedValue<Base>, PlonkError> {
    let c = a
        .value()
        .zip(b.value())
        .map(|(a, b)| (a - b).invert().unwrap_or(Base::ZERO));

    // Witness layout:
    // | A  | B  | C | D | E |
    // | -- | -- | --| --| --|
    // | a  | c  | b | c |   |

    // a * c -  b * c - 1 = 0
    let mut assigned = main_gate.apply(
        ctx,
        [
            Term::assigned_to_mul(a),
            Term::unassigned_to_mul(c),
            Term::assigned_to_mul(b),
            Term::unassigned_to_mul(c),
        ],
        -Base::ONE,
        CombinationOption::OneLinerDoubleMul(-Base::ONE),
    )?;
    ctx.constrain_equal(assigned[1].cell(), assigned[3].cell())?;
    Ok(assigned.swap_remove(1))
}

// d = (a-b) * c
fn sub_mul(
    main_gate: &MainGate<Base>,
    ctx: &mut RegionCtx<'_, Base>,
    a: &AssignedValue<Base>,
    b: &AssignedValue<Base>,
    c: &AssignedValue<Base>,
) -> Result<AssignedValue<Base>, PlonkError> {
    let d = a
        .value()
        .zip(b.value())
        .zip(c.value())
        .map(|((a, b), c)| (a - b) * c);

    // Witness layout:
    // | A  | B  | C | D | E |
    // | -- | -- | --| --| --|
    // | a  | c  | b | c |  d |

    // a * c -  b * c - d = 0
    let mut assigned = main_gate.apply(
        ctx,
        [
            Term::assigned_to_mul(a),
            Term::assigned_to_mul(c),
            Term::assigned_to_mul(b),
            Term::assigned_to_mul(c),
            Term::unassigned_to_sub(d),
        ],
        Base::ZERO,
        CombinationOption::OneLinerDoubleMul(-Base::ONE),
    )?;

    Ok(assigned.swap_remove(4))
}

// b = s * a * b where s is fixed scalar
fn mul(
    main_gate: &MainGate<Base>,
    ctx: &mut RegionCtx<'_, Base>,
    s: Base,
    a: &AssignedValue<Base>,
    b: &AssignedValue<Base>,
) -> Result<AssignedValue<Base>, PlonkError> {
    let c = a.value().zip(b.value()).map(|(a, b)| &s * a * b);

    // Witness layout:
    // | A  | B  | C | D | E |
    // | -- | -- | --| --| --|
    // | a  | b  | c |  |   |

    // s* a * b -  c  = 0
    Ok(main_gate
        .apply(
            ctx,
            [
                Term::assigned_to_mul(a),
                Term::assigned_to_mul(b),
                Term::unassigned_to_sub(c),
            ],
            Base::zero(),
            CombinationOptionCommon::CombineToNextScaleMul(Base::ZERO, s).into(),
        )?
        .swap_remove(2))
}

// lambda for point double: lambda = 3x^2/2y assuming y != 0;
// if y == 0 then a valid witness cannot be found unless x == 0; (0,0), (0, y), (x, 0) is not valid point on curve
fn lambda_double_unsafe(
    main_gate: &MainGate<Base>,
    ctx: &mut RegionCtx<'_, Base>,
    a: &AssignedPoint,
) -> Result<AssignedValue<Base>, PlonkError> {
    let lambda_value =
        a.x.value()
            .zip(a.y().value())
            .map(|(x, y)| y.invert().unwrap_or(Base::ZERO) * x * x * THREE_OVER_TWO);

    // Witness layout:
    // | A      | B | C | D | E  |
    // | ------ | --| --| --| ---|
    // | lambda | y | x | x |   |

    // lambda * y - (3/2) x * x = 0
    let mut assigned = main_gate.apply(
        ctx,
        [
            Term::unassigned_to_mul(lambda_value),
            Term::assigned_to_mul(a.y()),
            Term::assigned_to_mul(a.x()),
            Term::assigned_to_mul(a.x()),
        ],
        Base::zero(),
        CombinationOption::OneLinerDoubleMul(-THREE_OVER_TWO),
    )?;

    Ok(assigned.swap_remove(0))
}

impl GrumpkinChip {
    // a + b assuming a.x != b.x
    // if a.x == b.x then a valid witness cannot be found unless a.y == b.y
    // below we check the following equations:
    // t = lambda * xa - ya = lambda * xb - yb
    // xc = lambda * lambda - xa - xb
    // yc = t - lambda * xc
    pub fn add_incomplete(
        &self,
        ctx: &mut RegionCtx<'_, Base>,
        a: &AssignedPoint,
        b: &AssignedPoint,
    ) -> Result<AssignedPoint, PlonkError> {
        let main_gate = self.main_gate();

        // lambda = (ya - yb)/(xa - xb)
        let numerator_value = a.y().value().zip(b.y().value()).map(|(ya, yb)| ya - yb);
        let denominator_value = a.x().value().zip(b.x().value()).map(|(xa, xb)| xa - xb);
        let lambda_value = numerator_value
            .value()
            .zip(denominator_value.value())
            .map(|(n, d)| d.invert().unwrap_or(Base::ZERO) * n);

        // xc = lambda * lambda - xa - xb
        let xc_value = lambda_value
            .value()
            .zip(a.x().value())
            .zip(b.x().value())
            .map(|((l, xa), xb)| l * l - xa - xb);

        // lambda * lambda - xa - xb - xc = 0
        // Witness layout:
        // | A      | B      | C  | D  | E  |
        // | ------ | -------| ---| ---| ---|
        // | lambda | lambda | xa | xb | xc |
        let mut assigned = main_gate.apply(
            ctx,
            [
                Term::unassigned_to_mul(lambda_value),
                Term::unassigned_to_mul(lambda_value),
                Term::assigned_to_sub(a.x()),
                Term::assigned_to_sub(b.x()),
                Term::unassigned_to_sub(xc_value),
            ],
            Base::zero(),
            CombinationOptionCommon::OneLinerMul.into(),
        )?;
        ctx.constrain_equal(assigned[0].cell(), assigned[1].cell())?;

        let lambda = &assigned[0];
        let xc = assigned[4].clone();

        // t = lambda * xa - ya
        let t = &mul_sub(main_gate, ctx, lambda, a.x(), a.y())?;

        // lambda * xb - yb - t = 0
        // Witness layout:
        // | A      | B      | C  | D  | E  |
        // | ------ | -------| ---| ---| ---|
        // | lambda | xb | yb | t |  |
        let mut assigned = main_gate.apply(
            ctx,
            [
                Term::assigned_to_mul(lambda),
                Term::assigned_to_mul(b.x()),
                Term::assigned_to_sub(b.y()),
                Term::assigned_to_sub(t),
            ],
            Base::zero(),
            CombinationOptionCommon::OneLinerMul.into(),
        )?;

        // yc = t - lambda * xc
        let yc_value = lambda_value
            .zip(xc.value())
            .zip(t.value())
            .map(|((l, xc), t)| t - l * xc);

        // lambda * xc + yc - t = 0
        // Witness layout:
        // | A      | B      | C  | D | E  |
        // | ------ | -------| ---| --| ---|
        // | lambda | xc | yc | t |   |
        let mut assigned = main_gate.apply(
            ctx,
            [
                Term::assigned_to_mul(lambda),
                Term::assigned_to_mul(&xc),
                Term::unassigned_to_add(yc_value),
                Term::assigned_to_sub(&t),
            ],
            Base::zero(),
            CombinationOptionCommon::OneLinerMul.into(),
        )?;
        let yc = assigned.swap_remove(2);

        let c = AssignedPoint::new(xc, yc);
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
        let inv = &sub_invert_unsafe(main_gate, ctx, a.x(), b.x())?;
        let lambda = &sub_mul(main_gate, ctx, a.y(), b.y(), inv)?;

        // xc =  lambda * lambda - xa - xb
        let x = mul_sub_sub(main_gate, ctx, lambda, lambda, a.x(), b.x())?;

        // yc = lambda * (xa - xc) - ya
        let sub = &main_gate.sub(ctx, a.x(), &x)?;
        let y = mul_sub(main_gate, ctx, lambda, sub, a.y())?;

        let c = AssignedPoint::new(x, y);
        Ok(c)
    }

    // point double assuming a.y != 0
    // lambda = 3x^2/(2y), xc = lambda^2 - 2x, yc = lambda * (x - xc) - y
    // if y == 0 then a valid witness cannot be found unless x == 0; (0,0), (0,y) or (x, 0) are not valid point on curve
    pub fn double_incomplete(
        &self,
        ctx: &mut RegionCtx<'_, Base>,
        a: &AssignedPoint,
    ) -> Result<AssignedPoint, PlonkError> {
        let main_gate = self.main_gate();

        // lambda = 3x^2/(2y)
        let lambda = &lambda_double_unsafe(main_gate, ctx, a)?;

        // xc = lambda^2 - 2x
        let x = mul_sub_sub(main_gate, ctx, lambda, lambda, a.x(), a.x())?;

        // yc = lambda * (x - xc) - y
        let sub = &main_gate.sub(ctx, a.x(), &x)?;
        let y = mul_sub(main_gate, ctx, lambda, sub, a.y())?;

        let c = AssignedPoint::new(x, y);
        Ok(c)
    }

    // point double with assertion point.y != 0
    pub fn double(
        &self,
        ctx: &mut RegionCtx<'_, Base>,
        a: &AssignedPoint,
    ) -> Result<AssignedPoint, PlonkError> {
        let main_gate = self.main_gate();

        // lambda = 3x^2/(2y)
        let numerator = &mul(main_gate, ctx, THREE_OVER_TWO, a.x(), a.x())?;
        let inv = &main_gate.invert_unsafe(ctx, a.y())?;
        let lambda = &main_gate.mul(ctx, numerator, inv)?;

        // xc = lambda * lambda - 2 * x
        let x = mul_sub_sub(main_gate, ctx, lambda, lambda, a.x(), a.x())?;

        // yc = lambda * (x - xc) - y
        let sub = &main_gate.sub(ctx, a.x(), &x)?;
        let y = mul_sub(main_gate, ctx, lambda, sub, a.y())?;

        let c = AssignedPoint::new(x, y);
        Ok(c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant() {
        let s = Base::from(2).invert().unwrap() * Base::from(3);
        assert_eq!(s, THREE_OVER_TWO)
    }
}
