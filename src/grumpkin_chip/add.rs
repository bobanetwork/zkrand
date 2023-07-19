use crate::grumpkin_chip::{AssignedPoint, Base, GrumpkinChip, PlonkError};
use halo2_maingate::{
    AssignedValue, CombinationOption, CombinationOptionCommon, MainGate, MainGateInstructions, Term,
};
use halo2wrong::curves::ff::Field;
use halo2wrong::RegionCtx;

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

// c = 1/(a+b); if a + b == 0 then a valid witness cannot be found
fn add_invert_unsafe(
    main_gate: &MainGate<Base>,
    ctx: &mut RegionCtx<'_, Base>,
    a: &AssignedValue<Base>,
    b: &AssignedValue<Base>,
) -> Result<AssignedValue<Base>, PlonkError> {
    let c = a
        .value()
        .zip(b.value())
        .map(|(a, b)| (a + b).invert().unwrap_or(Base::ZERO));

    // Witness layout:
    // | A  | B  | C | D | E |
    // | -- | -- | --| --| --|
    // | a  | c  | b | c |   |

    // a * c + b * c - 1 = 0
    let mut assigned = main_gate.apply(
        ctx,
        [
            Term::assigned_to_mul(a),
            Term::unassigned_to_mul(c),
            Term::assigned_to_mul(b),
            Term::unassigned_to_mul(c),
        ],
        -Base::ONE,
        CombinationOption::OneLinerDoubleMul(Base::ONE),
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
    let s = Base::from(2).invert().unwrap() * Base::from(3);
    let lambda_value =
        a.x.value()
            .zip(a.y().value())
            .map(|(x, y)| y.invert().unwrap_or(Base::ZERO) * x * x * s);

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
        CombinationOption::OneLinerDoubleMul(-s),
    )?;

    Ok(assigned.swap_remove(0))
}

impl GrumpkinChip {
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
        let numerator = &mul(main_gate, ctx, Base::from(3), a.x(), a.x())?;
        let inv = &add_invert_unsafe(main_gate, ctx, a.y(), a.y())?;
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
