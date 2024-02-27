mod bn256;
mod fix_mul;

use halo2_ecc::integer::IntegerInstructions;
use halo2_ecc::{AssignedPoint, BaseFieldEccChip, EccConfig};
use halo2_maingate::{AssignedValue, MainGate, MainGateInstructions};
use halo2wrong::curves::ff::PrimeField;
use halo2wrong::curves::CurveAffine;
use halo2wrong::halo2::circuit::Layouter;
use halo2wrong::halo2::plonk::Error as PlonkError;
use halo2wrong::RegionCtx;

// windowed fix point multiplication
pub struct FixedPointChip<
    C: CurveAffine + AuxGen,
    const NUMBER_OF_LIMBS: usize,
    const BIT_LEN_LIMB: usize,
> {
    base_field_chip: BaseFieldEccChip<C, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    assigned_fixed_point: Option<AssignedPoint<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>>,
    assigned_table:
        Option<Vec<Vec<AssignedPoint<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>>>>,
    window_size: Option<usize>,
}

pub trait AuxGen {
    fn aux_generator(bytes: &[u8]) -> Self;
}

impl<C: CurveAffine + AuxGen, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize>
    FixedPointChip<C, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
{
    pub fn new(config: EccConfig) -> Self {
        let base_field_chip = BaseFieldEccChip::<C, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::new(config);
        Self {
            base_field_chip,
            assigned_fixed_point: None,
            assigned_table: None,
            window_size: None,
        }
    }

    pub fn base_field_chip(&self) -> &BaseFieldEccChip<C, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        &self.base_field_chip
    }

    pub fn main_gate(&self) -> &MainGate<C::Scalar> {
        self.base_field_chip.main_gate()
    }

    pub fn fixed_point(
        &self,
    ) -> Result<&AssignedPoint<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, PlonkError> {
        match &self.assigned_fixed_point {
            Some(w) => Ok(w),
            None => Err(PlonkError::Synthesis),
        }
    }

    pub fn expose_public(
        &self,
        mut layouter: impl Layouter<C::Scalar>,
        point: AssignedPoint<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        offset: &mut usize,
    ) -> Result<(), PlonkError> {
        self.base_field_chip
            .expose_public(layouter, point, *offset)?;
        *offset += NUMBER_OF_LIMBS * 2;
        Ok(())
    }

    pub fn expose_public_optimal(
        &self,
        mut layouter: impl Layouter<C::Scalar>,
        point: AssignedPoint<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        wrap_len: usize,
        assigned_base: Option<AssignedValue<C::Scalar>>,
        offset: &mut usize,
    ) -> Result<AssignedValue<C::Scalar>, PlonkError> {
        assert!(BIT_LEN_LIMB < 128);
        assert!(BIT_LEN_LIMB * wrap_len < C::Scalar::NUM_BITS as usize);
        // for simplicity
        assert_eq!(NUMBER_OF_LIMBS % wrap_len, 0);

        let num = NUMBER_OF_LIMBS / wrap_len;
        let main_gate = self.main_gate();

        let (assigned_base, wrapped) = layouter.assign_region(
            || "region wrap up public inputs",
            |region| {
                let ctx = &mut RegionCtx::new(region, *offset);

                let assigned_base = match &assigned_base {
                    Some(base) => base.clone(),
                    None => {
                        let base = C::Scalar::from_u128(1 << BIT_LEN_LIMB);
                        main_gate.assign_constant(ctx, base)?
                    }
                };

                // wrap up x, y coordinates
                let mut wrapped = vec![];
                for limbs in [point.x().limbs(), point.y().limbs()] {
                    for i in 0..num {
                        let begin = i * wrap_len;
                        let mut s = limbs[begin + wrap_len - 1].clone().into();
                        for j in (0..wrap_len - 1).rev() {
                            s = main_gate.mul_add(
                                ctx,
                                &s,
                                &assigned_base,
                                &limbs[begin + j].clone().into(),
                            )?
                        }
                        wrapped.push(s);
                    }
                }

                Ok((assigned_base, wrapped))
            },
        )?;

        for limb in wrapped.into_iter() {
            main_gate.expose_public(layouter.namespace(|| "G point coords"), limb, *offset)?;
            *offset += 1;
        }

        Ok(assigned_base)
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
}
