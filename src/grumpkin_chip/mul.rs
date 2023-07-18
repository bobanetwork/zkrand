use crate::grumpkin_chip::{AssignedPoint, Base, GrumpkinChip, PlonkError};
use halo2_maingate::{AssignedCondition, AssignedValue, MainGateInstructions};
use halo2wrong::curves::ff::PrimeField;
use halo2wrong::RegionCtx;

impl GrumpkinChip {
    // simple double-and-add; scalar is from base field
    pub fn mul(
        &self,
        ctx: &mut RegionCtx<'_, Base>,
        point: &AssignedPoint,
        scalar: &AssignedValue<Base>,
    ) -> Result<AssignedPoint, PlonkError> {
        let main_gate = self.main_gate();
        let decomposed = main_gate.to_bits(ctx, scalar, Base::NUM_BITS as usize)?;
        let res = self.mul_bits(ctx, point, &decomposed)?;
        Ok(res)
    }

    pub fn mul_bits(
        &self,
        ctx: &mut RegionCtx<'_, Base>,
        point: &AssignedPoint,
        bits: &[AssignedCondition<Base>],
    ) -> Result<AssignedPoint, PlonkError> {
        let aux = match self.aux_generator.clone() {
            Some((assigned, _)) => Ok(assigned),
            None => Err(PlonkError::Synthesis),
        }?;
        let aux_sub = match self.aux_sub.clone() {
            Some((assigned, _)) => Ok(assigned),
            None => Err(PlonkError::Synthesis),
        }?;

        let mut res = aux;
        let mut double = point.clone();
        for bit in bits.iter() {
            let t = self.add(ctx, &res, &double)?;
            res = self.select(ctx, bit, &t, &res)?;
            double = self.double_incomplete(ctx, &double)?;
        }

        res = self.add(ctx, &res, &aux_sub)?;
        Ok(res)
    }
}
