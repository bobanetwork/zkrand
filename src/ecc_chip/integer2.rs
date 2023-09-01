use halo2_ecc::integer::rns::{Integer, Rns};
use halo2_ecc::integer::{AssignedInteger, IntegerChip, IntegerConfig, IntegerInstructions};
use halo2_maingate::{AssignedCondition, MainGate};
use halo2wrong::curves::ff::PrimeField;
//use halo2wrong::halo2::circuit::Value;
use halo2wrong::halo2::plonk::Error as PlonkError;
use halo2wrong::RegionCtx;
use std::rc::Rc;

/// Witness Integer2 for elements in GF(p^2) with prime p and irreducible polynomial X^2+1. p is the modulus for W.
#[derive(Clone)]
pub struct Integer2<
    W: PrimeField,
    N: PrimeField,
    const NUMBER_OF_LIMBS: usize,
    const BIT_LEN_LIMB: usize,
> {
    i0: Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    i1: Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
}

impl<W: PrimeField, N: PrimeField, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize>
    Integer2<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
{
    pub fn new(
        i0: Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        i1: Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Self {
        Integer2 { i0, i1 }
    }

    pub fn from_fe(e: (W, W), rns: Rc<Rns<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>>) -> Self {
        let i0 = Integer::from_fe(e.0, rns.clone());
        let i1 = Integer::from_fe(e.1, rns);

        Integer2 { i0, i1 }
    }

    pub fn limbs(&self) -> Vec<N> {
        let mut limbs = self.i0.limbs();
        limbs.extend(self.i1.limbs());
        limbs
    }
}

#[derive(Clone)]
pub struct AssignedInteger2<
    W: PrimeField,
    N: PrimeField,
    const NUMBER_OF_LIMBS: usize,
    const BIT_LEN_LIMB: usize,
> {
    pub(crate) i0: AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    pub(crate) i1: AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
}

/// Integer2Chip for instructions in GF(p^2) with prime p and irreducible polynomial X^2+1
#[derive(Clone, Debug)]
pub struct Integer2Chip<
    W: PrimeField,
    N: PrimeField,
    const NUMBER_OF_LIMBS: usize,
    const BIT_LEN_LIMB: usize,
> {
    integer_chip: IntegerChip<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
}

impl<W: PrimeField, N: PrimeField, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize>
    Integer2Chip<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
{
    pub fn new(config: IntegerConfig, rns: Rc<Rns<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>>) -> Self {
        let integer_chip = IntegerChip::new(config, rns);

        Integer2Chip { integer_chip }
    }

    pub fn rns(&self) -> Rc<Rns<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>> {
        self.integer_chip.rns()
    }

    pub fn main_gate(&self) -> &MainGate<N> {
        self.integer_chip.main_gate()
    }

    pub fn reduce(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        a: &AssignedInteger2<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger2<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, PlonkError> {
        let i0 = self.integer_chip.reduce(ctx, &a.i0)?;
        let i1 = self.integer_chip.reduce(ctx, &a.i1)?;

        Ok(AssignedInteger2 { i0, i1 })
    }

    pub fn assign_constant(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        x: (W, W),
    ) -> Result<AssignedInteger2<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, PlonkError> {
        let i0 = self.integer_chip.assign_constant(ctx, x.0)?;
        let i1 = self.integer_chip.assign_constant(ctx, x.1)?;

        Ok(AssignedInteger2 { i0, i1 })
    }

    pub fn assert_equal(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        a: &AssignedInteger2<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        b: &AssignedInteger2<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<(), PlonkError> {
        self.integer_chip.assert_equal(ctx, &a.i0, &b.i0)?;
        self.integer_chip.assert_equal(ctx, &a.i1, &b.i1)?;

        Ok(())
    }

    pub fn assert_zero(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        a: &AssignedInteger2<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<(), PlonkError> {
        // temporary
        let a = self.reduce(ctx, a)?;
        self.integer_chip.assert_zero(ctx, &a.i0)?;
        self.integer_chip.assert_zero(ctx, &a.i1)?;

        Ok(())
    }

    pub fn assert_not_equal(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        a: &AssignedInteger2<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        b: &AssignedInteger2<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<(), PlonkError> {
        let c = &self.sub(ctx, a, b)?;
        self.assert_not_zero(ctx, c)?;
        Ok(())
    }

    pub fn assert_not_zero(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        a: &AssignedInteger2<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<(), PlonkError> {
        // a0*a0 + a1*a1 != 0
        let norm = self.norm(ctx, a)?;
        self.integer_chip.assert_not_zero(ctx, &norm)?;

        Ok(())
    }

    pub fn add(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        a: &AssignedInteger2<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        b: &AssignedInteger2<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger2<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, PlonkError> {
        let i0 = self.integer_chip.add(ctx, &a.i0, &b.i0)?;
        let i1 = self.integer_chip.add(ctx, &a.i1, &b.i1)?;

        Ok(AssignedInteger2 { i0, i1 })
    }

    pub fn sub(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        a: &AssignedInteger2<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        b: &AssignedInteger2<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger2<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, PlonkError> {
        let i0 = self.integer_chip.sub(ctx, &a.i0, &b.i0)?;
        let i1 = self.integer_chip.sub(ctx, &a.i1, &b.i1)?;

        Ok(AssignedInteger2 { i0, i1 })
    }

    pub fn sub_sub(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        a: &AssignedInteger2<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        b: &AssignedInteger2<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        c: &AssignedInteger2<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger2<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, PlonkError> {
        let i0 = self.integer_chip.sub_sub(ctx, &a.i0, &b.i0, &c.i0)?;
        let i1 = self.integer_chip.sub_sub(ctx, &a.i1, &b.i1, &c.i1)?;

        Ok(AssignedInteger2 { i0, i1 })
    }

    pub fn neg(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        a: &AssignedInteger2<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger2<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, PlonkError> {
        let i0 = self.integer_chip.neg(ctx, &a.i0)?;
        let i1 = self.integer_chip.neg(ctx, &a.i1)?;

        Ok(AssignedInteger2 { i0, i1 })
    }

    pub fn mul(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        a: &AssignedInteger2<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        b: &AssignedInteger2<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger2<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, PlonkError> {
        let mut t1 = self.integer_chip.mul(ctx, &a.i0, &b.i0)?;
        let mut t0 = self.integer_chip.add(ctx, &a.i0, &a.i1)?;
        let t2 = self.integer_chip.mul(ctx, &a.i1, &b.i1)?;
        let t3 = self.integer_chip.add(ctx, &b.i0, &b.i1)?;
        let i0 = self.integer_chip.sub(ctx, &t1, &t2)?;
        t1 = self.integer_chip.add(ctx, &t1, &t2)?;
        t0 = self.integer_chip.mul(ctx, &t0, &t3)?;
        let i1 = self.integer_chip.sub(ctx, &t0, &t1)?;

        Ok(AssignedInteger2 { i0, i1 })
    }

    pub fn mul2(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        a: &AssignedInteger2<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger2<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, PlonkError> {
        let i0 = self.integer_chip.mul2(ctx, &a.i0)?;
        let i1 = self.integer_chip.mul2(ctx, &a.i1)?;

        Ok(AssignedInteger2 { i0, i1 })
    }

    pub fn mul3(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        a: &AssignedInteger2<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger2<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, PlonkError> {
        let i0 = self.integer_chip.mul3(ctx, &a.i0)?;
        let i1 = self.integer_chip.mul3(ctx, &a.i1)?;

        Ok(AssignedInteger2 { i0, i1 })
    }

    pub fn square(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        a: &AssignedInteger2<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger2<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, PlonkError> {
        let t0 = self.integer_chip.square(ctx, &a.i0)?;
        let t1 = self.integer_chip.square(ctx, &a.i1)?;
        let i0 = self.integer_chip.sub(ctx, &t0, &t1)?;

        let t2 = self.integer_chip.mul(ctx, &a.i0, &a.i1)?;
        let i1 = self.integer_chip.mul2(ctx, &t2)?;

        Ok(AssignedInteger2 { i0, i1 })
    }

    pub fn norm(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        a: &AssignedInteger2<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, PlonkError> {
        let t0 = self.integer_chip.square(ctx, &a.i0)?;
        let t1 = self.integer_chip.square(ctx, &a.i1)?;
        self.integer_chip.add(ctx, &t0, &t1)
    }

    pub fn div_incomplete(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        a: &AssignedInteger2<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        b: &AssignedInteger2<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger2<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, PlonkError> {
        let norm = self.norm(ctx, b)?;
        let norm_inv = self.integer_chip.invert_incomplete(ctx, &norm)?;

        let i0 = self.integer_chip.mul(ctx, &b.i0, &norm_inv)?;
        let mut i1 = self.integer_chip.mul(ctx, &b.i1, &norm_inv)?;
        i1 = self.integer_chip.neg(ctx, &i1)?;
        let b_inv = AssignedInteger2 { i0, i1 };

        self.mul(ctx, a, &b_inv)
    }

    pub fn select(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        a: &AssignedInteger2<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        b: &AssignedInteger2<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        cond: &AssignedCondition<N>,
    ) -> Result<AssignedInteger2<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, PlonkError> {
        let i0 = self.integer_chip.select(ctx, &a.i0, &b.i0, cond)?;
        let i1 = self.integer_chip.select(ctx, &a.i1, &b.i1, cond)?;

        Ok(AssignedInteger2 { i0, i1 })
    }
}
