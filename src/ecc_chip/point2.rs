use crate::ecc_chip::integer2::{AssignedInteger2, Integer2};
use crate::ecc_chip::point2_base_chip::SplitBase;
use halo2_ecc::integer::rns::Rns;
use halo2wrong::curves::ff::PrimeField;
use halo2wrong::curves::CurveAffine;
use std::fmt;
use std::rc::Rc;

/// Points on E(F_p^2) with E: y^2 = x^3 + b
#[derive(Clone)]
pub struct Point2<
    W: PrimeField,
    N: PrimeField,
    const NUMBER_OF_LIMBS: usize,
    const BIT_LEN_LIMB: usize,
> {
    x: Integer2<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    y: Integer2<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
}

impl<W: PrimeField, N: PrimeField, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize>
    Point2<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
{
    pub fn new<C: CurveAffine + SplitBase<C::Base, W>>(
        rns: Rc<Rns<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>>,
        p: C,
    ) -> Self {
        let coordinates = p.coordinates().unwrap();
        let x_split = C::split_base(*coordinates.x());
        let y_split = C::split_base(*coordinates.y());
        let x = Integer2::from_fe(x_split, rns.clone());
        let y = Integer2::from_fe(y_split, rns.clone());
        Point2 { x, y }
    }

    pub fn public(&self) -> Vec<N> {
        let mut public_data = Vec::new();
        public_data.extend(self.x.limbs());
        public_data.extend(self.y.limbs());
        public_data
    }

    /// Returns $x$ coordinate
    pub fn x(&self) -> &Integer2<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        &self.x
    }

    /// Returns $y$ coordinate
    pub fn y(&self) -> &Integer2<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        &self.y
    }
}

#[derive(Clone)]
/// point on G2 that is assumed to be on curve and not infinity
pub struct AssignedPoint2<
    W: PrimeField,
    N: PrimeField,
    const NUMBER_OF_LIMBS: usize,
    const BIT_LEN_LIMB: usize,
> {
    pub(crate) x: AssignedInteger2<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    pub(crate) y: AssignedInteger2<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
}

impl<W: PrimeField, N: PrimeField, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize>
    fmt::Debug for AssignedPoint2<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("AssignedPoint on G2")
            .field("x0", &self.x.i0.native().value())
            .field("x1", &self.x.i1.native().value())
            .field("y0", &self.y.i0.native().value())
            .field("y1", &self.y.i1.native().value())
            .finish()?;
        Ok(())
    }
}

impl<W: PrimeField, N: PrimeField, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize>
    AssignedPoint2<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
{
    /// Returns $x$ coordinate
    pub fn x(&self) -> &AssignedInteger2<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        &self.x
    }

    /// Returns $y$ coordinate
    pub fn y(&self) -> &AssignedInteger2<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        &self.y
    }
}
