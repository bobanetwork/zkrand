use halo2_maingate::AssignedCondition;
use halo2wrong::curves::ff::PrimeField;

mod bn256;
mod integer2;
mod point2;
mod point2_base_chip;
mod point_base_chip;

pub use point2::Point2;
pub use point2_base_chip::FixedPoint2Chip;
pub use point_base_chip::FixedPointChip;

#[derive(Default)]
pub(crate) struct Selector<F: PrimeField>(Vec<AssignedCondition<F>>);

pub(crate) struct Windowed<F: PrimeField>(Vec<Selector<F>>);
