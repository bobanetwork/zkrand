use halo2_maingate::AssignedCondition;
use halo2wrong::curves::ff::PrimeField;

#[cfg(feature = "g2chip")]
mod bn256;
#[cfg(feature = "g2chip")]
mod integer2;
#[cfg(feature = "g2chip")]
mod point2;
#[cfg(feature = "g2chip")]
mod point2_base_chip;
#[cfg(feature = "g2chip")]
pub use point2::Point2;
#[cfg(feature = "g2chip")]
pub use point2_base_chip::FixedPoint2Chip;

mod point_base_chip;
pub use point_base_chip::FixedPointChip;

#[derive(Default)]
pub(crate) struct Selector<F: PrimeField>(Vec<AssignedCondition<F>>);

pub(crate) struct Windowed<F: PrimeField>(Vec<Selector<F>>);
