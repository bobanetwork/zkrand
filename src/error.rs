use halo2wrong::halo2::plonk;

#[derive(Debug)]
pub enum Error {
    InvalidIndex { index: usize },
    InvalidOrder { index: usize },
    VerifyFailed,
    Circuit(plonk::Error),
}
