use halo2wrong::halo2::plonk;

#[derive(Debug)]
pub enum Error {
    InvalidIndex,
    InvalidLength,
    VerifyFailed,
    Circuit(plonk::Error),
}
