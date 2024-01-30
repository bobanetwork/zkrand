use halo2wrong::halo2::plonk;

#[derive(Debug)]
pub enum Error {
    InvalidParams {
        threshold: usize,
        number_of_members: usize,
    },
    InvalidIndex {
        index: usize,
    },
    InvalidOrder {
        index: usize,
    },
    VerifyFailed,
    Circuit(plonk::Error),
}
