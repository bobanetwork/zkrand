use halo2wrong::halo2::plonk;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("invalid params ({threshold:?}, {number_of_members:?})")]
    InvalidParams {
        threshold: usize,
        number_of_members: usize,
    },
    #[error("invalid index {index:?}")]
    InvalidIndex { index: usize },
    #[error("invalid index order {index:?}")]
    InvalidOrder { index: usize },
    #[error("verification failed")]
    VerifyFailed,
    #[error("circuit error {0:?}")]
    Circuit(plonk::Error),
}
