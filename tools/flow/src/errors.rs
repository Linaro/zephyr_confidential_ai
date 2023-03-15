//! Error wrapping.
//!
//! The coset library's Error type does not implement 'std::error::Error'. Since
//! both the trait and the enum are not implemented in this crate, we need to
//! wrap this error in order to be able to make this conversion possible.

use coset::CoseError;

#[derive(Debug)]
pub struct WrappedCoseError(CoseError);

impl std::fmt::Display for WrappedCoseError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "CoseError({:?})", self.0)
    }
}

impl std::error::Error for WrappedCoseError {
}

pub fn wrap<T>(item: Result<T, CoseError>) -> Result<T, WrappedCoseError> {
    item.map_err(|e| WrappedCoseError(e))
}

// /// This trait can be brought in, to allow an Error that isn't wrapped to be wrapped.
// pub trait ErrorWrapper {
//     fn wrap<T>(Result<T, self>) -> Result<T, >
// }
