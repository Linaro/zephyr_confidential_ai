//! Error wrapping.
//!
//! The error type used within flow.

// use std::backtrace::Backtrace;

use coset::CoseError;
use thiserror::Error;
use x509_parser::prelude::{PEMError, X509Error};

#[derive(Error, Debug)]
pub enum FlowError {
    #[error("Session does not match payload packet")]
    SessionMismatch,
    #[error("Incorrect tag on message, expecting {0}")]
    IncorrectTag(&'static str),
    #[error("Error with COSE: {0}")]
    CoseError(&'static str),
    #[error("IO Error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Error decoding json: {0:?}")]
    Json(#[from] serde_json::Error),
    #[error("X.509 PEM Error) {0}")]
    X509Pem(#[from] x509_parser::nom::Err<PEMError>),
    #[error("X.509 Parse Error: {0}")]
    X509ParseError(#[from] x509_parser::nom::Err<X509Error>),
    #[error("X.509 Error: {0}")]
    X509Error(#[from] X509Error),
    #[error("Elliptic curve error")]
    EllipticCurveError(#[from] p256::elliptic_curve::Error),
    #[error("Invalid digest length")]
    InvalidDigestLength(#[from] sha2::digest::InvalidLength),
    #[error("Ecdsa Error: {0:?}")]
    EcdsaError(#[from] p256::ecdsa::Error),
    #[error("Base64 error: {0:?}")]
    Base64Error(#[from] base64::DecodeError),
    #[error("Cborium SER error: {0:?}")]
    CboriumSerError(#[from] ciborium::ser::Error<std::io::Error>),
    #[error("Cborium DE error: {0:?}")]
    CboriumDeError(#[from] ciborium::de::Error<std::io::Error>),
    #[error("COSE error {0:?}")]
    CoseLibError(#[from] CoseError),

    #[error("Unexpected keywrap algorithm {0:?}")]
    UnexpectedKeyWrap(String),

    // This can be expanded out if these need to be individually detected.
    #[error("Flow error: {0}")]
    Flow(&'static str),
}
