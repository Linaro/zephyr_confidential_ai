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
    #[error("IO Error")]
    Io {
        #[from]
        source: std::io::Error,
        // backtrace: Backtrace,
    },
    #[error("Error decoding json: {source:?}")]
    Json {
        #[from]
        source: serde_json::Error,
    },
    #[error("X.509 PEM Error")]
    X509Pem {
        #[from]
        source: x509_parser::nom::Err<PEMError>,
    },
    #[error("X.509 Parse Error")]
    X509ParseError {
        #[from]
        source: x509_parser::nom::Err<X509Error>,
    },
    #[error("X.509 Error")]
    X509Error {
        #[from]
        source: X509Error,
    },
    #[error("Elliptic curve error")]
    EllipticCurveError {
        #[from]
        source: p256::elliptic_curve::Error,
    },
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

    // Cose error seems rather broken, as far as using it as an error. For now,
    // we'll just make it into a String.
    #[error("COSE error {text:?}")]
    CoseLibError {
        text: String,
    },

    #[error("Unexpected keywrap algorithm {0:?}")]
    UnexpectedKeyWrap(String),

    // This can be expanded out if these need to be individually detected.
    #[error("Flow error: {0}")]
    Flow(&'static str),
}

/// The CoseError doesn't seem to want to play with other error types. Convert
/// from CoseError to a string.
pub fn wrap<T>(item: std::result::Result<T, CoseError>) -> crate::Result<T> {
    match item {
        Ok(t) => Ok(t),
        Err(e) => {
            let msg = format!("{:?}", e);
            Err(FlowError::CoseLibError {
                text: msg,
            })
        }
    }
}
