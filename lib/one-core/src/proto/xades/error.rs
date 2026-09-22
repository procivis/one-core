use thiserror::Error;
use x509_parser::error::X509Error;

use super::c14n::C14nError;
use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};
use crate::provider::key_algorithm::error::KeyAlgorithmError;
use crate::provider::key_algorithm::key::KeyHandleError;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Signing time is in the future")]
    SigningTimeInFuture,
    #[error("Document contains no enveloped signature")]
    MissingEnvelopedSignature,
    #[error("Invalid XML Document: `{0}`")]
    InvalidDocument(String),
    #[error("Signature suite not supported: `{0}`")]
    UnsupportedSuite(String),
    #[error("SignedInfo contains no Reference for {0}")]
    MissingReference(String),
    #[error("Incorrect Reference Transform algorithms: {0}")]
    InvalidTransformsInReference(String),
    #[error("Digest computed for {0} does not match")]
    IncorrectDigest(String),
    #[error("KeyInfo contains no X509Data for signing certificate {0}")]
    SigningCertificateNotFound(String),
    #[error("Invalid XAdES signature: {0}")]
    InvalidSignature(String),
    #[error("No x5c certificates in chain")]
    EmptyCertificateChain,

    #[error("Failed to parse XML: `{0}`")]
    RoXMLParsing(#[from] roxmltree::Error),
    #[error("Invalid b64: `{0}`")]
    Base64Encoding(#[from] ct_codecs::Error),
    #[error("Could not canonize: `{0}`")]
    C14n(#[from] C14nError),
    #[error("Key Algorithm Error: `{0}`")]
    KeyAlgorithm(#[from] KeyAlgorithmError),
    #[error("Key Handle Error: `{0}`")]
    KeyHandleError(#[from] KeyHandleError),
    #[error("Certificate parsing error: `{0}`")]
    CertificateParsing(#[from] asn1_rs::Err<X509Error>),
    #[error("Hash error: `{0}`")]
    HasherError(#[from] one_crypto::HasherError),
    #[error("Serde Error: `{0}`")]
    SerdeDe(#[from] quick_xml::DeError),
    #[error("Serde Error: `{0}`")]
    SerdeSe(#[from] quick_xml::SeError),
    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for Error {
    fn error_code(&self) -> ErrorCode {
        match self {
            // Signature verification failures
            Self::InvalidSignature(_) | Self::IncorrectDigest(_) => ErrorCode::BR_0410,

            // Malformed or invalid signature payload
            Self::MissingEnvelopedSignature
            | Self::MissingReference(_)
            | Self::InvalidTransformsInReference(_)
            | Self::InvalidDocument(_)
            | Self::RoXMLParsing(_)
            | Self::Base64Encoding(_)
            | Self::SerdeDe(_)
            | Self::SerdeSe(_)
            | Self::C14n(_) => ErrorCode::BR_0332,

            // Signing time validation
            Self::SigningTimeInFuture => ErrorCode::BR_0324,

            // Certificate errors
            Self::SigningCertificateNotFound(_) => ErrorCode::BR_0223,
            Self::EmptyCertificateChain | Self::CertificateParsing(_) => ErrorCode::BR_0224,

            // Key/algorithm errors
            Self::UnsupportedSuite(_) | Self::KeyAlgorithm(_) => ErrorCode::BR_0063,
            Self::KeyHandleError(_) => ErrorCode::BR_0201,

            // Crypto errors
            Self::HasherError(_) => ErrorCode::BR_0050,

            Self::Nested(nested) => nested.error_code(),
        }
    }
}
