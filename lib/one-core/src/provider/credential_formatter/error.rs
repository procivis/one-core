use one_crypto::CryptoProviderError;
use thiserror::Error;

use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};

#[derive(Debug, PartialEq, Eq, Error)]
pub enum ParseError {
    #[error("Failed: `{0}`")]
    Failed(String),
}

#[derive(Debug, Error)]
pub enum FormatterError {
    #[error("Failed: `{0}`")]
    Failed(String),
    #[error("Could not sign: `{0}`")]
    CouldNotSign(String),
    #[error("Could not verify: `{0}`")]
    CouldNotVerify(String),
    #[error("Could not format: `{0}`")]
    CouldNotFormat(String),
    #[error("Could not extract credentials: `{0}`")]
    CouldNotExtractCredentials(String),
    #[error("Could not extract presentation: `{0}`")]
    CouldNotExtractPresentation(String),
    #[error("Could not extract claims from presentation: `{0}`")]
    CouldNotExtractClaimsFromPresentation(String),
    #[error("Incorrect signature")]
    IncorrectSignature,
    #[error("Missing part")]
    MissingPart,
    #[error("Missing disclosure")]
    MissingDisclosure,
    #[error("Missing issuer")]
    MissingIssuer,
    #[error("Missing credential subject")]
    MissingHolder,
    #[error("Missing claim")]
    MissingClaim,
    #[error("Only BBS is allowed")]
    BBSOnly,
    #[error("Crypto library error: `{0}`")]
    CryptoError(#[from] CryptoProviderError),
    #[error("{formatter} formatter missing missing base url")]
    MissingBaseUrl { formatter: &'static str },
    #[error("JSON mapping error: `{0}`")]
    JsonMapping(String),
    #[error("Jsonptr assign error: `{0}`")]
    JsonPtrAssignError(#[from] jsonptr::assign::Error),
    #[error("Jsonptr parse error: `{0}`")]
    JsonPtrParseError(#[from] jsonptr::ParseError),
    #[error("Encoding error: `{0}`")]
    EncodingError(#[from] ct_codecs::Error),
    #[error("Float value is NaN")]
    FloatValueIsNaN,

    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for FormatterError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::BBSOnly => ErrorCode::BR_0090,
            Self::Failed(_)
            | Self::CouldNotSign(_)
            | Self::CouldNotVerify(_)
            | Self::CouldNotFormat(_)
            | Self::CouldNotExtractCredentials(_)
            | Self::CouldNotExtractPresentation(_)
            | Self::CouldNotExtractClaimsFromPresentation(_)
            | Self::IncorrectSignature
            | Self::MissingPart
            | Self::MissingDisclosure
            | Self::MissingIssuer
            | Self::MissingHolder
            | Self::MissingClaim
            | Self::CryptoError(_)
            | Self::MissingBaseUrl { .. }
            | Self::JsonMapping(_)
            | Self::JsonPtrAssignError(_)
            | Self::JsonPtrParseError(_)
            | Self::EncodingError(_)
            | Self::FloatValueIsNaN => ErrorCode::BR_0057,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}
