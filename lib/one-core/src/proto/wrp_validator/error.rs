use std::string::FromUtf8Error;

use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};
use crate::proto::certificate_validator::CertContext;

#[derive(Debug, thiserror::Error)]
pub(crate) enum WRPValidatorError {
    #[error("Access certificate not trusted")]
    AccessCertificateNotTrusted,
    #[error("Registration certificate not trusted")]
    RegistrationCertificateNotTrusted,
    #[error(
        "Registration certificate mismatch field: `{field_name}`: `{first_value}` != `{second_value}`"
    )]
    RegistrationCertificateMissmatch {
        field_name: String,
        first_value: String,
        second_value: String,
    },
    #[error("Issuer not on trust list for {role}")]
    IssuerNotTrusted { role: &'static str },
    #[error("Registry not trusted")]
    RegistryNotTrusted,
    #[error("Wallet provider not on trust list")]
    WalletProviderNotTrusted,
    #[error("{0}: certificate is revoked")]
    CertificateRevoked(CertContext),
    #[error(
        "Access certificate does not match registration certificate: {field} expected `{expected}` got `{actual}`"
    )]
    AccessRegistrationCertificateMismatch {
        field: &'static str,
        expected: String,
        actual: String,
    },
    #[error("Invalid registry URL: `{0}`")]
    InvalidRegistryUrl(String),
    #[error("Missing registry key: `{0:?}`")]
    MissingRegistryKey(Option<String>),
    #[error("Missing signing details")]
    MissingSigningDetails,
    #[error("Invalid signing method: `{0}`")]
    InvalidSigningMethod(String),

    #[error("Missing issuer")]
    MissingIssuer,
    #[error("URL parsing error: `{0}`")]
    URLParsing(#[from] url::ParseError),
    #[error("From UTF-8 error: `{0}`")]
    FromUtf8Error(#[from] FromUtf8Error),

    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for WRPValidatorError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::CertificateRevoked(_) => ErrorCode::BR_0212,
            Self::AccessCertificateNotTrusted => ErrorCode::BR_0486,
            Self::RegistrationCertificateNotTrusted => ErrorCode::BR_0489,
            Self::IssuerNotTrusted { .. } => ErrorCode::BR_0488,
            Self::RegistryNotTrusted => ErrorCode::BR_0493,
            Self::WalletProviderNotTrusted => ErrorCode::BR_0494,
            Self::AccessRegistrationCertificateMismatch { .. } => ErrorCode::BR_0491,
            Self::MissingIssuer => ErrorCode::BR_0492,
            Self::MissingSigningDetails
            | Self::MissingRegistryKey(_)
            | Self::InvalidRegistryUrl(_)
            | Self::InvalidSigningMethod(_)
            | Self::RegistrationCertificateMissmatch { .. } => ErrorCode::BR_0224,
            Self::URLParsing(_) | Self::FromUtf8Error(_) => ErrorCode::BR_0047,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}
