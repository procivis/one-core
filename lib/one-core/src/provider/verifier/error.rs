use thiserror::Error;

use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};

#[derive(Debug, Error)]
pub enum VerifierProviderError {
    #[error("Access certificate provisioning disabled")]
    AccessCertificateProvisioningDisabled,
    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for VerifierProviderError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::AccessCertificateProvisioningDisabled => ErrorCode::BR_0468,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}
