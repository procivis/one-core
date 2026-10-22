use shared_types::CredentialId;
use thiserror::Error;

use crate::error::{ErrorCode, ErrorCodeMixin};

#[derive(Debug, Clone, PartialEq)]
pub struct DigitalCredentialRegistration {
    pub credential_id: CredentialId,
    pub metadata: DigitalCredentialMetadata,
    pub claims: Vec<DigitalCredentialClaim>,
    pub display: DigitalCredentialDisplay,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DigitalCredentialClaim {
    pub path: Vec<String>,
    pub display_name: Option<String>,
    pub selectively_disclosable: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DigitalCredentialDisplay {
    pub credential_name: String,
    pub issuer_name: Option<String>,
    pub logo: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum DigitalCredentialMetadata {
    SdJwtVc { vct: String },
    Mdoc { doctype: String },
}

/// Provider of native credential manager (for DC-API)
#[cfg_attr(test, mockall::automock)]
#[async_trait::async_trait]
pub trait NativeCredentialManager: Send + Sync {
    async fn synchronize(
        &self,
        credentials: Vec<DigitalCredentialRegistration>,
    ) -> Result<(), CredentialManagerError>;
}

#[cfg_attr(test, mockall::automock)]
pub trait NativeDcApiResponseHandler: Send + Sync {
    fn on_submit(&self, response: String) -> Result<(), CredentialManagerError>;
    fn on_reject(&self) -> Result<(), CredentialManagerError>;
}

impl std::fmt::Debug for dyn NativeDcApiResponseHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeDcApiResponseHandler")
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Error, Clone)]
pub enum CredentialManagerError {
    #[error("Credential manager synchronization failure: `{reason}`")]
    SynchronizationError { reason: String },
    #[error("Unknown credential manager error: {reason}")]
    Unknown { reason: String },
}

impl ErrorCodeMixin for CredentialManagerError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::SynchronizationError { .. } => ErrorCode::BR_0516,
            Self::Unknown { .. } => ErrorCode::BR_0000,
        }
    }
}
