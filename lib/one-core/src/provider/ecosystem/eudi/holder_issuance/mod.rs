use std::sync::Arc;

use shared_types::{EcosystemId, OrganisationId};
use thiserror::Error;
use time::Duration;

use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};
use crate::proto::session_provider::SessionProvider;
use crate::proto::wrp_validator::WRPValidator;
use crate::proto::wrp_validator::model::TrustScope;
use crate::provider::blob_storage::provider::BlobStorageProvider;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::interaction_repository::InteractionRepository;

mod credential;
mod metadata;

/// Which trust document was checked when it failed to cover the requested credential.
#[derive(Debug, Clone, Copy, strum::Display)]
pub(crate) enum AttestationCoverageSource {
    #[strum(serialize = "registration certificate")]
    RegistrationCertificate,
    #[strum(serialize = "national registry response")]
    NationalRegistry,
}

#[derive(Debug, Error)]
pub(crate) enum HolderIssuanceError {
    #[error("Missing registry URL")]
    MissingRegistryUrl,
    #[error("Missing identifier")]
    MissingIdentifier,
    #[error("The {document} does not cover the requested credential")]
    TrustAttestationDoesNotCoverCredential { document: AttestationCoverageSource },
    #[error("Required entitlements missing from the {document}")]
    EntitlementsMissing { document: AttestationCoverageSource },
    #[error("Inconsistent trust info")]
    InconsistentTrustInfo,
    #[error("No credential configuration")]
    NoCredentialConfiguration,
    #[error("Invalid credential configuration: `{0}`")]
    InvalidCredentialConfiguration(String),

    #[error("Mapping error: `{0}`")]
    MappingError(String),
    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for HolderIssuanceError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::MissingRegistryUrl
            | Self::MissingIdentifier
            | Self::InconsistentTrustInfo
            | Self::NoCredentialConfiguration
            | Self::InvalidCredentialConfiguration(_) => ErrorCode::BR_0477,
            Self::TrustAttestationDoesNotCoverCredential { .. } => ErrorCode::BR_0490,
            Self::EntitlementsMissing { .. } => ErrorCode::BR_0501,
            Self::MappingError(_) => ErrorCode::BR_0047,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}

pub(crate) struct HolderIssuanceResolver {
    history_repository: Arc<dyn HistoryRepository>,
    interaction_repository: Arc<dyn InteractionRepository>,
    wrp_validator: Arc<dyn WRPValidator>,
    blob_storage_provider: Arc<dyn BlobStorageProvider>,
    session_provider: Arc<dyn SessionProvider>,
    formatter_provider: Arc<dyn CredentialFormatterProvider>,
    leeway: Duration,
    ecosystem: EcosystemId,
}

impl HolderIssuanceResolver {
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn new(
        history_repository: Arc<dyn HistoryRepository>,
        interaction_repository: Arc<dyn InteractionRepository>,
        wrp_validator: Arc<dyn WRPValidator>,
        blob_storage_provider: Arc<dyn BlobStorageProvider>,
        session_provider: Arc<dyn SessionProvider>,
        formatter_provider: Arc<dyn CredentialFormatterProvider>,
        leeway: Duration,
        ecosystem: EcosystemId,
    ) -> Self {
        Self {
            history_repository,
            interaction_repository,
            wrp_validator,
            blob_storage_provider,
            session_provider,
            formatter_provider,
            leeway,
            ecosystem,
        }
    }

    /// Trust may only be resolved against collections of the ecosystem being acted in.
    pub(super) fn trust_scope(&self, organisation_id: OrganisationId) -> TrustScope {
        TrustScope {
            organisation_id,
            ecosystem: self.ecosystem.to_owned(),
        }
    }
}
