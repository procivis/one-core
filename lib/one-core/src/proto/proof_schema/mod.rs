use shared_types::{CredentialFormat, ProofSchemaId};

use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};
use crate::model::organisation::Organisation;
use crate::service::proof_schema::dto::ImportProofSchemaDTO;

pub(crate) mod importer;
pub(crate) mod mapper;
pub(crate) mod validator;

/// Imports proof schemas, together with the credential schemas they reference.
#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub(crate) trait ProofSchemaImporter: Send + Sync {
    /// Imports the given proof schema, importing the referenced credential schemas which are not
    /// present yet.
    async fn import_proof_schema(
        &self,
        schema: ImportProofSchemaDTO,
        id: ProofSchemaId,
        organisation: &Organisation,
        imported_source_url: String,
    ) -> Result<(), Error>;

    /// Downloads the proof schema published under `url` and imports it.
    async fn import_proof_schema_from_url(
        &self,
        url: &str,
        organisation: &Organisation,
    ) -> Result<(), Error>;
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error("Proof schema already exists")]
    AlreadyExists,
    #[error("Unsupported datatype: {0}")]
    UnsupportedDatatype(String),
    #[error("Unsupported format: {0}")]
    UnsupportedFormat(CredentialFormat),

    #[expect(clippy::enum_variant_names)]
    #[error("Mapping error: `{0}`")]
    MappingError(String),

    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for Error {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::AlreadyExists => ErrorCode::BR_0015,
            Self::UnsupportedDatatype(_) | Self::UnsupportedFormat(_) => ErrorCode::BR_0135,
            Self::MappingError(_) => ErrorCode::BR_0047,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}
