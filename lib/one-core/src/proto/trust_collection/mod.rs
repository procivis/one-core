use dto::RemoteTrustCollectionInfoDTO;
use shared_types::{OrganisationId, TrustCollectionId};

use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};

pub(crate) mod dto;
pub(crate) mod manager;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait TrustCollectionManager: Send + Sync {
    async fn create_empty_trust_collections(
        &self,
        provider_metadata_url: &str,
        collections: Vec<RemoteTrustCollectionInfoDTO>,
        organisation_id: OrganisationId,
    ) -> Result<Vec<TrustCollectionId>, Error>;
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Invalid URL")]
    InvalidUrl,
    #[error("URL parse error: `{0}`")]
    UrlParse(#[from] url::ParseError),

    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for Error {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::UrlParse(_) | Self::InvalidUrl => ErrorCode::BR_0047,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}
