use std::sync::Arc;

use shared_types::{IdentifierId, TrustListPublisherId};

use crate::error::{ContextWithErrorCode, ErrorCode, ErrorCodeMixin, NestedError};
use crate::model::list_filter::ListFilterValue;
use crate::model::trust_list_publication::{
    TrustListPublicationFilterValue, TrustListPublicationListQuery,
};
use crate::provider::trust_list_publisher::provider::TrustListPublisherProvider;
use crate::repository::trust_list_publication_repository::TrustListPublicationRepository;

#[cfg(test)]
mod test;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait TrustListRegenerator: Send + Sync {
    /// Refreshes every publication containing the identifier.
    async fn regenerate_for_identifier(&self, identifier_id: IdentifierId) -> Result<(), Error>;
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Missing trust list publisher `{0}`")]
    MissingPublisher(TrustListPublisherId),
    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for Error {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::MissingPublisher(_) => ErrorCode::BR_0388,
            Self::Nested(error) => error.error_code(),
        }
    }
}

pub struct TrustListRegeneratorImpl {
    publication_repository: Arc<dyn TrustListPublicationRepository>,
    publisher_provider: Arc<dyn TrustListPublisherProvider>,
}

impl TrustListRegeneratorImpl {
    pub fn new(
        publication_repository: Arc<dyn TrustListPublicationRepository>,
        publisher_provider: Arc<dyn TrustListPublisherProvider>,
    ) -> Self {
        Self {
            publication_repository,
            publisher_provider,
        }
    }
}

#[async_trait::async_trait]
impl TrustListRegenerator for TrustListRegeneratorImpl {
    async fn regenerate_for_identifier(&self, identifier_id: IdentifierId) -> Result<(), Error> {
        let publications = self
            .publication_repository
            .list(TrustListPublicationListQuery {
                filtering: Some(
                    TrustListPublicationFilterValue::TrustEntryIdentifierId(identifier_id)
                        .condition(),
                ),
                include_count: false,
                ..Default::default()
            })
            .await
            .error_while("listing trust lists containing identifier")?;

        for publication in publications.values {
            let publisher = self
                .publisher_provider
                .get(&publication.r#type)
                .ok_or_else(|| Error::MissingPublisher(publication.r#type.clone()))?;
            publisher
                .regenerate_content(publication.id)
                .await
                .error_while("regenerating trust list content")?;
        }

        Ok(())
    }
}
