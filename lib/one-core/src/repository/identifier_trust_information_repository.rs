use async_trait::async_trait;
use shared_types::{IdentifierId, IdentifierTrustInformationId};

use crate::model::identifier_trust_information::IdentifierTrustInformation;
use crate::repository::error::DataLayerError;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait]
pub trait IdentifierTrustInformationRepository: Send + Sync {
    async fn create(
        &self,
        trust_information: IdentifierTrustInformation,
    ) -> Result<IdentifierTrustInformationId, DataLayerError>;
    async fn get_by_identifier_id(
        &self,
        identifier_id: &IdentifierId,
    ) -> Result<Vec<IdentifierTrustInformation>, DataLayerError>;
    /// Hard-deletes all trust information rows belonging to `identifier_id`.
    async fn delete_by_identifier_id(
        &self,
        identifier_id: &IdentifierId,
    ) -> Result<(), DataLayerError>;
}
