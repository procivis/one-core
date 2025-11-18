use shared_types::{ClaimSchemaId, CredentialSchemaId};

use super::error::DataLayerError;
use crate::model::claim_schema::{ClaimSchema, ClaimSchemaRelations};

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait ClaimSchemaRepository: Send + Sync {
    async fn create_claim_schema_list(
        &self,
        request: Vec<ClaimSchema>,
        credential_schema_id: CredentialSchemaId,
    ) -> Result<(), DataLayerError>;

    async fn get_claim_schema_list(
        &self,
        id: Vec<ClaimSchemaId>,
        relations: &ClaimSchemaRelations,
    ) -> Result<Vec<ClaimSchema>, DataLayerError>;
}
