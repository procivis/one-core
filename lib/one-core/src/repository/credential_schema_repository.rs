use std::sync::Arc;

use shared_types::{CredentialSchemaId, OrganisationId};

use super::error::DataLayerError;
use crate::model::credential_schema::{
    CredentialSchema, CredentialSchemaListQuery, GetCredentialSchemaList,
    UpdateCredentialSchemaRequest,
};
use crate::model::relation::AsyncModelLoader;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait CredentialSchemaRepository: Send + Sync {
    async fn create_credential_schema(
        &self,
        request: CredentialSchema,
    ) -> Result<CredentialSchemaId, DataLayerError>;

    async fn delete_credential_schema(
        &self,
        credential_schema: &CredentialSchema,
    ) -> Result<(), DataLayerError>;

    async fn get_credential_schema(
        &self,
        id: &CredentialSchemaId,
    ) -> Result<CredentialSchema, DataLayerError>;

    async fn get_credential_schema_list(
        &self,
        query_params: CredentialSchemaListQuery,
    ) -> Result<GetCredentialSchemaList, DataLayerError>;

    async fn update_credential_schema(
        &self,
        id: &CredentialSchemaId,
        schema: UpdateCredentialSchemaRequest,
    ) -> Result<(), DataLayerError>;

    async fn get_by_schema_id_and_organisation(
        &self,
        schema_id: &str,
        organisation_id: OrganisationId,
    ) -> Result<Option<CredentialSchema>, DataLayerError>;
}

#[async_trait::async_trait]
impl AsyncModelLoader<CredentialSchema> for Arc<dyn CredentialSchemaRepository> {
    async fn load(&self, id: &CredentialSchemaId) -> Result<CredentialSchema, DataLayerError> {
        self.get_credential_schema(id).await
    }
}
