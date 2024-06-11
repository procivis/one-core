use shared_types::{CredentialSchemaId, OrganisationId};

use crate::model::credential_schema::{
    CredentialSchema, CredentialSchemaRelations, GetCredentialSchemaList, GetCredentialSchemaQuery,
    UpdateCredentialSchemaRequest,
};

use super::error::DataLayerError;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait CredentialSchemaRepository: Send + Sync {
    async fn create_credential_schema(
        &self,
        request: CredentialSchema,
    ) -> Result<CredentialSchemaId, DataLayerError>;

    async fn delete_credential_schema(&self, id: &CredentialSchemaId)
        -> Result<(), DataLayerError>;

    async fn get_credential_schema(
        &self,
        id: &CredentialSchemaId,
        relations: &CredentialSchemaRelations,
    ) -> Result<Option<CredentialSchema>, DataLayerError>;

    async fn get_credential_schema_list(
        &self,
        query_params: GetCredentialSchemaQuery,
        relations: &CredentialSchemaRelations,
    ) -> Result<GetCredentialSchemaList, DataLayerError>;

    async fn update_credential_schema(
        &self,
        schema: UpdateCredentialSchemaRequest,
    ) -> Result<(), DataLayerError>;

    async fn get_by_schema_id_and_organisation(
        &self,
        schema_id: &str,
        organisation_id: OrganisationId,
        relations: &CredentialSchemaRelations,
    ) -> Result<Option<CredentialSchema>, DataLayerError>;
}
