use crate::model::credential_schema::{
    CredentialSchema, CredentialSchemaId, CredentialSchemaRelations, GetCredentialSchemaList,
    GetCredentialSchemaQuery,
};

use super::error::DataLayerError;

#[async_trait::async_trait]
pub trait CredentialSchemaRepository {
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
    ) -> Result<CredentialSchema, DataLayerError>;

    async fn get_credential_schema_list(
        &self,
        query_params: GetCredentialSchemaQuery,
    ) -> Result<GetCredentialSchemaList, DataLayerError>;
}
