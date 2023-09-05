use crate::{
    model::credential_schema::{
        CredentialSchema, CredentialSchemaId, CredentialSchemaRelations, GetCredentialSchemaList,
        GetCredentialSchemaQuery,
    },
    repository::error::DataLayerError,
};
use mockall::*;

#[derive(Default)]
struct CredentialSchemaRepository;

mock! {
    pub CredentialSchemaRepository {
        pub fn create_credential_schema(
            &self,
            request: CredentialSchema,
        ) -> Result<CredentialSchemaId, DataLayerError>;

        pub fn delete_credential_schema(&self, id: &CredentialSchemaId)
            -> Result<(), DataLayerError>;

        pub fn get_credential_schema(
            &self,
            id: &CredentialSchemaId,
            relations: &CredentialSchemaRelations,
        ) -> Result<CredentialSchema, DataLayerError>;

        pub fn get_credential_schema_list(
            &self,
            query_params: GetCredentialSchemaQuery,
        ) -> Result<GetCredentialSchemaList, DataLayerError>;
    }
}

#[async_trait::async_trait]
impl crate::repository::credential_schema_repository::CredentialSchemaRepository
    for MockCredentialSchemaRepository
{
    async fn create_credential_schema(
        &self,
        request: CredentialSchema,
    ) -> Result<CredentialSchemaId, DataLayerError> {
        self.create_credential_schema(request)
    }

    async fn delete_credential_schema(
        &self,
        id: &CredentialSchemaId,
    ) -> Result<(), DataLayerError> {
        self.delete_credential_schema(id)
    }

    async fn get_credential_schema(
        &self,
        id: &CredentialSchemaId,
        relations: &CredentialSchemaRelations,
    ) -> Result<CredentialSchema, DataLayerError> {
        self.get_credential_schema(id, relations)
    }

    async fn get_credential_schema_list(
        &self,
        query_params: GetCredentialSchemaQuery,
    ) -> Result<GetCredentialSchemaList, DataLayerError> {
        self.get_credential_schema_list(query_params)
    }
}
