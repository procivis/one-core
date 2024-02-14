use std::vec;

use uuid::Uuid;

use crate::model::{
    common::ExactColumn,
    credential_schema::{
        CredentialSchema, CredentialSchemaId, CredentialSchemaRelations, GetCredentialSchemaList,
        GetCredentialSchemaQuery, UpdateCredentialSchemaRequest,
    },
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
    ) -> Result<GetCredentialSchemaList, DataLayerError>;

    async fn update_credential_schema(
        &self,
        schema: UpdateCredentialSchemaRequest,
    ) -> Result<(), DataLayerError>;
}

impl dyn CredentialSchemaRepository {
    pub async fn get_by_name_and_organisation(
        &self,
        name: &str,
        organisation_id: Uuid,
    ) -> Result<Option<CredentialSchema>, DataLayerError> {
        let mut schema = self
            .get_credential_schema_list(GetCredentialSchemaQuery {
                page: 0,
                page_size: 1,
                organisation_id: organisation_id.to_string(),
                name: Some(name.to_owned()),
                exact: Some(vec![ExactColumn::Name]),
                sort: None,
                sort_direction: None,
                ids: None,
            })
            .await?;

        Ok(schema.values.pop())
    }
}
