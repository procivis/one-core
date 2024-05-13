use shared_types::{CredentialSchemaId, OrganisationId};

use crate::{
    model::{
        credential_schema::{
            CredentialSchema, CredentialSchemaRelations, GetCredentialSchemaList,
            GetCredentialSchemaQuery, UpdateCredentialSchemaRequest,
        },
        list_filter::{ListFilterValue, StringMatch, StringMatchType},
        list_query::ListPagination,
    },
    service::credential_schema::dto::CredentialSchemaFilterValue,
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
    ) -> Result<Option<CredentialSchema>, DataLayerError>;
}

impl dyn CredentialSchemaRepository {
    pub async fn get_by_name_and_organisation(
        &self,
        name: &str,
        organisation_id: OrganisationId,
    ) -> Result<Option<CredentialSchema>, DataLayerError> {
        let mut schema = self
            .get_credential_schema_list(
                GetCredentialSchemaQuery {
                    pagination: Some(ListPagination {
                        page: 0,
                        page_size: 1,
                    }),
                    filtering: Some(
                        CredentialSchemaFilterValue::OrganisationId(organisation_id).condition()
                            & CredentialSchemaFilterValue::Name(StringMatch {
                                r#match: StringMatchType::Equals,
                                value: name.to_owned(),
                            }),
                    ),
                    ..Default::default()
                },
                &Default::default(),
            )
            .await?;

        Ok(schema.values.pop())
    }
}
