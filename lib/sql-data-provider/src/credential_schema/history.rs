use std::sync::Arc;

use one_core::model::credential_schema::{
    CredentialSchema, CredentialSchemaRelations, CredentialSchemaType, GetCredentialSchemaList,
    GetCredentialSchemaQuery, UpdateCredentialSchemaRequest,
};
use one_core::model::history::{History, HistoryAction, HistoryEntityType};
use one_core::repository::credential_schema_repository::CredentialSchemaRepository;
use one_core::repository::error::DataLayerError;
use one_core::repository::history_repository::HistoryRepository;
use shared_types::{CredentialSchemaId, OrganisationId};
use time::OffsetDateTime;
use uuid::Uuid;

pub struct CredentialSchemaHistoryDecorator {
    pub history_repository: Arc<dyn HistoryRepository>,
    pub inner: Arc<dyn CredentialSchemaRepository>,
}

#[async_trait::async_trait]
impl CredentialSchemaRepository for CredentialSchemaHistoryDecorator {
    async fn create_credential_schema(
        &self,
        request: CredentialSchema,
    ) -> Result<CredentialSchemaId, DataLayerError> {
        self.inner.create_credential_schema(request.clone()).await
    }

    async fn delete_credential_schema(
        &self,
        credential_schema: &CredentialSchema,
    ) -> Result<(), DataLayerError> {
        self.inner
            .delete_credential_schema(credential_schema)
            .await?;

        let Some(organisation) = &credential_schema.organisation else {
            tracing::warn!(
                "failed to insert credential schema history event. missing organisation"
            );
            return Ok(());
        };

        let result = self
            .history_repository
            .create_history(History {
                id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                action: HistoryAction::Deleted,
                name: credential_schema.name.to_owned(),
                entity_id: Some(credential_schema.id.into()),
                entity_type: HistoryEntityType::CredentialSchema,
                metadata: None,
                organisation_id: organisation.id,
            })
            .await;

        if let Err(err) = result {
            tracing::warn!("failed to insert credential schema history event: {err:?}");
        }

        Ok(())
    }

    async fn get_credential_schema(
        &self,
        id: &CredentialSchemaId,
        relations: &CredentialSchemaRelations,
    ) -> Result<Option<CredentialSchema>, DataLayerError> {
        self.inner.get_credential_schema(id, relations).await
    }

    async fn get_credential_schema_list(
        &self,
        query_params: GetCredentialSchemaQuery,
        relations: &CredentialSchemaRelations,
    ) -> Result<GetCredentialSchemaList, DataLayerError> {
        self.inner
            .get_credential_schema_list(query_params, relations)
            .await
    }

    async fn update_credential_schema(
        &self,
        schema: UpdateCredentialSchemaRequest,
    ) -> Result<(), DataLayerError> {
        self.inner.update_credential_schema(schema).await
    }

    async fn get_by_schema_id_and_organisation(
        &self,
        schema_id: &str,
        schema_type: CredentialSchemaType,
        organisation_id: OrganisationId,
        relations: &CredentialSchemaRelations,
    ) -> Result<Option<CredentialSchema>, DataLayerError> {
        self.inner
            .get_by_schema_id_and_organisation(schema_id, schema_type, organisation_id, relations)
            .await
    }
}
