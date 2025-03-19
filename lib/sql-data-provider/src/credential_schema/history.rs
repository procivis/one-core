use std::sync::Arc;

use anyhow::Context;
use one_core::model::credential_schema::{
    CredentialSchema, CredentialSchemaRelations, CredentialSchemaType, GetCredentialSchemaList,
    GetCredentialSchemaQuery, UpdateCredentialSchemaRequest,
};
use one_core::model::history::{History, HistoryAction, HistoryEntityType};
use one_core::model::organisation::Organisation;
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

impl CredentialSchemaHistoryDecorator {
    async fn get_organisation_for_credential_schema(
        &self,
        schema_id: &CredentialSchemaId,
    ) -> Result<Organisation, DataLayerError> {
        let schema = self
            .inner
            .get_credential_schema(
                schema_id,
                &CredentialSchemaRelations {
                    organisation: Some(Default::default()),
                    ..Default::default()
                },
            )
            .await?
            .context("credential schema is missing")?;

        schema
            .organisation
            .ok_or_else(|| anyhow::anyhow!("organisation is None").into())
    }
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
        id: &CredentialSchemaId,
    ) -> Result<(), DataLayerError> {
        self.inner.delete_credential_schema(id).await?;

        let organisation = self.get_organisation_for_credential_schema(id).await?;

        let result = self
            .history_repository
            .create_history(History {
                id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                action: HistoryAction::Deleted,
                entity_id: Some((*id).into()),
                entity_type: HistoryEntityType::CredentialSchema,
                metadata: None,
                organisation_id: organisation.id,
            })
            .await;

        if let Err(err) = result {
            tracing::debug!("failed to insert credential schema history event: {err:?}");
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
