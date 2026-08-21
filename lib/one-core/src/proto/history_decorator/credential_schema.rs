use std::sync::Arc;

use shared_types::{CredentialSchemaId, OrganisationId};
use uuid::Uuid;

use crate::model::credential_schema::{
    CredentialSchema, CredentialSchemaListQuery, GetCredentialSchemaList,
    UpdateCredentialSchemaRequest,
};
use crate::model::history::{History, HistoryAction, HistoryEntityType, HistorySource};
use crate::proto::session_provider::{SessionExt, SessionProvider};
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::repository::error::DataLayerError;
use crate::repository::history_repository::HistoryRepository;

pub struct CredentialSchemaHistoryDecorator {
    pub history_repository: Arc<dyn HistoryRepository>,
    pub inner: Arc<dyn CredentialSchemaRepository>,
    pub session_provider: Arc<dyn SessionProvider>,
    pub core_base_url: Option<String>,
}

#[async_trait::async_trait]
impl CredentialSchemaRepository for CredentialSchemaHistoryDecorator {
    async fn create_credential_schema(
        &self,
        request: CredentialSchema,
    ) -> Result<CredentialSchemaId, DataLayerError> {
        let local_import_source_urls = if let Some(core_base_url) = self.core_base_url.as_ref() {
            vec![
                format!("{core_base_url}/ssi/schema/v1/{}", request.id),
                format!("{core_base_url}/ssi/schema/v2/{}", request.id),
            ]
        } else {
            vec![]
        };
        let history_action = if local_import_source_urls.contains(&request.imported_source_url) {
            HistoryAction::Created
        } else {
            HistoryAction::Imported
        };

        let result = self
            .inner
            .create_credential_schema(request.to_owned())
            .await?;

        self.write_history(&request, history_action).await;

        Ok(result)
    }

    async fn delete_credential_schema(
        &self,
        credential_schema: &CredentialSchema,
    ) -> Result<(), DataLayerError> {
        self.inner
            .delete_credential_schema(credential_schema)
            .await?;

        self.write_history(credential_schema, HistoryAction::Deleted)
            .await;

        Ok(())
    }

    async fn update_credential_schema(
        &self,
        id: &CredentialSchemaId,
        schema: UpdateCredentialSchemaRequest,
    ) -> Result<(), DataLayerError> {
        self.inner.update_credential_schema(id, schema).await
    }

    async fn get_credential_schema(
        &self,
        id: &CredentialSchemaId,
    ) -> Result<CredentialSchema, DataLayerError> {
        self.inner.get_credential_schema(id).await
    }

    async fn get_credential_schema_list(
        &self,
        query_params: CredentialSchemaListQuery,
    ) -> Result<GetCredentialSchemaList, DataLayerError> {
        self.inner.get_credential_schema_list(query_params).await
    }

    async fn get_by_schema_id_and_organisation(
        &self,
        schema_id: &str,
        organisation_id: OrganisationId,
    ) -> Result<Option<CredentialSchema>, DataLayerError> {
        self.inner
            .get_by_schema_id_and_organisation(schema_id, organisation_id)
            .await
    }
}

impl CredentialSchemaHistoryDecorator {
    async fn write_history(&self, credential_schema: &CredentialSchema, action: HistoryAction) {
        let result = self
            .history_repository
            .create_history(History {
                id: Uuid::new_v4().into(),
                created_date: crate::clock::now_utc(),
                action,
                name: credential_schema.name.to_owned(),
                source: HistorySource::Core,
                target: None,
                entity_id: Some(credential_schema.id.into()),
                entity_type: HistoryEntityType::CredentialSchema,
                metadata: None,
                metadata_blob_id: None,
                organisation_id: Some(credential_schema.organisation.id()),
                user: self.session_provider.session().user(),
            })
            .await;

        if let Err(err) = result {
            tracing::warn!("failed to insert credential schema history event: {err:?}");
        }
    }
}
