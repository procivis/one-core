use std::sync::Arc;

use shared_types::{CredentialSchemaId, OrganisationId};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::model::credential_schema::{
    CredentialSchema, CredentialSchemaRelations, GetCredentialSchemaList, GetCredentialSchemaQuery,
    UpdateCredentialSchemaRequest,
};
use crate::model::history::{History, HistoryAction, HistoryEntityType};
use crate::model::organisation::Organisation;
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
        let local_import_source_url = self
            .core_base_url
            .as_ref()
            .map(|core_base_url| format!("{core_base_url}/ssi/schema/v1/{}", request.id));
        let history_action =
            if local_import_source_url.as_ref() == Some(&request.imported_source_url) {
                HistoryAction::Created
            } else {
                HistoryAction::Imported
            };

        let organisation = self.get_organisation(&request).await?;

        let result = self
            .inner
            .create_credential_schema(request.to_owned())
            .await?;

        self.write_history(&request, organisation, history_action)
            .await;

        Ok(result)
    }

    async fn delete_credential_schema(
        &self,
        credential_schema: &CredentialSchema,
    ) -> Result<(), DataLayerError> {
        let organisation = self.get_organisation(credential_schema).await?;

        self.inner
            .delete_credential_schema(credential_schema)
            .await?;

        self.write_history(credential_schema, organisation, HistoryAction::Deleted)
            .await;

        Ok(())
    }

    async fn update_credential_schema(
        &self,
        schema: UpdateCredentialSchemaRequest,
    ) -> Result<(), DataLayerError> {
        self.inner.update_credential_schema(schema).await
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

    async fn get_by_schema_id_and_organisation(
        &self,
        schema_id: &str,
        organisation_id: OrganisationId,
        relations: &CredentialSchemaRelations,
    ) -> Result<Option<CredentialSchema>, DataLayerError> {
        self.inner
            .get_by_schema_id_and_organisation(schema_id, organisation_id, relations)
            .await
    }
}

impl CredentialSchemaHistoryDecorator {
    async fn get_organisation(
        &self,
        credential_schema: &CredentialSchema,
    ) -> Result<Organisation, DataLayerError> {
        Ok(match &credential_schema.organisation {
            Some(organisation) => organisation.to_owned(),
            None => {
                let credential_schema = self
                    .inner
                    .get_credential_schema(
                        &credential_schema.id,
                        &CredentialSchemaRelations {
                            organisation: Some(Default::default()),
                            ..Default::default()
                        },
                    )
                    .await?
                    .ok_or(DataLayerError::MappingError)?;

                credential_schema
                    .organisation
                    .ok_or(DataLayerError::MappingError)?
            }
        })
    }

    async fn write_history(
        &self,
        credential_schema: &CredentialSchema,
        organisation: Organisation,
        action: HistoryAction,
    ) {
        let result = self
            .history_repository
            .create_history(History {
                id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                action,
                name: credential_schema.name.to_owned(),
                target: None,
                entity_id: Some(credential_schema.id.into()),
                entity_type: HistoryEntityType::CredentialSchema,
                metadata: None,
                organisation_id: Some(organisation.id),
                user: self.session_provider.session().user(),
            })
            .await;

        if let Err(err) = result {
            tracing::warn!("failed to insert credential schema history event: {err:?}");
        }
    }
}
