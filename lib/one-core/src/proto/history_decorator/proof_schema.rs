use std::sync::Arc;

use anyhow::anyhow;
use shared_types::{OrganisationId, ProofSchemaId};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::model::history::{History, HistoryAction, HistoryEntityType};
use crate::model::proof_schema::{
    GetProofSchemaList, GetProofSchemaQuery, ProofSchema, ProofSchemaRelations,
};
use crate::proto::session_provider::{SessionExt, SessionProvider};
use crate::repository::error::DataLayerError;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::proof_schema_repository::ProofSchemaRepository;

pub struct ProofSchemaHistoryDecorator {
    pub history_repository: Arc<dyn HistoryRepository>,
    pub inner: Arc<dyn ProofSchemaRepository>,
    pub session_provider: Arc<dyn SessionProvider>,
    pub core_base_url: Option<String>,
}

#[async_trait::async_trait]
impl ProofSchemaRepository for ProofSchemaHistoryDecorator {
    async fn create_proof_schema(
        &self,
        request: ProofSchema,
    ) -> Result<ProofSchemaId, DataLayerError> {
        let name = request.name.to_owned();
        let organisation_id = request
            .organisation
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("organisation is None"))?
            .id;

        let local_import_source_url = self
            .core_base_url
            .as_ref()
            .map(|core_base_url| format!("{core_base_url}/ssi/proof-schema/v1/{}", request.id));
        let history_action = match (
            local_import_source_url.as_ref(),
            &request.imported_source_url,
        ) {
            (Some(local), Some(requested)) => {
                if local == requested {
                    HistoryAction::Created
                } else {
                    HistoryAction::Imported
                }
            }
            (None, Some(_)) => HistoryAction::Imported,
            (_, None) => HistoryAction::Created,
        };

        let result = self.inner.create_proof_schema(request).await?;

        self.write_history(result, name, organisation_id, history_action)
            .await;

        Ok(result)
    }

    async fn delete_proof_schema(
        &self,
        id: &ProofSchemaId,
        deleted_at: OffsetDateTime,
    ) -> Result<(), DataLayerError> {
        let proof_schema = self
            .inner
            .get_proof_schema(
                id,
                &ProofSchemaRelations {
                    organisation: Some(Default::default()),
                    ..Default::default()
                },
            )
            .await?
            .ok_or_else(|| {
                DataLayerError::Db(anyhow!("We cannot find proof schema we just updated: {id}"))
            })?;
        let organisation = proof_schema
            .organisation
            .ok_or_else(|| anyhow::anyhow!("organisation is None"))?;

        self.inner.delete_proof_schema(id, deleted_at).await?;

        self.write_history(
            *id,
            proof_schema.name,
            organisation.id,
            HistoryAction::Deleted,
        )
        .await;

        Ok(())
    }

    async fn get_proof_schema(
        &self,
        id: &ProofSchemaId,
        relations: &ProofSchemaRelations,
    ) -> Result<Option<ProofSchema>, DataLayerError> {
        self.inner.get_proof_schema(id, relations).await
    }

    async fn get_proof_schema_list(
        &self,
        query_params: GetProofSchemaQuery,
    ) -> Result<GetProofSchemaList, DataLayerError> {
        self.inner.get_proof_schema_list(query_params).await
    }
}

impl ProofSchemaHistoryDecorator {
    async fn write_history(
        &self,
        id: ProofSchemaId,
        name: String,
        organisation_id: OrganisationId,
        action: HistoryAction,
    ) {
        if let Err(error) = self
            .history_repository
            .create_history(History {
                id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                action,
                name,
                target: None,
                entity_id: Some(id.into()),
                entity_type: HistoryEntityType::ProofSchema,
                metadata: None,
                organisation_id: Some(organisation_id),
                user: self.session_provider.session().user(),
            })
            .await
        {
            tracing::warn!(%error, "failed to insert proof schema history event");
        }
    }
}
