use std::sync::Arc;

use anyhow::Context;
use one_core::model::claim::ClaimId;
use one_core::model::credential::{
    Credential, CredentialRelations, CredentialState, GetCredentialList, GetCredentialQuery,
    UpdateCredentialRequest,
};
use one_core::model::credential_schema::CredentialSchemaRelations;
use one_core::model::history::{History, HistoryAction, HistoryEntityType};
use one_core::model::interaction::InteractionId;
use one_core::model::organisation::Organisation;
use one_core::repository::credential_repository::CredentialRepository;
use one_core::repository::error::DataLayerError;
use one_core::repository::history_repository::HistoryRepository;
use shared_types::{CredentialId, DidId};
use uuid::Uuid;

pub struct CredentialHistoryDecorator {
    pub history_repository: Arc<dyn HistoryRepository>,
    pub inner: Arc<dyn CredentialRepository>,
}

impl CredentialHistoryDecorator {
    async fn get_organisation_for_credential(
        &self,
        credential_id: &CredentialId,
    ) -> Result<Organisation, DataLayerError> {
        let credential = self
            .inner
            .get_credential(
                credential_id,
                &CredentialRelations {
                    schema: Some(CredentialSchemaRelations {
                        organisation: Some(Default::default()),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            )
            .await?
            .context("credential is missing")?;

        if let Some(organisation) = credential.schema.and_then(|schema| schema.organisation) {
            Ok(organisation)
        } else {
            Err(anyhow::anyhow!("organisation is None").into())
        }
    }

    async fn create_history_entry(&self, credential_id: CredentialId, state: CredentialState) {
        let organisation = match self.get_organisation_for_credential(&credential_id).await {
            Ok(org) => org,
            Err(err) => {
                tracing::debug!("failed to retrieve organisation for credential (while creating a history event): {err:?}");
                return;
            }
        };

        let entry = History {
            id: Uuid::new_v4().into(),
            created_date: state.created_date,
            action: HistoryAction::from(state),
            entity_id: Some(credential_id.into()),
            entity_type: HistoryEntityType::Credential,
            metadata: None,
            organisation: Some(organisation),
        };
        let result = self.history_repository.create_history(entry).await;

        if let Err(err) = result {
            tracing::debug!("failed to insert credential history event: {err:?}");
        }
    }
}

#[async_trait::async_trait]
impl CredentialRepository for CredentialHistoryDecorator {
    async fn create_credential(&self, request: Credential) -> Result<CredentialId, DataLayerError> {
        let state = request.state.clone();
        let credential_id = self.inner.create_credential(request).await?;

        if let Some(states) = state {
            for state in states {
                self.create_history_entry(credential_id, state).await;
            }
        };

        Ok(credential_id)
    }

    async fn delete_credential(&self, id: &CredentialId) -> Result<(), DataLayerError> {
        self.inner.delete_credential(id).await
    }

    async fn get_credential(
        &self,
        id: &CredentialId,
        relations: &CredentialRelations,
    ) -> Result<Option<Credential>, DataLayerError> {
        self.inner.get_credential(id, relations).await
    }

    async fn get_credentials_by_interaction_id(
        &self,
        interaction_id: &InteractionId,
        relations: &CredentialRelations,
    ) -> Result<Vec<Credential>, DataLayerError> {
        self.inner
            .get_credentials_by_interaction_id(interaction_id, relations)
            .await
    }

    async fn get_credentials_by_issuer_did_id(
        &self,
        issuer_did_id: &DidId,
        relations: &CredentialRelations,
    ) -> Result<Vec<Credential>, DataLayerError> {
        self.inner
            .get_credentials_by_issuer_did_id(issuer_did_id, relations)
            .await
    }

    async fn get_credential_list(
        &self,
        query_params: GetCredentialQuery,
    ) -> Result<GetCredentialList, DataLayerError> {
        self.inner.get_credential_list(query_params).await
    }

    async fn update_credential(
        &self,
        credential: UpdateCredentialRequest,
    ) -> Result<(), DataLayerError> {
        self.inner.update_credential(credential.clone()).await?;

        if let Some(state) = credential.state {
            self.create_history_entry(credential.id, state).await;
        };

        Ok(())
    }

    async fn get_credentials_by_claim_names(
        &self,
        claim_names: Vec<String>,
        relations: &CredentialRelations,
    ) -> Result<Vec<Credential>, DataLayerError> {
        self.inner
            .get_credentials_by_claim_names(claim_names, relations)
            .await
    }

    async fn get_credential_by_claim_id(
        &self,
        claim_id: &ClaimId,
        relations: &CredentialRelations,
    ) -> Result<Option<Credential>, DataLayerError> {
        self.inner
            .get_credential_by_claim_id(claim_id, relations)
            .await
    }

    async fn get_credentials_by_credential_schema_id(
        &self,
        schema_id: String,
        relations: &CredentialRelations,
    ) -> Result<Vec<Credential>, DataLayerError> {
        self.inner
            .get_credentials_by_credential_schema_id(schema_id, relations)
            .await
    }
}
