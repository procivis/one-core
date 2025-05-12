use std::collections::HashSet;
use std::sync::Arc;

use one_core::model::claim::ClaimId;
use one_core::model::credential::{
    Credential, CredentialRelations, GetCredentialList, GetCredentialQuery, UpdateCredentialRequest,
};
use one_core::model::credential_schema::CredentialSchemaRelations;
use one_core::model::history::{History, HistoryAction, HistoryEntityType};
use one_core::model::identifier::IdentifierRelations;
use one_core::model::interaction::InteractionId;
use one_core::repository::credential_repository::CredentialRepository;
use one_core::repository::error::DataLayerError;
use one_core::repository::history_repository::HistoryRepository;
use shared_types::{CredentialId, DidId};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::credential::mapper::target_from_credential;

pub struct CredentialHistoryDecorator {
    pub history_repository: Arc<dyn HistoryRepository>,
    pub inner: Arc<dyn CredentialRepository>,
}

impl CredentialHistoryDecorator {
    async fn create_history_entry(&self, credential_id: CredentialId, action: HistoryAction) {
        let credential = self
            .get_credential(
                &credential_id,
                &CredentialRelations {
                    schema: Some(CredentialSchemaRelations {
                        organisation: Some(Default::default()),
                        ..Default::default()
                    }),
                    issuer_identifier: Some(IdentifierRelations {
                        did: Some(Default::default()),
                        ..Default::default()
                    }),
                    holder_identifier: Some(IdentifierRelations {
                        did: Some(Default::default()),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            )
            .await;

        match credential {
            Ok(Some(credential)) => {
                self.create_history_entry_for_credential(&credential, action)
                    .await;
            }
            _ => {
                tracing::warn!(
                    "failed inserting {action:?} history event for credential. missing credential {credential_id}",
                );
            }
        }
    }

    async fn create_history_entry_for_credential(
        &self,
        credential: &Credential,
        action: HistoryAction,
    ) {
        let Some(credential_schema) = &credential.schema else {
            tracing::warn!(
                "failed inserting {action:?} history event for credential: {}. missing credential schema",
                credential.id
            );
            return;
        };

        let Some(organisation) = &credential_schema.organisation else {
            tracing::warn!(
                "failed inserting {action:?} history event for credential: {}. credential schema is missing organisation",
                credential.id
            );
            return;
        };

        let entry = History {
            id: Uuid::new_v4().into(),
            created_date: OffsetDateTime::now_utc(),
            action,
            name: credential_schema.name.to_owned(),
            target: target_from_credential(credential),
            entity_id: Some(credential.id.into()),
            entity_type: HistoryEntityType::Credential,
            metadata: None,
            organisation_id: organisation.id,
        };
        let result = self.history_repository.create_history(entry).await;

        if let Err(err) = result {
            tracing::warn!("failed to insert credential history event: {err}");
        }
    }
}

#[async_trait::async_trait]
impl CredentialRepository for CredentialHistoryDecorator {
    async fn create_credential(&self, request: Credential) -> Result<CredentialId, DataLayerError> {
        let state = request.state;
        let credential_id = self.inner.create_credential(request).await?;
        self.create_history_entry(credential_id, HistoryAction::from(state))
            .await;

        Ok(credential_id)
    }

    async fn delete_credential(&self, credential: &Credential) -> Result<(), DataLayerError> {
        self.inner.delete_credential(credential).await?;
        self.create_history_entry_for_credential(credential, HistoryAction::Deleted)
            .await;

        Ok(())
    }

    async fn delete_credential_blobs(
        &self,
        request: HashSet<CredentialId>,
    ) -> Result<(), DataLayerError> {
        self.inner.delete_credential_blobs(request).await
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
        credential_id: CredentialId,
        credential: UpdateCredentialRequest,
    ) -> Result<(), DataLayerError> {
        self.inner
            .update_credential(credential_id, credential.clone())
            .await?;

        if let Some(state) = credential.state {
            self.create_history_entry(credential_id, HistoryAction::from(state))
                .await;
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
