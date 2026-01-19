use std::collections::HashSet;
use std::fmt::Debug;
use std::sync::Arc;

use shared_types::{ClaimId, CredentialId, InteractionId};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::model::credential::{
    Credential, CredentialRelations, CredentialRole, CredentialStateEnum, GetCredentialList,
    GetCredentialQuery, UpdateCredentialRequest,
};
use crate::model::credential_schema::CredentialSchemaRelations;
use crate::model::history::{History, HistoryAction, HistoryEntityType, HistorySource};
use crate::model::identifier::IdentifierRelations;
use crate::proto::session_provider::{SessionExt, SessionProvider};
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::error::DataLayerError;
use crate::repository::history_repository::HistoryRepository;

pub struct CredentialHistoryDecorator {
    pub history_repository: Arc<dyn HistoryRepository>,
    pub inner: Arc<dyn CredentialRepository>,
    pub session_provider: Arc<dyn SessionProvider>,
}

impl CredentialHistoryDecorator {
    async fn get_stored(&self, credential_id: CredentialId) -> Result<Credential, DataLayerError> {
        self.get_credential(
            &credential_id,
            &CredentialRelations {
                interaction: Some(Default::default()),
                ..Default::default()
            },
        )
        .await?
        .ok_or_else(|| anyhow::anyhow!("Credential (id: {credential_id}) not found").into())
    }

    async fn create_history_entry(
        &self,
        credential_id: CredentialId,
        actions: impl IntoIterator<Item = HistoryAction> + Debug,
    ) {
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
                for action in actions {
                    self.create_history_entry_for_credential(&credential, action)
                        .await;
                }
            }
            _ => {
                tracing::warn!(
                    "failed inserting {actions:?} history event for credential. missing credential {credential_id}",
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
            source: HistorySource::Core,
            target: target_from_credential(credential),
            entity_id: Some(credential.id.into()),
            entity_type: HistoryEntityType::Credential,
            metadata: None,
            organisation_id: Some(organisation.id),
            user: self.session_provider.session().user(),
        };

        if let Err(err) = self.history_repository.create_history(entry).await {
            tracing::warn!("failed to insert credential history event: {err}");
        }
    }
}

#[async_trait::async_trait]
impl CredentialRepository for CredentialHistoryDecorator {
    async fn create_credential(&self, request: Credential) -> Result<CredentialId, DataLayerError> {
        let state = request.state;
        let role = request.role;
        let credential_id = self.inner.create_credential(request).await?;

        if role == CredentialRole::Holder && state == CredentialStateEnum::Accepted {
            self.create_history_entry(
                credential_id,
                [HistoryAction::Issued, HistoryAction::Accepted],
            )
            .await;
        } else {
            self.create_history_entry(credential_id, [action_from_state(state)])
                .await;
        };

        Ok(credential_id)
    }

    async fn update_credential(
        &self,
        credential_id: CredentialId,
        update: UpdateCredentialRequest,
    ) -> Result<(), DataLayerError> {
        let stored = self.get_stored(credential_id).await?;

        self.inner
            .update_credential(credential_id, update.clone())
            .await?;

        // issuer, changing interaction while pending -> repeated sharing
        if let Some(interaction_id) = update.interaction
            && stored.state == CredentialStateEnum::Pending
            && stored.role == CredentialRole::Issuer
            && update.state.is_none()
            && Some(interaction_id) != stored.interaction.map(|i| i.id)
        {
            self.create_history_entry(credential_id, [HistoryAction::Shared])
                .await;
        }

        if let Some(new_state) = update.state {
            if stored.state != new_state {
                self.create_history_entry(credential_id, [action_from_state(new_state)])
                    .await;
            }

            if let Some(additional_event) = match (stored.state, new_state) {
                (
                    CredentialStateEnum::Created | CredentialStateEnum::InteractionExpired,
                    CredentialStateEnum::Pending,
                ) => {
                    if stored.role == CredentialRole::Issuer {
                        Some(HistoryAction::Shared)
                    } else {
                        None
                    }
                }
                (
                    CredentialStateEnum::Pending | CredentialStateEnum::Offered,
                    CredentialStateEnum::Accepted,
                ) => Some(HistoryAction::Issued),
                (CredentialStateEnum::Suspended, CredentialStateEnum::Accepted) => {
                    Some(HistoryAction::Reactivated)
                }
                _ => None,
            } {
                self.create_history_entry(credential_id, [additional_event])
                    .await;
            }
        }

        Ok(())
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

    async fn get_credential_list(
        &self,
        query_params: GetCredentialQuery,
    ) -> Result<GetCredentialList, DataLayerError> {
        self.inner.get_credential_list(query_params).await
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
}

fn target_from_credential(credential: &Credential) -> Option<String> {
    match credential.role {
        CredentialRole::Holder => credential
            .issuer_identifier
            .as_ref()
            .map(|identifier| identifier.id.to_string()),
        CredentialRole::Issuer => credential
            .holder_identifier
            .as_ref()
            .map(|identifier| identifier.id.to_string()),
        CredentialRole::Verifier => None,
    }
}

fn action_from_state(state: CredentialStateEnum) -> HistoryAction {
    match state {
        CredentialStateEnum::Created => HistoryAction::Created,
        CredentialStateEnum::Pending => HistoryAction::Pending,
        CredentialStateEnum::Offered => HistoryAction::Offered,
        CredentialStateEnum::Accepted => HistoryAction::Accepted,
        CredentialStateEnum::Rejected => HistoryAction::Rejected,
        CredentialStateEnum::Revoked => HistoryAction::Revoked,
        CredentialStateEnum::Suspended => HistoryAction::Suspended,
        CredentialStateEnum::Error => HistoryAction::Errored,
        CredentialStateEnum::InteractionExpired => HistoryAction::InteractionExpired,
    }
}
