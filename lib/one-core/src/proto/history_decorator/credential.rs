use std::collections::HashSet;
use std::sync::Arc;

use shared_types::{CredentialId, InteractionId};
use uuid::Uuid;

use crate::model::credential::{
    Credential, CredentialListQuery, CredentialStateEnum, GetCredentialList,
    UpdateCredentialRequest,
};
use crate::model::history::{
    History, HistoryAction, HistoryEntityType, HistoryErrorMetadata, HistoryMetadata, HistorySource,
};
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
        self.get_credential(&credential_id).await
    }

    async fn create_history_entry(
        &self,
        credential_id: CredentialId,
        action: HistoryAction,
        error_info: Option<HistoryErrorMetadata>,
    ) {
        let credential = self.get_credential(&credential_id).await;

        match credential {
            Ok(credential) => {
                self.create_history_entry_for_credential(&credential, action, error_info)
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
        error_info: Option<HistoryErrorMetadata>,
    ) {
        let credential_schema = match credential.common().schema.as_ref().await {
            Ok(schema) => schema,
            Err(err) => {
                tracing::warn!(
                    "failed inserting {action:?} history event for credential: {}: {err}",
                    credential.common().id
                );
                return;
            }
        };

        let entry = History {
            id: Uuid::new_v4().into(),
            created_date: crate::clock::now_utc(),
            action,
            name: credential_schema.name.to_owned(),
            source: HistorySource::Core,
            target: target_from_credential(credential),
            entity_id: Some(credential.common().id.into()),
            entity_type: HistoryEntityType::Credential,
            metadata: error_info.map(HistoryMetadata::ErrorMetadata),
            metadata_blob_id: None,
            organisation_id: Some(credential_schema.organisation.id()),
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
        let id = request.common().id;
        self.create_credentials(vec![request]).await?;
        Ok(id)
    }

    async fn create_credentials(
        &self,
        requests: Vec<Credential>,
    ) -> Result<Vec<CredentialId>, DataLayerError> {
        let ids = self.inner.create_credentials(requests.clone()).await?;
        // Creation preserves state, role and schema; history does not need to reload
        // every stored credential or inspect its canonical claim IDs.
        for credential in requests {
            if matches!(
                credential,
                Credential::HolderSingle { .. }
                    | Credential::HolderBatchParent { .. }
                    | Credential::HolderBatchItem { .. }
            ) && credential.common().state == CredentialStateEnum::Accepted
            {
                for action in [HistoryAction::Issued, HistoryAction::Accepted] {
                    self.create_history_entry_for_credential(&credential, action, None)
                        .await;
                }
            } else {
                self.create_history_entry_for_credential(
                    &credential,
                    action_from_state(credential.common().state),
                    None,
                )
                .await;
            }
        }
        Ok(ids)
    }

    async fn update_credential(
        &self,
        credential_id: CredentialId,
        mut update: UpdateCredentialRequest,
    ) -> Result<(), DataLayerError> {
        let stored = self.get_stored(credential_id).await?;
        let error_info = update.error_info.take();

        self.inner
            .update_credential(credential_id, update.clone())
            .await?;

        // issuer, changing interaction while pending -> repeated sharing
        if let Some(interaction_id) = update.interaction
            && stored.common().state == CredentialStateEnum::Pending
            && stored.issuer().is_ok()
            && update.state.is_none()
            && Some(interaction_id) != stored.common().interaction.as_ref().map(|i| i.id())
        {
            self.create_history_entry(credential_id, HistoryAction::Shared, None)
                .await;
        }

        if let Some(new_state) = update.state {
            if stored.common().state != new_state {
                self.create_history_entry(credential_id, action_from_state(new_state), error_info)
                    .await;
            }

            if let Some(additional_event) = match (stored.common().state, new_state) {
                (
                    CredentialStateEnum::Created | CredentialStateEnum::InteractionExpired,
                    CredentialStateEnum::Pending,
                ) => {
                    if stored.issuer().is_ok() {
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
                self.create_history_entry(credential_id, additional_event, None)
                    .await;
            }
        }

        Ok(())
    }

    async fn delete_credentials(&self, credentials: &[Credential]) -> Result<(), DataLayerError> {
        self.inner.delete_credentials(credentials).await?;
        for credential in credentials {
            self.create_history_entry_for_credential(credential, HistoryAction::Deleted, None)
                .await;
        }

        Ok(())
    }

    async fn delete_credential_blobs(
        &self,
        request: HashSet<CredentialId>,
    ) -> Result<(), DataLayerError> {
        self.inner.delete_credential_blobs(request).await
    }

    async fn get_credential(&self, id: &CredentialId) -> Result<Credential, DataLayerError> {
        self.inner.get_credential(id).await
    }

    async fn get_credentials_by_interaction_id(
        &self,
        interaction_id: &InteractionId,
    ) -> Result<Vec<Credential>, DataLayerError> {
        self.inner
            .get_credentials_by_interaction_id(interaction_id)
            .await
    }

    async fn get_credential_list(
        &self,
        query_params: CredentialListQuery,
    ) -> Result<GetCredentialList, DataLayerError> {
        self.inner.get_credential_list(query_params).await
    }

    async fn get_credentials_by_claim_names(
        &self,
        claim_names: Vec<String>,
    ) -> Result<Vec<Credential>, DataLayerError> {
        self.inner.get_credentials_by_claim_names(claim_names).await
    }
}

fn target_from_credential(credential: &Credential) -> Option<String> {
    match credential {
        Credential::HolderSingle { credential, .. }
        | Credential::HolderBatchItem { credential, .. } => {
            Some(credential.issuer.identifier.id().to_string())
        }
        Credential::IssuerSingle { credential, .. }
        | Credential::IssuerBatchItem { credential, .. } => credential
            .holder_identifier
            .as_ref()
            .map(|identifier| identifier.id().to_string()),
        Credential::IssuerBatchParent { .. }
        | Credential::HolderBatchParent { .. }
        | Credential::Verifier { .. } => None,
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
        CredentialStateEnum::Expired => HistoryAction::Expired,
        CredentialStateEnum::Expiring => HistoryAction::Expiring,
    }
}

#[cfg(test)]
mod test {
    use assert2::let_assert;
    use mockall::Sequence;
    use similar_asserts::assert_eq;

    use super::*;
    use crate::error::ErrorCode;
    use crate::proto::session_provider::NoSessionProvider;
    use crate::repository::credential_repository::MockCredentialRepository;
    use crate::repository::history_repository::MockHistoryRepository;
    use crate::service::test_utilities::dummy_credential;

    #[tokio::test]
    async fn error_context_is_consumed_by_history_decorator() {
        let credential = dummy_credential();
        let credential_id = credential.common().id;
        let error_info = HistoryErrorMetadata {
            error_code: ErrorCode::BR_0062,
            message: "Credential signing failed".to_string(),
        };
        let mut sequence = Sequence::new();
        let mut inner = MockCredentialRepository::new();
        inner
            .expect_get_credential()
            .once()
            .in_sequence(&mut sequence)
            .return_once({
                let credential = credential.clone();
                move |_| Ok(credential)
            });
        inner
            .expect_update_credential()
            .once()
            .in_sequence(&mut sequence)
            .withf(move |id, request| {
                *id == credential_id
                    && request.state == Some(CredentialStateEnum::Error)
                    && request.error_info.is_none()
            })
            .return_once(|_, _| Ok(()));
        inner
            .expect_get_credential()
            .once()
            .in_sequence(&mut sequence)
            .return_once(move |_| {
                Ok({
                    let mut updated_credential = credential;
                    updated_credential.common_mut().state = CredentialStateEnum::Error;
                    updated_credential
                })
            });

        let mut history = MockHistoryRepository::new();
        history.expect_create_history().once().return_once({
            let expected = error_info.clone();
            move |entry| {
                assert_eq!(entry.entity_id, Some(credential_id.into()));
                assert_eq!(entry.action, HistoryAction::Errored);
                let_assert!(Some(HistoryMetadata::ErrorMetadata(error)) = entry.metadata);
                assert_eq!(error, expected);
                Ok(entry.id)
            }
        });

        let repository = CredentialHistoryDecorator {
            inner: Arc::new(inner),
            history_repository: Arc::new(history),
            session_provider: Arc::new(NoSessionProvider),
        };
        repository
            .update_credential(
                credential_id,
                UpdateCredentialRequest {
                    state: Some(CredentialStateEnum::Error),
                    error_info: Some(error_info),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
    }
}
