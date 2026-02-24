use std::collections::HashSet;
use std::sync::Arc;

use shared_types::{ClaimId, CredentialId, InteractionId};

use crate::config::core_config::CoreConfig;
use crate::error::{ContextWithErrorCode, ErrorCodeMixinExt};
use crate::model::credential::{
    Credential, CredentialRelations, CredentialStateEnum, GetCredentialList, GetCredentialQuery,
    UpdateCredentialRequest,
};
use crate::model::credential_schema::CredentialSchemaRelations;
use crate::proto::notification_scheduler::{NotificationPayload, NotificationScheduler};
use crate::provider::issuance_protocol::model::CommonParams;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::error::DataLayerError;
use crate::service::error::{ServiceError, ValidationError};

pub struct CredentialNotificationDecorator {
    pub inner: Arc<dyn CredentialRepository>,
    pub notification_scheduler: Arc<dyn NotificationScheduler>,
    pub config: Arc<CoreConfig>,
}

impl CredentialNotificationDecorator {
    async fn send_notification(
        &self,
        credential_id: CredentialId,
        status: CredentialStateEnum,
    ) -> Result<(), DataLayerError> {
        let stored = self
            .get_credential(
                &credential_id,
                &CredentialRelations {
                    schema: Some(CredentialSchemaRelations {
                        organisation: Some(Default::default()),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            )
            .await?
            .ok_or(ServiceError::MappingError("missing credential".to_string()))
            .error_while("sending notification")?;

        let Some(webhook_url) = &stored.webhook_url else {
            return Ok(());
        };

        let params: CommonParams = self
            .config
            .issuance_protocol
            .get(&stored.protocol)
            .error_while("parsing config")?;

        let Some(task_id) = params.webhook_task else {
            return Err(ValidationError::NotificationsNotAllowed {
                protocol: stored.protocol.to_owned(),
            }
            .error_while("getting webhook task")
            .into());
        };

        let organisation_id = stored
            .schema
            .as_ref()
            .ok_or(ServiceError::MappingError("missing schema".to_string()))
            .error_while("getting organisation_id")?
            .organisation
            .as_ref()
            .ok_or(ServiceError::MappingError(
                "missing organisation".to_string(),
            ))
            .error_while("getting organisation_id")?
            .id;

        self.notification_scheduler
            .schedule(
                webhook_url,
                NotificationPayload::Credential(credential_id, status),
                task_id,
                organisation_id,
                Some(credential_id.to_string()),
            )
            .await
            .error_while("scheduling notification")?;

        Ok(())
    }
}

#[async_trait::async_trait]
impl CredentialRepository for CredentialNotificationDecorator {
    async fn update_credential(
        &self,
        credential_id: CredentialId,
        update: UpdateCredentialRequest,
    ) -> Result<(), DataLayerError> {
        let updated_state = update.state;

        self.inner.update_credential(credential_id, update).await?;

        if let Some(updated_state) = updated_state {
            match updated_state {
                CredentialStateEnum::Accepted
                | CredentialStateEnum::Suspended
                | CredentialStateEnum::Revoked
                | CredentialStateEnum::Rejected
                | CredentialStateEnum::Error => {
                    self.send_notification(credential_id, updated_state).await?;
                }
                _ => {}
            }
        }

        Ok(())
    }

    async fn create_credential(&self, request: Credential) -> Result<CredentialId, DataLayerError> {
        self.inner.create_credential(request).await
    }

    async fn delete_credential(&self, credential: &Credential) -> Result<(), DataLayerError> {
        self.inner.delete_credential(credential).await
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
