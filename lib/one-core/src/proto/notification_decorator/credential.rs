use std::collections::HashSet;
use std::sync::Arc;

use shared_types::{CredentialId, InteractionId};

use crate::config::core_config::CoreConfig;
use crate::error::{ContextWithErrorCode, ErrorCodeMixinExt};
use crate::model::credential::{
    Credential, CredentialListQuery, CredentialStateEnum, GetCredentialList,
    UpdateCredentialRequest,
};
use crate::proto::notification_scheduler::{NotificationPayload, NotificationScheduler};
use crate::provider::issuance_protocol::model::CommonParams;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::error::DataLayerError;
use crate::service::error::ValidationError;

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
            .get_credential(&credential_id)
            .await
            .error_while("sending notification")?;

        let (common, webhook_url) = match &stored {
            Credential::IssuerSingle {
                common,
                webhook_url: Some(webhook_url),
                ..
            }
            | Credential::IssuerBatchParent {
                common,
                webhook_url: Some(webhook_url),
                ..
            } => (common, webhook_url),
            _ => return Ok(()),
        };

        let params: CommonParams = self
            .config
            .issuance_protocol
            .get(&common.protocol)
            .error_while("parsing config")?;

        let Some(task_id) = params.webhook_task else {
            return Err(ValidationError::NotificationsNotAllowed {
                protocol: common.protocol.to_owned(),
            }
            .error_while("getting webhook task")
            .into());
        };

        let organisation_id = common
            .schema
            .as_ref()
            .await
            .error_while("getting organisation_id")?
            .organisation
            .id();

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
                | CredentialStateEnum::Suspended { .. }
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

    async fn create_credentials(
        &self,
        requests: Vec<Credential>,
    ) -> Result<Vec<CredentialId>, DataLayerError> {
        self.inner.create_credentials(requests).await
    }

    async fn delete_credentials(&self, credentials: &[Credential]) -> Result<(), DataLayerError> {
        self.inner.delete_credentials(credentials).await
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
