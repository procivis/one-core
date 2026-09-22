use std::sync::Arc;

use shared_types::{InteractionId, OrganisationId, ProofId};

use crate::config::core_config::CoreConfig;
use crate::error::{ContextWithErrorCode, ErrorCodeMixinExt};
use crate::model::common::LockType;
use crate::model::history::HistoryErrorMetadata;
use crate::model::proof::{
    GetProofList, Proof, ProofClaim, ProofListQuery, ProofStateEnum, UpdateProofRequest,
};
use crate::proto::notification_scheduler::{NotificationPayload, NotificationScheduler};
use crate::provider::verification_protocol::model::CommonParams;
use crate::repository::error::DataLayerError;
use crate::repository::proof_repository::ProofRepository;
use crate::service::error::{ServiceError, ValidationError};

pub struct ProofNotificationDecorator {
    pub inner: Arc<dyn ProofRepository>,
    pub notification_scheduler: Arc<dyn NotificationScheduler>,
    pub config: Arc<CoreConfig>,
}

impl ProofNotificationDecorator {
    async fn send_notification(
        &self,
        proof_id: &ProofId,
        status: ProofStateEnum,
    ) -> Result<(), DataLayerError> {
        let proof = self.inner.get_proof(proof_id, None).await?;

        let Some(webhook_url) = &proof.webhook_url else {
            return Ok(());
        };

        let organisation_id = organisation_id_from_proof(&proof)
            .await
            .error_while("preparing notification")?
            .ok_or(ServiceError::MappingError(
                "missing organisation_id".to_string(),
            ))
            .error_while("preparing notification")?;

        let params: CommonParams = self
            .config
            .verification_protocol
            .get(&proof.protocol)
            .error_while("parsing config")?;

        let Some(task_id) = params.webhook_task else {
            return Err(ValidationError::NotificationsNotAllowed {
                protocol: proof.protocol.to_owned(),
            }
            .error_while("getting webhook task")
            .into());
        };

        self.notification_scheduler
            .schedule(
                webhook_url,
                NotificationPayload::Proof(*proof_id, status),
                task_id,
                organisation_id,
                Some(proof_id.to_string()),
            )
            .await
            .error_while("scheduling notification")?;

        Ok(())
    }
}

#[async_trait::async_trait]
impl ProofRepository for ProofNotificationDecorator {
    async fn update_proof(
        &self,
        proof_id: &ProofId,
        update: UpdateProofRequest,
        error_info: Option<HistoryErrorMetadata>,
    ) -> Result<(), DataLayerError> {
        let updated_state = update.state;

        self.inner
            .update_proof(proof_id, update, error_info)
            .await?;

        if let Some(updated_state) = updated_state {
            match updated_state {
                ProofStateEnum::Accepted | ProofStateEnum::Rejected | ProofStateEnum::Error => {
                    self.send_notification(proof_id, updated_state).await?;
                }
                _ => {}
            }
        }

        Ok(())
    }

    async fn create_proof(&self, request: Proof) -> Result<ProofId, DataLayerError> {
        self.inner.create_proof(request.clone()).await
    }

    async fn delete_proof_claims(&self, proof_id: &ProofId) -> Result<(), DataLayerError> {
        self.inner.delete_proof_claims(proof_id).await
    }

    async fn delete_proof(&self, proof_id: &ProofId) -> Result<(), DataLayerError> {
        self.inner.delete_proof(proof_id).await
    }

    async fn get_proof(
        &self,
        id: &ProofId,
        lock: Option<LockType>,
    ) -> Result<Proof, DataLayerError> {
        self.inner.get_proof(id, lock).await
    }

    async fn get_proof_by_interaction_id(
        &self,
        interaction_id: &InteractionId,
    ) -> Result<Proof, DataLayerError> {
        self.inner.get_proof_by_interaction_id(interaction_id).await
    }

    async fn get_proof_list(
        &self,
        query_params: ProofListQuery,
    ) -> Result<GetProofList, DataLayerError> {
        self.inner.get_proof_list(query_params).await
    }

    async fn set_proof_claims(
        &self,
        proof_id: &ProofId,
        claims: Vec<ProofClaim>,
    ) -> Result<(), DataLayerError> {
        self.inner.set_proof_claims(proof_id, claims).await
    }
}

async fn organisation_id_from_proof(
    proof: &Proof,
) -> Result<Option<OrganisationId>, DataLayerError> {
    if let Some(schema) = proof.schema.as_ref() {
        return Ok(Some(schema.as_ref().await?.organisation.id()));
    }

    if let Some(interaction) = proof.interaction.as_ref() {
        return Ok(Some(interaction.as_ref().await?.organisation.id()));
    }

    Ok(None)
}
