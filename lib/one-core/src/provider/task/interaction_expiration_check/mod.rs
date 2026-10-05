use std::sync::Arc;

use serde_json::Value;
use uuid::Uuid;

use self::dto::InteractionExpirationCheckResultDTO;
use super::Task;
use crate::error::ContextWithErrorCode;
use crate::model::credential::{Credential, CredentialRole};
use crate::model::history::{History, HistoryAction, HistoryEntityType, HistorySource};
use crate::proto::session_provider::{SessionExt, SessionProvider};
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::interaction_repository::InteractionRepository;
use crate::repository::proof_repository::ProofRepository;
use crate::service::error::ServiceError;

pub mod dto;

pub(crate) struct InteractionExpirationCheckProvider {
    interaction_repository: Arc<dyn InteractionRepository>,
    history_repository: Arc<dyn HistoryRepository>,
    credential_repository: Arc<dyn CredentialRepository>,
    proof_repository: Arc<dyn ProofRepository>,
    session_provider: Arc<dyn SessionProvider>,
}

impl InteractionExpirationCheckProvider {
    pub fn new(
        interaction_repository: Arc<dyn InteractionRepository>,
        history_repository: Arc<dyn HistoryRepository>,
        credential_repository: Arc<dyn CredentialRepository>,
        proof_repository: Arc<dyn ProofRepository>,
        session_provider: Arc<dyn SessionProvider>,
    ) -> Self {
        Self {
            interaction_repository,
            history_repository,
            credential_repository,
            proof_repository,
            session_provider,
        }
    }
}

#[async_trait::async_trait]
impl Task for InteractionExpirationCheckProvider {
    async fn run(&self, _params: Option<Value>) -> Result<Value, ServiceError> {
        let now = crate::clock::now_utc();
        let updated_credentials = self
            .interaction_repository
            .update_expired_credentials()
            .await
            .error_while("updating expired credentials")?;

        // write credential history
        for credential_id in &updated_credentials {
            let credential = self
                .credential_repository
                .get_credential(credential_id)
                .await
                .error_while("getting credential")?;

            let target = target_from_credential(&credential);
            let schema = credential.common().schema.as_ref().await?.to_owned();

            self.history_repository
                .create_history(History {
                    id: Uuid::new_v4().into(),
                    created_date: now,
                    action: HistoryAction::InteractionExpired,
                    name: schema.name,
                    target,
                    source: HistorySource::Core,
                    entity_id: Some((*credential_id).into()),
                    entity_type: HistoryEntityType::Credential,
                    metadata: None,
                    metadata_blob_id: None,
                    organisation_id: Some(schema.organisation.id()),
                    user: self.session_provider.session().user(),
                })
                .await
                .error_while("creating history")?;
        }

        let updated_proofs = self
            .interaction_repository
            .update_expired_proofs()
            .await
            .error_while("updating expired proofs")?;

        // write proof history
        for proof_id in &updated_proofs {
            let proof = self
                .proof_repository
                .get_proof(proof_id, None)
                .await
                .error_while("getting proof")?;
            let name = if let Some(proof_schema) = proof.schema.as_ref() {
                proof_schema.as_ref().await?.name.to_owned()
            } else {
                Default::default()
            };

            let organisation_id = proof
                .interaction
                .as_ref()
                .ok_or(ServiceError::MappingError(
                    "interaction missing".to_string(),
                ))?
                .as_ref()
                .await?
                .organisation
                .id();

            self.history_repository
                .create_history(History {
                    id: Uuid::new_v4().into(),
                    created_date: now,
                    action: HistoryAction::InteractionExpired,
                    name,
                    target: None,
                    source: HistorySource::Core,
                    entity_id: Some((*proof_id).into()),
                    entity_type: HistoryEntityType::Proof,
                    metadata: None,
                    metadata_blob_id: None,
                    organisation_id: Some(organisation_id),
                    user: self.session_provider.session().user(),
                })
                .await
                .error_while("creating history")?;
        }

        let result = InteractionExpirationCheckResultDTO {
            updated_credentials,
            updated_proofs,
        };

        serde_json::to_value(result).map_err(|e| ServiceError::MappingError(e.to_string()))
    }
}

fn target_from_credential(credential: &Credential) -> Option<String> {
    match credential.role() {
        CredentialRole::Holder => credential
            .issuer_identifier()
            .as_ref()
            .map(|identifier| identifier.id().to_string()),
        CredentialRole::Issuer => credential
            .holder_identifier()
            .as_ref()
            .map(|identifier| identifier.id().to_string()),
        CredentialRole::Verifier => None,
    }
}
