use std::sync::Arc;

use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use self::dto::InteractionExpirationCheckResultDTO;
use super::Task;
use crate::model::credential::{Credential, CredentialRelations, CredentialRole};
use crate::model::credential_schema::CredentialSchemaRelations;
use crate::model::history::{History, HistoryAction, HistoryEntityType, HistorySource};
use crate::model::identifier::IdentifierRelations;
use crate::model::interaction::InteractionRelations;
use crate::model::proof::ProofRelations;
use crate::proto::session_provider::{SessionExt, SessionProvider};
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::interaction_repository::InteractionRepository;
use crate::repository::proof_repository::ProofRepository;
use crate::service::error::{EntityNotFoundError, ServiceError};

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
    async fn run(&self) -> Result<Value, ServiceError> {
        let now = OffsetDateTime::now_utc();
        let updated_credentials = self
            .interaction_repository
            .update_expired_credentials()
            .await?;

        // write credential history
        for credential_id in &updated_credentials {
            let credential = self
                .credential_repository
                .get_credential(
                    credential_id,
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
                .await?
                .ok_or(EntityNotFoundError::Credential(*credential_id))?;

            let target = target_from_credential(&credential);
            let schema = credential
                .schema
                .ok_or(ServiceError::MappingError("schema missing".to_string()))?;

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
                    organisation_id: schema.organisation.map(|o| o.id),
                    user: self.session_provider.session().user(),
                })
                .await?;
        }

        let updated_proofs = self.interaction_repository.update_expired_proofs().await?;

        // write proof history
        for proof_id in &updated_proofs {
            let proof = self
                .proof_repository
                .get_proof(
                    proof_id,
                    &ProofRelations {
                        schema: Some(Default::default()),
                        interaction: Some(InteractionRelations {
                            organisation: Some(Default::default()),
                        }),
                        ..Default::default()
                    },
                    None,
                )
                .await?
                .ok_or(EntityNotFoundError::Proof(*proof_id))?;

            let name = proof.schema.map(|schema| schema.name).unwrap_or_default();
            let organisation = proof
                .interaction
                .ok_or(ServiceError::MappingError(
                    "interaction missing".to_string(),
                ))?
                .organisation;

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
                    organisation_id: organisation.map(|o| o.id),
                    user: self.session_provider.session().user(),
                })
                .await?;
        }

        let result = InteractionExpirationCheckResultDTO {
            updated_credentials,
            updated_proofs,
        };

        serde_json::to_value(result).map_err(|e| ServiceError::MappingError(e.to_string()))
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
