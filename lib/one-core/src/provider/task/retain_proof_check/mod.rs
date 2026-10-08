use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};
use uuid::Uuid;

use super::Task;
use crate::config::core_config::BlobStorageType;
use crate::error::ContextWithErrorCode;
use crate::model::credential::{Credential, CredentialFilterValue, CredentialListQuery};
use crate::model::history::{HistoryAction, HistoryEntityType, HistoryFilterValue};
use crate::model::list_filter::ListFilterValue;
use crate::model::list_query::{ListPagination, ListQuery};
use crate::model::proof::ProofStateEnum;
use crate::provider::blob_storage::provider::BlobStorageProvider;
use crate::repository::claim_repository::ClaimRepository;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::proof_repository::ProofRepository;
use crate::service::error::ServiceError;
use crate::service::proof::dto::ProofFilterValue;

pub struct RetainProofCheck {
    claim_repository: Arc<dyn ClaimRepository>,
    credential_repository: Arc<dyn CredentialRepository>,
    proof_repository: Arc<dyn ProofRepository>,
    history_repository: Arc<dyn HistoryRepository>,
    blob_storage_provider: Arc<dyn BlobStorageProvider>,
}

impl RetainProofCheck {
    pub fn new(
        claim_repository: Arc<dyn ClaimRepository>,
        credential_repository: Arc<dyn CredentialRepository>,
        proof_repository: Arc<dyn ProofRepository>,
        history_repository: Arc<dyn HistoryRepository>,
        blob_storage_provider: Arc<dyn BlobStorageProvider>,
    ) -> Self {
        Self {
            claim_repository,
            credential_repository,
            proof_repository,
            history_repository,
            blob_storage_provider,
        }
    }
}

#[async_trait::async_trait]
impl Task for RetainProofCheck {
    async fn run(&self, _params: Option<Value>) -> Result<Value, ServiceError> {
        let processed_events: Vec<_> = self
            .history_repository
            .get_history_list(ListQuery {
                include_count: false,
                filtering: Some(
                    HistoryFilterValue::EntityTypes(vec![HistoryEntityType::Proof]).condition()
                        & HistoryFilterValue::Actions(vec![HistoryAction::ClaimsRemoved]),
                ),
                pagination: None,
                sorting: None,
                include: None,
            })
            .await
            .error_while("getting history list")?
            .values
            .into_iter()
            .flat_map(|event| event.entity_id)
            .map(|event_id| Uuid::from(event_id).into())
            .collect();

        let now = crate::clock::now_utc();
        let mut page = 0;

        loop {
            let proofs = self
                .proof_repository
                .get_proof_list(ListQuery {
                    include_count: false,
                    filtering: Some(
                        ProofFilterValue::States(vec![ProofStateEnum::Accepted]).condition()
                            & ProofFilterValue::ValidForDeletion
                            & ProofFilterValue::ProofIdsNot(processed_events.clone()),
                    ),
                    pagination: Some(ListPagination {
                        page,
                        page_size: 100,
                    }),
                    sorting: None,
                    include: None,
                })
                .await
                .error_while("getting proofs")?;

            if proofs.values.is_empty() {
                return Ok(json!({}));
            }

            for proof in proofs.values {
                let schema = proof
                    .schema
                    .as_ref()
                    .ok_or_else(|| ServiceError::MappingError("schema is None".into()))?
                    .as_ref()
                    .await?;

                if proof.completed_date.is_some_and(|value| {
                    value + Duration::from_secs(schema.expire_duration as _) > now
                }) {
                    continue;
                }

                let credential_ids = proof
                    .claims
                    .as_ref()
                    .await?
                    .into_iter()
                    .map(|proof_claim| proof_claim.credential.id())
                    .collect::<HashSet<_>>();

                self.proof_repository
                    .delete_proof_claims(&proof.id)
                    .await
                    .error_while("deleting proof claims")?;
                self.claim_repository
                    .delete_claims_for_credentials(credential_ids.clone())
                    .await
                    .error_while("deleting credential claims")?;

                let blob_storage = self
                    .blob_storage_provider
                    .get_blob_storage(BlobStorageType::Db)?;

                let credential_blob_ids = self
                    .credential_repository
                    .get_credential_list(CredentialListQuery {
                        include_count: false,
                        filtering: Some(
                            CredentialFilterValue::CredentialIds(Vec::from_iter(
                                credential_ids.clone(),
                            ))
                            .condition()
                                & CredentialFilterValue::Deleted(false),
                        ),
                        ..CredentialListQuery::default()
                    })
                    .await
                    .error_while("getting credentials")?
                    .values
                    .into_iter()
                    .filter_map(|credential| match credential {
                        Credential::IssuerSingle { credential, .. }
                        | Credential::IssuerBatchItem { credential, .. } => {
                            credential.credential_blob_id
                        }
                        Credential::HolderSingle { credential, .. }
                        | Credential::HolderBatchItem { credential, .. } => {
                            credential.credential_blob_id
                        }
                        _ => None,
                    })
                    .collect::<Vec<_>>();

                blob_storage
                    .delete_many(&credential_blob_ids)
                    .await
                    .error_while("deleting blobs")?;
                self.credential_repository
                    .delete_credential_blobs(credential_ids)
                    .await
                    .error_while("deleting credential blobs")?;

                if let Some(proof_blob_id) = proof.proof_blob_id {
                    let blob_storage = self
                        .blob_storage_provider
                        .get_blob_storage(BlobStorageType::Db)?;

                    blob_storage
                        .delete(&proof_blob_id)
                        .await
                        .error_while("deleting proof blob")?;
                }
            }

            page += 1;
        }
    }
}
