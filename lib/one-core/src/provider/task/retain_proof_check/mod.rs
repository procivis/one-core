use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};
use shared_types::CredentialId;
use time::OffsetDateTime;
use uuid::Uuid;

use super::Task;
use crate::model::claim::ClaimRelations;
use crate::model::credential::{CredentialFilterValue, CredentialRelations, GetCredentialQuery};
use crate::model::history::{HistoryAction, HistoryEntityType, HistoryFilterValue};
use crate::model::list_filter::ListFilterValue;
use crate::model::list_query::{ListPagination, ListQuery};
use crate::model::proof::{ProofClaimRelations, ProofRelations, ProofStateEnum};
use crate::provider::blob_storage_provider::{BlobStorageProvider, BlobStorageType};
use crate::repository::claim_repository::ClaimRepository;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::proof_repository::ProofRepository;
use crate::service::error::{EntityNotFoundError, MissingProviderError, ServiceError};
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
    async fn run(&self) -> Result<Value, ServiceError> {
        let processed_events: Vec<_> = self
            .history_repository
            .get_history_list(ListQuery {
                filtering: Some(
                    HistoryFilterValue::EntityTypes(vec![HistoryEntityType::Proof]).condition()
                        & HistoryFilterValue::Actions(vec![HistoryAction::ClaimsRemoved]),
                ),
                pagination: None,
                sorting: None,
                include: None,
            })
            .await?
            .values
            .into_iter()
            .flat_map(|event| event.entity_id)
            .map(|event_id| Uuid::from(event_id).into())
            .collect();

        let now = OffsetDateTime::now_utc();
        let mut page = 0;

        loop {
            let proofs = self
                .proof_repository
                .get_proof_list(ListQuery {
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
                .await?;

            if proofs.values.is_empty() {
                return Ok(json!({}));
            }

            for proof in proofs.values {
                let schema = proof
                    .schema
                    .clone()
                    .ok_or_else(|| ServiceError::MappingError("schema is None".into()))?;

                if proof.completed_date.is_some_and(|value| {
                    value + Duration::from_secs(schema.expire_duration as _) > now
                }) {
                    continue;
                }

                let credential_ids = self
                    .proof_repository
                    .get_proof(
                        &proof.id,
                        &ProofRelations {
                            claims: Some(ProofClaimRelations {
                                claim: ClaimRelations::default(),
                                credential: Some(CredentialRelations::default()),
                            }),
                            ..Default::default()
                        },
                    )
                    .await?
                    .ok_or(ServiceError::EntityNotFound(EntityNotFoundError::Proof(
                        proof.id,
                    )))?
                    .claims
                    .ok_or(ServiceError::MappingError("claims are None".to_string()))?
                    .into_iter()
                    .map(|proof_claim| {
                        Ok::<CredentialId, ServiceError>(
                            proof_claim
                                .credential
                                .ok_or(ServiceError::MappingError(
                                    "credential is None".to_string(),
                                ))?
                                .id,
                        )
                    })
                    .collect::<Result<HashSet<_>, _>>()?;

                self.proof_repository.delete_proof_claims(&proof.id).await?;
                self.claim_repository
                    .delete_claims_for_credentials(credential_ids.clone())
                    .await?;

                let blob_storage = self
                    .blob_storage_provider
                    .get_blob_storage(BlobStorageType::Db)
                    .await
                    .ok_or_else(|| {
                        MissingProviderError::BlobStorage(BlobStorageType::Db.to_string())
                    })?;

                let credential_blob_ids = self
                    .credential_repository
                    .get_credential_list(GetCredentialQuery {
                        filtering: Some(
                            CredentialFilterValue::CredentialIds(Vec::from_iter(
                                credential_ids.clone(),
                            ))
                            .condition(),
                        ),
                        ..GetCredentialQuery::default()
                    })
                    .await?
                    .values
                    .into_iter()
                    .filter_map(|c| c.credential_blob_id)
                    .collect::<Vec<_>>();

                blob_storage.delete_many(&credential_blob_ids).await?;
                self.credential_repository
                    .delete_credential_blobs(credential_ids)
                    .await?;

                if let Some(proof_blob_id) = proof.proof_blob_id {
                    let blob_storage = self
                        .blob_storage_provider
                        .get_blob_storage(BlobStorageType::Db)
                        .await
                        .ok_or_else(|| {
                            MissingProviderError::BlobStorage(BlobStorageType::Db.to_string())
                        })?;

                    blob_storage.delete(&proof_blob_id).await?;
                }
            }

            page += 1;
        }
    }
}
