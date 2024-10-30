use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use time::OffsetDateTime;
use uuid::Uuid;

use super::Task;
use crate::model::history::{HistoryAction, HistoryEntityType, HistoryFilterValue};
use crate::model::list_filter::ListFilterValue;
use crate::model::list_query::{ListPagination, ListQuery};
use crate::model::proof::ProofStateEnum;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::proof_repository::ProofRepository;
use crate::service::error::ServiceError;
use crate::service::proof::dto::ProofFilterValue;

pub struct RetainProofCheck {
    proof_repository: Arc<dyn ProofRepository>,
    history_repository: Arc<dyn HistoryRepository>,
}

impl RetainProofCheck {
    pub fn new(
        proof_repository: Arc<dyn ProofRepository>,
        history_repository: Arc<dyn HistoryRepository>,
    ) -> Self {
        Self {
            proof_repository,
            history_repository,
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
                        & HistoryFilterValue::Action(HistoryAction::ClaimsRemoved),
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
                        ProofFilterValue::ProofStates(vec![ProofStateEnum::Accepted]).condition()
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

                let completed_date = proof
                    .state
                    .clone()
                    .ok_or_else(|| ServiceError::MappingError("state is None".into()))?
                    .iter()
                    .find(|state| state.state == ProofStateEnum::Accepted)
                    .map(|state| state.created_date)
                    .ok_or_else(|| ServiceError::MappingError("completed_date is None".into()))?;

                if completed_date + Duration::from_secs(schema.expire_duration as _) > now {
                    continue;
                }

                self.proof_repository.delete_proof_claims(&proof.id).await?;
            }

            page += 1;
        }
    }
}
