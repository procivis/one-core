use std::collections::HashSet;
use std::sync::Arc;

use serde_json::Value;
use time::OffsetDateTime;

use self::dto::LifecycleCheckResultDTO;
use super::Task;
use crate::error::ContextWithErrorCode;
use crate::model::credential::{
    Credential, CredentialFilterValue, CredentialListQuery, CredentialRole, CredentialStateEnum,
    CredentialType, UpdateCredentialRequest,
};
use crate::model::list_filter::{ComparisonType, ListFilterValue, ValueComparison};
use crate::proto::credential_validity_manager::dto::ChangeCredentialState;
use crate::proto::credential_validity_manager::{
    CredentialValidityManager, is_batch_parent_expired,
};
use crate::repository::credential_repository::CredentialRepository;
use crate::service::error::ServiceError;

pub mod dto;

pub(crate) struct LifecycleCheckProvider {
    credential_repository: Arc<dyn CredentialRepository>,
    credential_validity_manager: Arc<dyn CredentialValidityManager>,
}

impl LifecycleCheckProvider {
    pub fn new(
        credential_repository: Arc<dyn CredentialRepository>,
        credential_validity_manager: Arc<dyn CredentialValidityManager>,
    ) -> Self {
        LifecycleCheckProvider {
            credential_repository,
            credential_validity_manager,
        }
    }

    async fn reactivate_expired_suspensions(
        &self,
    ) -> Result<(Vec<shared_types::CredentialId>, u64), ServiceError> {
        let credential_list = self
            .credential_repository
            .get_credential_list(CredentialListQuery {
                include_count: false,
                filtering: Some(
                    CredentialFilterValue::States(vec![CredentialStateEnum::Suspended]).condition()
                        & CredentialFilterValue::Roles(vec![CredentialRole::Issuer])
                        & CredentialFilterValue::Types(vec![
                            CredentialType::Single,
                            CredentialType::BatchItem,
                        ])
                        & CredentialFilterValue::SuspendEndDate(ValueComparison {
                            comparison: ComparisonType::LessThan,
                            value: crate::clock::now_utc(),
                        })
                        & CredentialFilterValue::Deleted(false),
                ),
                ..Default::default()
            })
            .await
            .error_while("getting credentials")?;

        let mut reactivated_ids = vec![];
        for credential in &credential_list.values {
            match self
                .credential_validity_manager
                .change_credential_state(&credential.common().id, ChangeCredentialState::Accepted)
                .await
            {
                Ok(()) => reactivated_ids.push(credential.common().id),
                Err(error) => {
                    tracing::warn!(%error, "failed to reactivate credential {}", credential.common().id)
                }
            }
        }

        let total_checks = credential_list.values.len() as u64;

        Ok((reactivated_ids, total_checks))
    }

    async fn expire_stale_credentials(
        &self,
        now: OffsetDateTime,
    ) -> Result<(Vec<shared_types::CredentialId>, u64), ServiceError> {
        let base_filter =
            CredentialFilterValue::States(CredentialStateEnum::non_terminal_states().to_vec())
                .condition()
                & CredentialFilterValue::Roles(vec![
                    CredentialRole::Holder,
                    CredentialRole::Issuer,
                ])
                & CredentialFilterValue::Deleted(false);

        // `Single` credentials and batch items can only ever need expiring once their own
        // `expires_at` has passed, so - exactly like `Single` was already handled - that's
        // pushed down into the query and both are expired here in one shared pass. This avoids
        // loading (and loading the schema/format relation of) every still-valid credential on
        // each task run, and avoids a separate per-parent pass over batch items entirely.
        let stale_credentials = self
            .credential_repository
            .get_credential_list(CredentialListQuery {
                include_count: false,
                filtering: Some(
                    base_filter.clone()
                        & CredentialFilterValue::Types(vec![
                            CredentialType::Single,
                            CredentialType::BatchItem,
                        ])
                        & CredentialFilterValue::ExpiresAt(ValueComparison {
                            comparison: ComparisonType::LessThan,
                            value: now,
                        }),
                ),
                ..Default::default()
            })
            .await
            .error_while("getting single credentials and batch items")?;

        // a batch parent can also expire purely because its shared OAuth refresh token expired,
        // independent of its own `expires_at` - that can't be expressed as a DB-level filter, so
        // all non-terminal batch parents still need to be fetched and evaluated individually
        let batch_parents = self
            .credential_repository
            .get_credential_list(CredentialListQuery {
                include_count: false,
                filtering: Some(
                    base_filter & CredentialFilterValue::Types(vec![CredentialType::BatchParent]),
                ),
                ..Default::default()
            })
            .await
            .error_while("getting batch parent credentials")?;

        let total_checks = (stale_credentials.values.len() + batch_parents.values.len()) as u64;

        let mut expired_ids = vec![];

        for credential in stale_credentials.values {
            match self.expire_if_stale(&credential, now).await {
                Ok(true) => expired_ids.push(credential.common().id),
                Ok(false) => {}
                Err(error) => {
                    tracing::warn!(%error, "failed to expire credential {}", credential.common().id)
                }
            }
        }

        if !batch_parents.values.is_empty() {
            let parent_ids = batch_parents.values.iter().map(|c| c.common().id).collect();

            // any item already in a terminal state - `Expired` (just now or in a previous run),
            // but also e.g. `Revoked`/`Rejected` - is done and can't block the parent, so it's
            // excluded here by construction; a parent id that doesn't show up among these "still
            // remaining" (non-terminal) items has had every item expire or otherwise terminate
            let remaining_items = self
                .credential_repository
                .get_credential_list(CredentialListQuery {
                    include_count: false,
                    filtering: Some(
                        CredentialFilterValue::ParentCredentials(parent_ids).condition()
                            & CredentialFilterValue::Deleted(false)
                            & CredentialFilterValue::States(
                                CredentialStateEnum::non_terminal_states().to_vec(),
                            ),
                    ),
                    ..Default::default()
                })
                .await
                .error_while("getting remaining batch items")?
                .values;

            let parents_with_remaining_items: HashSet<_> = remaining_items
                .iter()
                .filter_map(|item| item.parent().map(|parent| parent.id()))
                .collect();

            for credential in batch_parents.values {
                let all_items_expired =
                    !parents_with_remaining_items.contains(&credential.common().id);

                match self
                    .expire_batch_parent_if_stale(&credential, all_items_expired, now)
                    .await
                {
                    Ok(true) => expired_ids.push(credential.common().id),
                    Ok(false) => {}
                    Err(error) => {
                        tracing::warn!(
                            %error,
                            "failed to expire batch parent credential {}",
                            credential.common().id
                        )
                    }
                }
            }
        }

        Ok((expired_ids, total_checks))
    }

    /// The parent is only expired once every item has individually expired, and its own
    /// business-level `expires_at` has passed or the shared OAuth refresh token has already
    /// expired - a still-valid refresh token past `expires_at` does not keep the batch alive,
    /// but a single still-valid item does.
    async fn expire_batch_parent_if_stale(
        &self,
        credential: &Credential,
        all_items_expired: bool,
        now: OffsetDateTime,
    ) -> Result<bool, ServiceError> {
        if !all_items_expired || credential.common().state.is_terminal() {
            return Ok(false);
        }

        let interaction = match credential.common().interaction.as_ref() {
            Some(interaction) => Some(interaction.as_ref().await?.to_owned()),
            None => None,
        };

        if !is_batch_parent_expired(credential, interaction.as_ref(), now)
            .error_while("checking batch parent expiry")?
        {
            return Ok(false);
        }

        self.credential_repository
            .update_credential(
                credential.common().id,
                UpdateCredentialRequest {
                    state: Some(CredentialStateEnum::Expired),
                    ..Default::default()
                },
            )
            .await
            .error_while("updating batch parent credential")?;

        Ok(true)
    }

    async fn expire_if_stale(
        &self,
        credential: &Credential,
        now: OffsetDateTime,
    ) -> Result<bool, ServiceError> {
        if credential.common().state.is_terminal() {
            return Ok(false);
        }

        if credential
            .common()
            .expires_at
            .is_none_or(|expires_at| expires_at >= now)
        {
            return Ok(false);
        }

        self.credential_repository
            .update_credential(
                credential.common().id,
                UpdateCredentialRequest {
                    state: Some(CredentialStateEnum::Expired),
                    ..Default::default()
                },
            )
            .await
            .error_while("updating credential")?;

        Ok(true)
    }
}

#[async_trait::async_trait]
impl Task for LifecycleCheckProvider {
    async fn run(&self, _params: Option<Value>) -> Result<Value, ServiceError> {
        let (reactivated_credential_ids, total_reactivation_checks) =
            self.reactivate_expired_suspensions().await?;

        let now = crate::clock::now_utc();
        let (expired_credential_ids, total_expiration_checks) =
            self.expire_stale_credentials(now).await?;

        let result = LifecycleCheckResultDTO {
            reactivated_credential_ids,
            total_reactivation_checks,
            expired_credential_ids,
            total_expiration_checks,
        };

        serde_json::to_value(result).map_err(|e| ServiceError::MappingError(e.to_string()))
    }
}
