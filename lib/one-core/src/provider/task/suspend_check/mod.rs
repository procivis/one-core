use std::sync::Arc;

use serde_json::Value;
use time::OffsetDateTime;

use crate::{
    model::{
        credential::{
            CredentialRelations, CredentialState, CredentialStateEnum, GetCredentialQuery,
            UpdateCredentialRequest,
        },
        credential_schema::CredentialSchemaRelations,
        did::DidRelations,
        key::KeyRelations,
        list_filter::{ComparisonType, ListFilterValue, ValueComparison},
        organisation::OrganisationRelations,
    },
    provider::revocation::{provider::RevocationMethodProvider, CredentialRevocationState},
    repository::{
        credential_repository::CredentialRepository, history_repository::HistoryRepository,
    },
    service::{
        credential::{dto::CredentialFilterValue, mapper::credential_revocation_history_event},
        error::{EntityNotFoundError, MissingProviderError, ServiceError},
    },
};

use self::dto::SuspendCheckResultDTO;
use super::Task;

pub mod dto;

pub(crate) struct SuspendCheckProvider {
    credential_repository: Arc<dyn CredentialRepository>,
    revocation_method_provider: Arc<dyn RevocationMethodProvider>,
    history_repository: Arc<dyn HistoryRepository>,
}

impl SuspendCheckProvider {
    pub fn new(
        credential_repository: Arc<dyn CredentialRepository>,
        revocation_method_provider: Arc<dyn RevocationMethodProvider>,
        history_repository: Arc<dyn HistoryRepository>,
    ) -> Self {
        SuspendCheckProvider {
            credential_repository,
            revocation_method_provider,
            history_repository,
        }
    }
}

#[async_trait::async_trait]
impl Task for SuspendCheckProvider {
    async fn run(&self) -> Result<Value, ServiceError> {
        let now: OffsetDateTime = OffsetDateTime::now_utc();
        let credential_list = self
            .credential_repository
            .get_credential_list(GetCredentialQuery {
                filtering: Some(
                    CredentialFilterValue::State(CredentialStateEnum::Suspended).condition()
                        & CredentialFilterValue::SuspendEndDate(ValueComparison {
                            comparison: ComparisonType::LessThan,
                            value: now,
                        }),
                ),
                ..Default::default()
            })
            .await?;

        let credentials = credential_list.values;

        for credential in credentials.iter() {
            let credential_schema =
                credential
                    .schema
                    .as_ref()
                    .ok_or(ServiceError::MappingError(
                        "credential_schema is None".to_string(),
                    ))?;

            let revocation_method = self
                .revocation_method_provider
                .get_revocation_method(&credential_schema.revocation_method)
                .ok_or(MissingProviderError::RevocationMethod(
                    credential_schema.revocation_method.clone(),
                ))?;

            let credential_id = credential.id;
            let credential = self
                .credential_repository
                .get_credential(
                    &credential_id,
                    &CredentialRelations {
                        issuer_did: Some(DidRelations {
                            keys: Some(KeyRelations::default()),
                            ..Default::default()
                        }),
                        schema: Some(CredentialSchemaRelations {
                            organisation: Some(OrganisationRelations::default()),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                )
                .await?;

            let Some(credential) = credential else {
                return Err(EntityNotFoundError::Credential(credential_id).into());
            };

            revocation_method
                .mark_credential_as(&credential, CredentialRevocationState::Valid)
                .await?;

            self.credential_repository
                .update_credential(UpdateCredentialRequest {
                    id: credential_id,
                    state: Some(CredentialState {
                        created_date: now,
                        state: CredentialStateEnum::Accepted,
                        suspend_end_date: None,
                    }),
                    credential: None,
                    holder_did_id: None,
                    issuer_did_id: None,
                    interaction: None,
                    key: None,
                    redirect_uri: None,
                })
                .await?;

            let _ = self
                .history_repository
                .create_history(credential_revocation_history_event(
                    credential_id,
                    CredentialRevocationState::Valid,
                    credential.schema.and_then(|c| c.organisation),
                ))
                .await;
        }

        let result = SuspendCheckResultDTO {
            updated_credential_ids: credentials.iter().map(|credential| credential.id).collect(),
            total_checks: credential_list.total_items,
        };

        serde_json::to_value(result).map_err(|e| ServiceError::MappingError(e.to_string()))
    }
}

#[cfg(test)]
mod test;