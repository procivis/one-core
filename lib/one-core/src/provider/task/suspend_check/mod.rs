use std::sync::Arc;

use serde_json::Value;
use time::OffsetDateTime;

use self::dto::SuspendCheckResultDTO;
use super::Task;
use crate::model::credential::{
    Clearable, CredentialRelations, CredentialStateEnum, GetCredentialQuery,
    UpdateCredentialRequest,
};
use crate::model::credential_schema::CredentialSchemaRelations;
use crate::model::did::{DidRelations, KeyRole};
use crate::model::key::KeyRelations;
use crate::model::list_filter::{ComparisonType, ListFilterValue, ValueComparison};
use crate::model::organisation::OrganisationRelations;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::revocation::error::RevocationError;
use crate::provider::revocation::model::CredentialRevocationState;
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::revocation_list_repository::RevocationListRepository;
use crate::repository::validity_credential_repository::ValidityCredentialRepository;
use crate::service::credential::dto::CredentialFilterValue;
use crate::service::error::{EntityNotFoundError, MissingProviderError, ServiceError};
use crate::util::revocation_update::{generate_credential_additional_data, process_update};

pub mod dto;

pub(crate) struct SuspendCheckProvider {
    credential_repository: Arc<dyn CredentialRepository>,
    revocation_method_provider: Arc<dyn RevocationMethodProvider>,
    revocation_list_repository: Arc<dyn RevocationListRepository>,
    validity_credential_repository: Arc<dyn ValidityCredentialRepository>,
    formatter_provider: Arc<dyn CredentialFormatterProvider>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    key_provider: Arc<dyn KeyProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    core_base_url: Option<String>,
}

impl SuspendCheckProvider {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        credential_repository: Arc<dyn CredentialRepository>,
        revocation_method_provider: Arc<dyn RevocationMethodProvider>,
        revocation_list_repository: Arc<dyn RevocationListRepository>,
        validity_credential_repository: Arc<dyn ValidityCredentialRepository>,
        formatter_provider: Arc<dyn CredentialFormatterProvider>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        key_provider: Arc<dyn KeyProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        core_base_url: Option<String>,
    ) -> Self {
        SuspendCheckProvider {
            credential_repository,
            revocation_method_provider,
            revocation_list_repository,
            validity_credential_repository,
            formatter_provider,
            did_method_provider,
            key_provider,
            key_algorithm_provider,
            core_base_url,
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
                    CredentialFilterValue::State(vec![CredentialStateEnum::Suspended]).condition()
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
                        holder_did: Some(DidRelations::default()),
                        key: Some(KeyRelations::default()),
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

            let revocation_method = self
                .revocation_method_provider
                .get_revocation_method("BITSTRINGSTATUSLIST")
                .ok_or(MissingProviderError::RevocationMethod(
                    "BITSTRINGSTATUSLIST".to_string(),
                ))?;

            let issuer = credential
                .issuer_did
                .as_ref()
                .ok_or(ServiceError::MappingError("issuer_did is None".to_string()))?;

            let did_document = self.did_method_provider.resolve(&issuer.did, None).await?;

            let Some(verification_method) =
                did_document.find_verification_method(None, Some(KeyRole::AssertionMethod))
            else {
                return Err(ServiceError::Revocation(
                    RevocationError::KeyWithRoleNotFound(KeyRole::AssertionMethod),
                ));
            };

            let update = revocation_method
                .mark_credential_as(
                    &credential,
                    CredentialRevocationState::Valid,
                    generate_credential_additional_data(
                        &credential,
                        &*self.credential_repository,
                        &*self.revocation_list_repository,
                        &*revocation_method,
                        &*self.formatter_provider,
                        &self.key_provider,
                        &self.key_algorithm_provider,
                        &self.core_base_url,
                        verification_method.id.to_owned(),
                    )
                    .await?,
                )
                .await?;
            process_update(
                update,
                &*self.validity_credential_repository,
                &*self.revocation_list_repository,
            )
            .await?;

            self.credential_repository
                .update_credential(UpdateCredentialRequest {
                    id: credential_id,
                    state: Some(CredentialStateEnum::Accepted),
                    suspend_end_date: Clearable::ForceSet(None),
                    credential: None,
                    holder_did_id: None,
                    issuer_did_id: None,
                    interaction: None,
                    key: None,
                    redirect_uri: None,
                    claims: None,
                })
                .await?;
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
