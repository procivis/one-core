use std::sync::Arc;

use one_dto_mapper::convert_inner;
use time::OffsetDateTime;
use uuid::Uuid;

use super::params::convert_params;
use crate::model::credential::{Credential, CredentialRelations, CredentialStateRelations};
use crate::model::did::Did;
use crate::model::revocation_list::{
    RevocationList, RevocationListId, RevocationListPurpose, RevocationListRelations,
};
use crate::model::validity_credential::Lvvc;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::credential_formatter::CredentialFormatter;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::revocation::bitstring_status_list::model::RevocationUpdateData;
use crate::provider::revocation::bitstring_status_list::{
    format_status_list_credential, generate_bitstring_from_credentials,
    purpose_to_credential_state_enum, Params,
};
use crate::provider::revocation::model::{CredentialAdditionalData, RevocationUpdate};
use crate::provider::revocation::RevocationMethod;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::revocation_list_repository::RevocationListRepository;
use crate::repository::validity_credential_repository::ValidityCredentialRepository;
use crate::service::error::{MissingProviderError, ServiceError};

#[allow(clippy::too_many_arguments)]
pub(crate) async fn generate_credential_additional_data(
    credential: &Credential,
    credential_repository: &dyn CredentialRepository,
    revocation_list_repository: &dyn RevocationListRepository,
    revocation_method: &dyn RevocationMethod,
    formatter_provider: &dyn CredentialFormatterProvider,
    key_provider: &Arc<dyn KeyProvider>,
    core_base_url: &Option<String>,
    issuer_key_id: String,
) -> Result<Option<CredentialAdditionalData>, ServiceError> {
    let status_type = revocation_method.get_status_type();
    if status_type != "BitstringStatusListEntry" && status_type != "StatusList2021Entry" {
        return Ok(None);
    }

    let params: Params = convert_params(revocation_method.get_params()?)?;

    let bitstring_credential_format: String = params
        .bitstring_credential_format
        .unwrap_or_default()
        .into();

    let issuer_did = credential
        .issuer_did
        .as_ref()
        .ok_or(ServiceError::MappingError("issuer_did is None".to_string()))?;

    let credentials_by_issuer_did = convert_inner(
        credential_repository
            .get_credentials_by_issuer_did_id(
                &issuer_did.id,
                &CredentialRelations {
                    state: Some(CredentialStateRelations::default()),
                    ..Default::default()
                },
            )
            .await?,
    );

    let formatter = formatter_provider
        .get_formatter(&bitstring_credential_format)
        .ok_or_else(|| {
            ServiceError::MissingProvider(MissingProviderError::Formatter(
                bitstring_credential_format.to_owned(),
            ))
        })?;

    let revocation_list_id = get_or_create_revocation_list_id(
        &credentials_by_issuer_did,
        issuer_did,
        RevocationListPurpose::Revocation,
        revocation_list_repository,
        key_provider,
        core_base_url,
        &*formatter,
        issuer_key_id.clone(),
    )
    .await?;

    let suspension_list_id = get_or_create_revocation_list_id(
        &credentials_by_issuer_did,
        issuer_did,
        RevocationListPurpose::Suspension,
        revocation_list_repository,
        key_provider,
        core_base_url,
        &*formatter,
        issuer_key_id,
    )
    .await?;

    Ok(Some(CredentialAdditionalData {
        credentials_by_issuer_did,
        revocation_list_id,
        suspension_list_id,
    }))
}

pub(crate) async fn process_update(
    revocation_update: RevocationUpdate,
    lvvc_repository: &dyn ValidityCredentialRepository,
    revocation_list_repository: &dyn RevocationListRepository,
) -> Result<(), ServiceError> {
    if revocation_update.status_type == "LVVC" {
        let update_data: Lvvc = serde_json::from_slice(&revocation_update.data)
            .map_err(|e| ServiceError::Other(e.to_string()))?;
        lvvc_repository.insert(update_data.into()).await?;
    } else if revocation_update.status_type == "BitstringStatusListEntry" {
        let update_data: RevocationUpdateData = serde_json::from_slice(&revocation_update.data)
            .map_err(|e| ServiceError::Other(e.to_string()))?;
        revocation_list_repository
            .update_credentials(&update_data.id, update_data.value)
            .await?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn get_or_create_revocation_list_id(
    credentials_by_issuer_did: &[Credential],
    issuer_did: &Did,
    purpose: RevocationListPurpose,
    revocation_list_repository: &dyn RevocationListRepository,
    key_provider: &Arc<dyn KeyProvider>,
    core_base_url: &Option<String>,
    formatter: &dyn CredentialFormatter,
    key_id: String,
) -> Result<RevocationListId, ServiceError> {
    let revocation_list = revocation_list_repository
        .get_revocation_by_issuer_did_id(
            &issuer_did.id,
            purpose.to_owned(),
            &RevocationListRelations::default(),
        )
        .await?;

    let credential_state = purpose_to_credential_state_enum(purpose.clone());

    Ok(match revocation_list {
        Some(value) => value.id,
        None => {
            let encoded_list = generate_bitstring_from_credentials(
                credentials_by_issuer_did,
                credential_state,
                None,
            )
            .await?;

            let revocation_list_id = Uuid::new_v4();
            let list_credential = format_status_list_credential(
                &revocation_list_id,
                issuer_did,
                encoded_list,
                purpose.to_owned(),
                key_provider,
                core_base_url,
                formatter,
                key_id,
            )
            .await?;

            let now = OffsetDateTime::now_utc();
            revocation_list_repository
                .create_revocation_list(RevocationList {
                    id: revocation_list_id,
                    created_date: now,
                    last_modified: now,
                    credentials: list_credential.into_bytes(),
                    purpose,
                    issuer_did: Some(issuer_did.to_owned()),
                })
                .await?
        }
    })
}
