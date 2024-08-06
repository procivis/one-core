use crate::model::credential::{Credential, CredentialRelations, CredentialStateRelations};
use crate::model::did::Did;
use crate::model::revocation_list::{
    RevocationList, RevocationListId, RevocationListPurpose, RevocationListRelations,
};
use crate::model::validity_credential::Lvvc;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::revocation_list_repository::RevocationListRepository;
use crate::repository::validity_credential_repository::ValidityCredentialRepository;
use crate::service::error::{MissingProviderError, ServiceError};
use dto_mapper::convert_inner;
use one_providers::key_storage::provider::KeyProvider;
use one_providers::revocation::imp::bitstring_status_list::model::RevocationUpdateData;
use one_providers::revocation::imp::bitstring_status_list::{
    format_status_list_credential, generate_bitstring_from_credentials,
    purpose_to_credential_state_enum,
};
use one_providers::revocation::model::{CredentialAdditionalData, RevocationUpdate};
use one_providers::revocation::provider::RevocationMethodProvider;
use std::sync::Arc;
use time::OffsetDateTime;
use uuid::Uuid;

pub(crate) async fn generate_credential_additional_data(
    credential: &Credential,
    credential_repository: &Arc<dyn CredentialRepository>,
    revocation_list_repository: &Arc<dyn RevocationListRepository>,
    revocation_method_provider: &Arc<dyn RevocationMethodProvider>,
    key_provider: &Arc<dyn KeyProvider>,
    core_base_url: &Option<String>,
) -> Result<Option<CredentialAdditionalData>, ServiceError> {
    let revocation_method_name = credential
        .schema
        .as_ref()
        .ok_or(ServiceError::MappingError(
            "credential_schema is None".to_string(),
        ))?
        .revocation_method
        .as_str();
    let revocation_method = revocation_method_provider
        .get_revocation_method(revocation_method_name)
        .ok_or(ServiceError::MissingProvider(
            MissingProviderError::RevocationMethod(revocation_method_name.to_string()),
        ))?;

    let status_type = revocation_method.get_status_type();
    if status_type != "BitstringStatusListEntry" && status_type != "StatusList2021Entry" {
        return Ok(None);
    }

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

    let revocation_list_id = get_revocation_list_id(
        &credentials_by_issuer_did,
        issuer_did,
        RevocationListPurpose::Revocation,
        revocation_list_repository,
        key_provider,
        core_base_url,
    )
    .await?;

    let suspension_list_id = get_revocation_list_id(
        &credentials_by_issuer_did,
        issuer_did,
        RevocationListPurpose::Suspension,
        revocation_list_repository,
        key_provider,
        core_base_url,
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
    lvvc_repository: &Arc<dyn ValidityCredentialRepository>,
    revocation_list_repository: &Arc<dyn RevocationListRepository>,
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

pub(crate) async fn get_revocation_list_id(
    credentials_by_issuer_did: &[one_providers::common_models::credential::OpenCredential],
    issuer_did: &Did,
    purpose: RevocationListPurpose,
    revocation_list_repository: &Arc<dyn RevocationListRepository>,
    key_provider: &Arc<dyn KeyProvider>,
    core_base_url: &Option<String>,
) -> Result<RevocationListId, ServiceError> {
    let revocation_list = revocation_list_repository
        .get_revocation_by_issuer_did_id(
            &issuer_did.id,
            purpose.to_owned(),
            &RevocationListRelations::default(),
        )
        .await?;

    let credential_state = purpose_to_credential_state_enum(purpose.to_owned().into());

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
                &issuer_did.to_owned().into(),
                encoded_list,
                purpose.to_owned().into(),
                key_provider,
                core_base_url,
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
