//! Fetching and caching LVVC on holder side.

use std::sync::Arc;

use time::OffsetDateTime;
use uuid::Uuid;

use super::Params;
use super::dto::IssuerResponseDTO;
use crate::KeyProvider;
use crate::model::credential::{Credential, CredentialRole};
use crate::model::validity_credential::{Lvvc, ValidityCredential, ValidityCredentialType};
use crate::provider::credential_formatter::model::CredentialStatus;
use crate::provider::http_client::HttpClient;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::revocation::error::RevocationError;
use crate::repository::validity_credential_repository::ValidityCredentialRepository;
use crate::util::bearer_token::prepare_bearer_token;

/// HOLDER: fetch remote or get locally cached LVVC credential
#[allow(clippy::too_many_arguments)]
pub(crate) async fn holder_get_lvvc(
    linked_credential: &Credential,
    credential_status: &CredentialStatus,
    validity_credential_repository: &dyn ValidityCredentialRepository,
    key_provider: &dyn KeyProvider,
    key_algorithm_provider: &Arc<dyn KeyAlgorithmProvider>,
    http_client: &dyn HttpClient,
    params: &Params,
    force_refresh: bool,
) -> Result<ValidityCredential, RevocationError> {
    let locally_stored_lvvc = validity_credential_repository
        .get_latest_by_credential_id(linked_credential.id, ValidityCredentialType::Lvvc)
        .await
        .map_err(|err| RevocationError::ValidationError(err.to_string()))?;
    if let Some(lvvc) = &locally_stored_lvvc {
        if !force_refresh
            && lvvc.created_date + params.minimum_refresh_time > OffsetDateTime::now_utc()
        {
            // the stored credential is fresh and preferences allow caching, no need to fetch an update
            return Ok(lvvc.to_owned());
        }
    }

    match fetch_remote_lvvc(
        linked_credential,
        credential_status,
        key_provider,
        key_algorithm_provider,
        http_client,
    )
    .await
    {
        Ok(remote_lvvc) => {
            // remove previously cached entries
            validity_credential_repository
                .remove_all_by_credential_id(linked_credential.id, ValidityCredentialType::Lvvc)
                .await
                .map_err(|err| RevocationError::ValidationError(err.to_string()))?;

            let lvvc: ValidityCredential = remote_lvvc.into();

            // insert new entry
            validity_credential_repository
                .insert(lvvc.to_owned())
                .await
                .map_err(|err| RevocationError::ValidationError(err.to_string()))?;

            Ok(lvvc)
        }
        Err(remote_fetch_err) => {
            // don't fall back to the existing LVVC credential on force refresh
            if force_refresh {
                return Err(remote_fetch_err);
            }
            // fetching remote LVVC failed, use locally stored (if any)
            locally_stored_lvvc.ok_or(remote_fetch_err)
        }
    }
}

/// Downloads a fresh LVVC from issuer
async fn fetch_remote_lvvc(
    linked_credential: &Credential,
    credential_status: &CredentialStatus,
    key_provider: &dyn KeyProvider,
    key_algorithm_provider: &Arc<dyn KeyAlgorithmProvider>,
    http_client: &dyn HttpClient,
) -> Result<Lvvc, RevocationError> {
    let lvvc_url = credential_status
        .id
        .as_ref()
        .ok_or(RevocationError::ValidationError(
            "LVVC status id is missing".to_string(),
        ))?;

    if linked_credential.role != CredentialRole::Holder {
        return Err(RevocationError::MappingError(
            "Can only prepare bearer_token for holder".to_string(),
        ));
    }

    let holder_did = linked_credential
        .holder_identifier
        .as_ref()
        .ok_or(RevocationError::MappingError(
            "holder_identifier is None".to_string(),
        ))?
        .did
        .as_ref()
        .ok_or(RevocationError::MappingError(
            "holder_did is None".to_string(),
        ))?;

    let bearer_token = prepare_bearer_token(holder_did, key_provider, key_algorithm_provider)
        .await
        .map_err(|e| RevocationError::MappingError(e.to_string()))?;

    let response: IssuerResponseDTO = http_client
        .get(lvvc_url.as_str())
        .bearer_auth(&bearer_token)
        .send()
        .await?
        .error_for_status()?
        .json()?;

    Ok(Lvvc {
        id: Uuid::new_v4(),
        created_date: OffsetDateTime::now_utc(),
        credential: response.credential.into_bytes(),
        linked_credential_id: linked_credential.id,
    })
}
