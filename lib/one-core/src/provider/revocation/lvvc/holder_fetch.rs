//! Fetching and caching LVVC on holder side.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use super::dto::IssuerResponseDTO;
use super::Params;
use crate::model::credential::{Credential, CredentialRole};
use crate::model::did::KeyRole;
use crate::model::validity_credential::{Lvvc, ValidityCredential, ValidityCredentialType};
use crate::provider::credential_formatter::jwt::model::{JWTHeader, JWTPayload};
use crate::provider::credential_formatter::jwt::Jwt;
use crate::provider::credential_formatter::model::CredentialStatus;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::http_client::HttpClient;
use crate::provider::revocation::error::RevocationError;
use crate::repository::validity_credential_repository::ValidityCredentialRepository;
use crate::KeyProvider;

/// HOLDER: fetch remote or get locally cached LVVC credential
pub(crate) async fn holder_get_lvvc(
    linked_credential: &Credential,
    credential_status: &CredentialStatus,
    validity_credential_repository: &dyn ValidityCredentialRepository,
    key_provider: &dyn KeyProvider,
    did_method_provider: &dyn DidMethodProvider,
    http_client: &dyn HttpClient,
    params: &Params,
) -> Result<ValidityCredential, RevocationError> {
    let locally_stored_lvvc = validity_credential_repository
        .get_latest_by_credential_id(linked_credential.id, ValidityCredentialType::Lvvc)
        .await
        .map_err(|err| RevocationError::ValidationError(err.to_string()))?;
    if let Some(lvvc) = &locally_stored_lvvc {
        if lvvc.created_date + params.minimum_refresh_time > OffsetDateTime::now_utc() {
            // the stored credential is fresh, no need to fetch an update
            return Ok(lvvc.to_owned());
        }
    }

    match fetch_remote_lvvc(
        linked_credential,
        credential_status,
        key_provider,
        did_method_provider,
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
    did_method_provider: &dyn DidMethodProvider,
    http_client: &dyn HttpClient,
) -> Result<Lvvc, RevocationError> {
    let lvvc_url = credential_status
        .id
        .as_ref()
        .ok_or(RevocationError::ValidationError(
            "LVVC status id is missing".to_string(),
        ))?;

    let bearer_token =
        prepare_bearer_token(linked_credential, key_provider, did_method_provider).await?;
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

async fn prepare_bearer_token(
    credential: &Credential,
    key_provider: &dyn KeyProvider,
    did_method_provider: &dyn DidMethodProvider,
) -> Result<String, RevocationError> {
    if credential.role != CredentialRole::Holder {
        return Err(RevocationError::MappingError(
            "Can only prepare bearer_token for holder".to_string(),
        ));
    }

    let holder_did = credential
        .holder_did
        .as_ref()
        .ok_or(RevocationError::MappingError(
            "holder_did is None".to_string(),
        ))?;

    let keys = holder_did
        .keys
        .as_ref()
        .ok_or(RevocationError::MappingError("keys is None".to_string()))?;

    let authentication_key = keys
        .iter()
        .find(|key| key.role == KeyRole::Authentication)
        .ok_or(RevocationError::MappingError(
            "No authentication keys found for DID".to_string(),
        ))?;

    let payload = JWTPayload {
        issuer: Some(holder_did.did.to_string()),
        ..Default::default()
    };

    let key_id = did_method_provider
        .get_verification_method_id_from_did_and_key(holder_did, &authentication_key.key)
        .await?;

    let signer = key_provider.get_signature_provider(&authentication_key.key, None)?;
    let bearer_token = Jwt::<BearerTokenPayload> {
        header: JWTHeader {
            algorithm: authentication_key.key.key_type.to_owned(),
            key_id: Some(key_id),
            signature_type: None,
            jwk: None,
        },
        payload,
    }
    .tokenize(Some(signer))
    .await?;

    Ok(bearer_token)
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct BearerTokenPayload {
    #[serde(with = "time::serde::timestamp")]
    pub timestamp: OffsetDateTime,
}

impl Default for BearerTokenPayload {
    fn default() -> Self {
        Self {
            timestamp: OffsetDateTime::now_utc(),
        }
    }
}
