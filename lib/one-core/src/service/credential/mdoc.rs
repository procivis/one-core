use anyhow::Context;
use one_crypto::encryption::{decrypt_string, encrypt_string};
use secrecy::{ExposeSecret, SecretSlice, SecretString};
use time::OffsetDateTime;

use crate::config::{ConfigValidationError, core_config};
use crate::model::blob::{Blob, BlobType, UpdateBlobRequest};
use crate::model::credential::{
    Clearable, Credential, CredentialStateEnum, UpdateCredentialRequest,
};
use crate::model::did::KeyRole;
use crate::proto::http_client::HttpClient;
use crate::proto::key_verification::KeyVerification;
use crate::provider::blob_storage_provider::BlobStorageType;
use crate::provider::credential_formatter::model::DetailCredential;
use crate::provider::issuance_protocol::deserialize_interaction_data;
use crate::provider::issuance_protocol::error::IssuanceProtocolError;
use crate::provider::issuance_protocol::openid4vci_draft13::model::{
    HolderInteractionData, OpenID4VCICredentialRequestDTO, OpenID4VCIDraft13Params,
    OpenID4VCIProofRequestDTO, OpenID4VCITokenResponseDTO,
};
use crate::provider::issuance_protocol::openid4vci_draft13::proof_formatter::OpenID4VCIProofJWTFormatter;
use crate::provider::issuance_protocol::openid4vci_draft13_swiyu::OpenID4VCISwiyuParams;
use crate::provider::issuance_protocol::openid4vci_final1_0::model::OpenID4VCIFinal1Params;
use crate::repository::interaction_repository::InteractionRepository;
use crate::service::credential::CredentialService;
use crate::service::credential::dto::CredentialRevocationCheckResponseDTO;
use crate::service::error::{MissingProviderError, ServiceError};
use crate::service::oid4vci_draft13::dto::OpenID4VCICredentialResponseDTO;

impl CredentialService {
    pub(super) async fn update_mdoc(
        &self,
        credential: &Credential,
        detail_credential: &DetailCredential,
        force_refresh: bool,
    ) -> Result<CredentialRevocationCheckResponseDTO, ServiceError> {
        let current_state = credential.state;
        let new_state = self
            .check_mdoc_update(credential, detail_credential, force_refresh)
            .await?;

        if new_state != current_state {
            let update_request = UpdateCredentialRequest {
                state: Some(new_state),
                suspend_end_date: Clearable::DontTouch,
                ..Default::default()
            };

            self.credential_repository
                .update_credential(credential.id, update_request)
                .await?;
        }

        Ok(CredentialRevocationCheckResponseDTO {
            credential_id: credential.id,
            status: new_state.into(),
            success: true,
            reason: None,
        })
    }

    async fn check_mdoc_update(
        &self,
        credential: &Credential,
        detail_credential: &DetailCredential,
        force_refresh: bool,
    ) -> Result<CredentialStateEnum, ServiceError> {
        let mut interaction_data: HolderInteractionData = deserialize_interaction_data(
            credential
                .interaction
                .as_ref()
                .and_then(|i| i.data.as_ref()),
        )?;

        let new_state = if is_mso_expired(detail_credential) {
            CredentialStateEnum::Suspended
        } else {
            CredentialStateEnum::Accepted
        };

        let result = check_access_token(
            credential,
            &*self.interaction_repository,
            &mut interaction_data,
            &*self.client,
            &encryption_key_from_config(&self.config, credential)?,
        )
        .await;

        let new_state = match result {
            Ok(TokenCheckResult::RefreshPossible { access_token })
                if force_refresh || mso_requires_update(detail_credential) =>
            {
                let result = self
                    .obtain_and_update_new_mso(credential, &interaction_data, &access_token)
                    .await;

                // If we have managed to refresh mso
                if result.is_ok() {
                    CredentialStateEnum::Accepted
                } else {
                    new_state
                }
            }
            Ok(TokenCheckResult::RefreshNotPossible) if is_mso_expired(detail_credential) => {
                CredentialStateEnum::Revoked
            }
            Err(_)
            | Ok(TokenCheckResult::RefreshNotPossible)
            | Ok(TokenCheckResult::RefreshPossible { .. }) => new_state,
        };
        Ok(new_state)
    }

    async fn obtain_and_update_new_mso(
        &self,
        credential: &Credential,
        interaction_data: &HolderInteractionData,
        access_token: &SecretString,
    ) -> Result<(), ServiceError> {
        let key = credential
            .key
            .as_ref()
            .ok_or(ServiceError::Other("Missing key".to_owned()))?
            .clone();
        let holder_did = credential
            .holder_identifier
            .as_ref()
            .ok_or(ServiceError::Other("Missing holder identifier".to_owned()))?
            .did
            .as_ref()
            .ok_or(ServiceError::Other("Missing holder did".to_owned()))?
            .clone();

        let key = holder_did.find_key(&key.id, &Default::default())?;
        let key_id = holder_did.verification_method_id(key);

        let auth_fn = self
            .key_provider
            .get_signature_provider(&key.key, None, self.key_algorithm_provider.clone())
            .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?;

        let proof_jwt = OpenID4VCIProofJWTFormatter::format_proof(
            interaction_data.issuer_url.clone(),
            Some(key_id),
            None,
            interaction_data.nonce.clone(),
            auth_fn,
        )
        .await
        .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?;

        let schema = credential
            .schema
            .as_ref()
            .ok_or(IssuanceProtocolError::Failed("schema is None".to_string()))?;

        let body = OpenID4VCICredentialRequestDTO {
            proof: OpenID4VCIProofRequestDTO {
                proof_type: "jwt".to_string(),
                jwt: proof_jwt,
            },
            format: "mso_mdoc".to_owned(),
            vct: None,
            credential_definition: None,
            doctype: Some(schema.schema_id.to_owned()),
        };

        let response = self
            .client
            .post(&interaction_data.credential_endpoint)
            .bearer_auth(access_token.expose_secret())
            .json(&body)
            .context("json error")
            .map_err(IssuanceProtocolError::Transport)?
            .send()
            .await
            .context("send error")
            .map_err(IssuanceProtocolError::Transport)?;
        let response = response
            .error_for_status()
            .context("status error")
            .map_err(IssuanceProtocolError::Transport)?;

        let result: OpenID4VCICredentialResponseDTO =
            serde_json::from_slice(&response.body).map_err(IssuanceProtocolError::JsonError)?;

        let formatter = self
            .formatter_provider
            .get_credential_formatter(&schema.format)
            .ok_or_else(|| {
                IssuanceProtocolError::Failed(format!("{} formatter not found", schema.format))
            })?;

        let verification_fn = Box::new(KeyVerification {
            key_algorithm_provider: self.key_algorithm_provider.clone(),
            did_method_provider: self.did_method_provider.clone(),
            key_role: KeyRole::AssertionMethod,
            certificate_validator: self.certificate_validator.clone(),
        });
        formatter
            .extract_credentials(&result.credential, Some(schema), verification_fn, None)
            .await
            .map_err(|e| IssuanceProtocolError::CredentialVerificationFailed(e.into()))?;

        let db_blob_storage = self
            .blob_storage_provider
            .get_blob_storage(BlobStorageType::Db)
            .await
            .ok_or_else(|| MissingProviderError::BlobStorage(BlobStorageType::Db.to_string()))?;

        let blob_id = match credential.credential_blob_id {
            None => {
                let blob = Blob::new(result.credential, BlobType::Credential);
                db_blob_storage.create(blob.clone()).await?;
                blob.id
            }
            Some(blob_id) => {
                db_blob_storage
                    .update(
                        &blob_id,
                        UpdateBlobRequest {
                            value: Some(result.credential.into()),
                        },
                    )
                    .await?;
                blob_id
            }
        };

        // Update credential value
        let update_request = UpdateCredentialRequest {
            credential_blob_id: Some(blob_id),
            suspend_end_date: Clearable::DontTouch,
            ..Default::default()
        };

        self.credential_repository
            .update_credential(credential.id, update_request)
            .await?;
        Ok(())
    }
}

enum TokenCheckResult {
    RefreshNotPossible,
    RefreshPossible { access_token: SecretString },
}

fn encryption_key_from_config(
    config: &core_config::CoreConfig,
    credential: &Credential,
) -> Result<SecretSlice<u8>, ServiceError> {
    let fields = config
        .issuance_protocol
        .get_fields(&credential.protocol)
        .map_err(ServiceError::ConfigValidationError)?;

    Ok(match fields.r#type {
        core_config::IssuanceProtocolType::OpenId4VciDraft13 => {
            let params = fields
                .deserialize::<OpenID4VCIDraft13Params>()
                .map_err(|source| ConfigValidationError::FieldsDeserialization {
                    key: credential.protocol.to_string(),
                    source,
                })?;
            params.encryption
        }
        core_config::IssuanceProtocolType::OpenId4VciDraft13Swiyu => {
            let params = fields
                .deserialize::<OpenID4VCISwiyuParams>()
                .map_err(|source| ConfigValidationError::FieldsDeserialization {
                    key: credential.protocol.to_string(),
                    source,
                })?;
            params.encryption
        }
        core_config::IssuanceProtocolType::OpenId4VciFinal1_0 => {
            let params = fields
                .deserialize::<OpenID4VCIFinal1Params>()
                .map_err(|source| ConfigValidationError::FieldsDeserialization {
                    key: credential.protocol.to_string(),
                    source,
                })?;
            params.encryption
        }
    })
}

async fn check_access_token(
    credential: &Credential,
    interactions: &dyn InteractionRepository,
    interaction_data: &mut HolderInteractionData,
    client: &dyn HttpClient,
    token_encryption_key: &SecretSlice<u8>,
) -> Result<TokenCheckResult, ServiceError> {
    let now = OffsetDateTime::now_utc();
    let access_token_expires_at =
        interaction_data
            .access_token_expires_at
            .ok_or(ServiceError::Other(
                "Missing expires_at in interaction data for mso".to_owned(),
            ))?;

    if access_token_expires_at > now {
        // stored access token still valid
        let access_token = decrypt_string(
            interaction_data
                .access_token
                .as_ref()
                .ok_or(ServiceError::Other("missing access_token".to_string()))?,
            token_encryption_key,
        )
        .map_err(|err| ServiceError::Other(format!("failed to decrypt refresh token: {err}")))?;
        return Ok(TokenCheckResult::RefreshPossible { access_token });
    }

    // Fetch a new one
    let refresh_token = if let Some(refresh_token) = interaction_data.refresh_token.as_ref() {
        decrypt_string(refresh_token, token_encryption_key)
            .map_err(|err| ServiceError::Other(format!("failed to decrypt refresh token: {err}")))?
    } else {
        // missing refresh token
        return Ok(TokenCheckResult::RefreshNotPossible);
    };

    if interaction_data
        .refresh_token_expires_at
        .is_some_and(|expires_at| expires_at <= now)
    {
        // Expired refresh token
        return Ok(TokenCheckResult::RefreshNotPossible);
    }

    let token_endpoint =
        interaction_data
            .token_endpoint
            .as_ref()
            .ok_or(IssuanceProtocolError::Failed(
                "token endpoint is missing".to_string(),
            ))?;

    let token_response: OpenID4VCITokenResponseDTO = client
        .post(token_endpoint)
        .form(&[
            ("refresh_token", refresh_token.expose_secret().to_string()),
            ("grant_type", "refresh_token".to_string()),
        ])
        .context("form error")
        .map_err(IssuanceProtocolError::Transport)?
        .send()
        .await
        .context("send error")
        .map_err(IssuanceProtocolError::Transport)?
        .error_for_status()
        .context("status error")
        .map_err(IssuanceProtocolError::Transport)?
        .json()
        .context("parsing error")
        .map_err(IssuanceProtocolError::Transport)?;

    let encrypted_token = encrypt_string(&token_response.access_token, token_encryption_key)
        .map_err(|err| {
            IssuanceProtocolError::Failed(format!("failed to encrypt access token: {err}"))
        })?;
    interaction_data.access_token = Some(encrypted_token);
    interaction_data.access_token_expires_at =
        OffsetDateTime::from_unix_timestamp(token_response.expires_in.0).ok();

    interaction_data.refresh_token = token_response
        .refresh_token
        .map(|token| encrypt_string(&token, token_encryption_key))
        .transpose()
        .map_err(|err| {
            IssuanceProtocolError::Failed(format!("failed to encrypt refresh token: {err}"))
        })?;
    interaction_data.refresh_token_expires_at = token_response
        .refresh_token_expires_in
        .and_then(|expires_in| OffsetDateTime::from_unix_timestamp(expires_in.0).ok());
    interaction_data.nonce = token_response.c_nonce;

    let mut interaction = credential
        .interaction
        .as_ref()
        .ok_or(ServiceError::Other("Missing interaction".to_owned()))?
        .clone();

    interaction.data = Some(
        serde_json::to_vec(&interaction_data)
            .map_err(|e| ServiceError::MappingError(e.to_string()))?,
    );
    // Update in database
    interactions
        .update_interaction(interaction.id, interaction.into())
        .await?;

    Ok(TokenCheckResult::RefreshPossible {
        access_token: token_response.access_token,
    })
}

fn is_mso_expired(detail_credential: &DetailCredential) -> bool {
    let now = OffsetDateTime::now_utc();

    if let Some(valid_until) = detail_credential.valid_until {
        return valid_until < now;
    }

    false
}

fn mso_requires_update(detail_credential: &DetailCredential) -> bool {
    let now = OffsetDateTime::now_utc();

    if let Some(update_at) = detail_credential.update_at {
        return update_at < now;
    }

    is_mso_expired(detail_credential)
}
