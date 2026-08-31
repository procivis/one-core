use one_crypto::Hasher;
use one_crypto::hasher::sha256::SHA256;
use shared_types::{DidValue, OrganisationId};
use standardized_types::oauth2::token::TokenRequest;
use standardized_types::openid4vci::CredentialConfiguration;

use super::mapper::credential_config_to_holder_signing_algs_and_key_storage_security;
use super::model::OpenID4VCIIssuerInteractionDataDTO;
use crate::config::core_config::KeySecurityLevelType;
use crate::error::ContextWithErrorCode;
use crate::model::credential::{Credential, CredentialStateEnum};
use crate::model::credential_schema_format::CredentialSchemaFormat;
use crate::model::identifier::IdentifierData;
use crate::model::instance::{
    InstanceFilterValue, InstanceListQuery, InstanceRole, InstanceStatus,
};
use crate::model::interaction::Interaction;
use crate::model::list_filter::ListFilterValue;
use crate::provider::issuance_protocol::error::{
    IssuanceProtocolError, OpenID4VCIError, OpenIDIssuanceError,
};
use crate::provider::issuance_protocol::model::CredentialWithBlob;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_security_level::provider::KeySecurityLevelProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::repository::instance_repository::InstanceRepository;

pub(crate) fn throw_if_token_request_invalid(
    request: &TokenRequest,
) -> Result<(), OpenIDIssuanceError> {
    match &request {
        TokenRequest::PreAuthorizedCode {
            pre_authorized_code,
            tx_code: _,
        } if pre_authorized_code.is_empty() => Err(OpenIDIssuanceError::OpenID4VCI(
            OpenID4VCIError::InvalidRequest,
        )),
        TokenRequest::RefreshToken { refresh_token } if refresh_token.is_empty() => Err(
            OpenIDIssuanceError::OpenID4VCI(OpenID4VCIError::InvalidRequest),
        ),

        _ => Ok(()),
    }
}

pub(crate) fn throw_if_tx_code_invalid(
    expected_code: Option<&String>,
    request: &TokenRequest,
) -> Result<(), OpenID4VCIError> {
    match (expected_code, request) {
        (
            Some(expected_code),
            TokenRequest::PreAuthorizedCode {
                pre_authorized_code: _,
                tx_code: Some(request_code),
            },
        ) => {
            if expected_code != request_code {
                tracing::info!("wrong tx_code supplied");
                return Err(OpenID4VCIError::InvalidGrant);
            }
            tracing::debug!("correct tx_code supplied");
        }
        (Some(_), _) => {
            tracing::info!("tx_code not supplied");
            return Err(OpenID4VCIError::InvalidRequest);
        }
        (
            None,
            TokenRequest::PreAuthorizedCode {
                pre_authorized_code: _,
                tx_code: Some(_),
            },
        ) => {
            tracing::info!("tx_code supplied while not expected");
            return Err(OpenID4VCIError::InvalidRequest);
        }
        (None, _) => {} // OK, correct handling without tx_code
    };

    Ok(())
}

pub(crate) fn throw_if_interaction_created_date(
    pre_authorization_expires_in: time::Duration,
    interaction: &Interaction,
) -> Result<(), OpenIDIssuanceError> {
    if interaction.created_date + pre_authorization_expires_in < crate::clock::now_utc() {
        return Err(OpenIDIssuanceError::OpenID4VCI(
            OpenID4VCIError::InvalidGrant,
        ));
    }
    Ok(())
}

pub(crate) fn throw_if_interaction_pre_authorized_code_used(
    interaction_data: &OpenID4VCIIssuerInteractionDataDTO,
) -> Result<(), OpenIDIssuanceError> {
    if interaction_data.pre_authorized_code_used {
        return Err(OpenIDIssuanceError::OpenID4VCI(
            OpenID4VCIError::InvalidGrant,
        ));
    }
    Ok(())
}

pub(crate) fn throw_if_credential_state_not_eq(
    credential: &Credential,
    state: CredentialStateEnum,
) -> Result<(), OpenIDIssuanceError> {
    let current_state = &credential.state;
    if *current_state != state {
        return Err(OpenIDIssuanceError::InvalidCredentialState {
            state: current_state.to_owned(),
        });
    }
    Ok(())
}

pub(super) fn validate_refresh_token(
    interaction_data: &OpenID4VCIIssuerInteractionDataDTO,
    refresh_token: &str,
) -> Result<(), OpenIDIssuanceError> {
    let Some(stored_refresh_token_hash) = interaction_data.refresh_token_hash.as_ref() else {
        return Err(OpenIDIssuanceError::OpenID4VCI(
            OpenID4VCIError::InvalidRequest,
        ));
    };

    let refresh_token_hash = SHA256
        .hash(refresh_token.as_bytes())
        .map_err(|e| OpenIDIssuanceError::ValidationError(e.to_string()))?;

    if stored_refresh_token_hash != &refresh_token_hash {
        return Err(OpenIDIssuanceError::OpenID4VCI(
            OpenID4VCIError::InvalidToken,
        ));
    }

    let Some(expires_at) = interaction_data.refresh_token_expires_at.as_ref() else {
        return Err(OpenIDIssuanceError::OpenID4VCI(
            OpenID4VCIError::InvalidRequest,
        ));
    };

    if &crate::clock::now_utc() > expires_at {
        return Err(OpenIDIssuanceError::OpenID4VCI(
            OpenID4VCIError::InvalidToken,
        ));
    }

    Ok(())
}

pub(super) fn validate_key_requirements_supported(
    key_algorithm_provider: &dyn KeyAlgorithmProvider,
    key_storage_provider: &dyn KeyProvider,
    key_security_provider: &dyn KeySecurityLevelProvider,
    credential_config: &CredentialConfiguration,
) -> Result<(), IssuanceProtocolError> {
    if let (Some(algs), Some(security)) =
        credential_config_to_holder_signing_algs_and_key_storage_security(
            key_algorithm_provider,
            credential_config,
        )
    {
        for security_level in security {
            if security_level_and_algs_supported(
                security_level.into(),
                &algs,
                key_storage_provider,
                key_security_provider,
            )? {
                return Ok(());
            }
        }

        return Err(IssuanceProtocolError::KeyRequirementsNotSupported);
    }

    Ok(())
}

fn security_level_and_algs_supported(
    level: KeySecurityLevelType,
    algs: &[String],
    key_storage_provider: &dyn KeyProvider,
    key_security_provider: &dyn KeySecurityLevelProvider,
) -> Result<bool, IssuanceProtocolError> {
    let security_level = key_security_provider.get_from_type(level)?;

    for storage_id in security_level.get_key_storages() {
        let storage = key_storage_provider.get_key_storage(storage_id)?;

        if !storage.enabled() {
            continue;
        }

        let capabilities = storage.get_capabilities();
        for supported_algorithm in capabilities.algorithms {
            if algs.contains(&supported_algorithm.to_string()) {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

pub(super) async fn validate_has_active_wallet_instance(
    holder_wallet_instance_repository: &dyn InstanceRepository,
    organisation_id: OrganisationId,
) -> Result<(), IssuanceProtocolError> {
    let list = holder_wallet_instance_repository
        .list(InstanceListQuery {
            filtering: Some(
                InstanceFilterValue::OrganisationIds(vec![organisation_id]).condition()
                    & InstanceFilterValue::Role(InstanceRole::Wallet)
                    & InstanceFilterValue::Status(InstanceStatus::Active),
            ),
            ..Default::default()
        })
        .await
        .error_while("getting holder wallet instance")?;

    if list.values.is_empty() {
        return Err(IssuanceProtocolError::WalletInstanceRequired);
    }

    Ok(())
}

pub(super) async fn validate_batch_consistency(
    credentials: &[CredentialWithBlob],
) -> Result<(), IssuanceProtocolError> {
    if credentials.len() < 2 {
        return Ok(());
    }
    let Some(reference) = credentials.first() else {
        return Ok(());
    };

    let reference_schema_format = single_schema_format(&reference.credential).await?;
    for credential in credentials.iter().skip(1) {
        let schema_format = single_schema_format(&credential.credential).await?;
        if schema_format.format != reference_schema_format.format
            || schema_format.ecosystem_schema_id != reference_schema_format.ecosystem_schema_id
        {
            return Err(IssuanceProtocolError::Failed(
                "Batch credentials have inconsistent schema formats".to_string(),
            ));
        }
    }

    let reference_claims = sorted_claim_entries(&reference.credential).await?;
    for credential in credentials.iter().skip(1) {
        if sorted_claim_entries(&credential.credential).await? != reference_claims {
            return Err(IssuanceProtocolError::InvalidRequest(
                "Batch credentials have inconsistent claims".to_string(),
            ));
        }
    }

    let reference_issuer = comparable_issuer(&reference.credential).await?;
    for credential in credentials.iter().skip(1) {
        let issuer = comparable_issuer(&credential.credential).await?;
        if issuer != reference_issuer {
            return Err(IssuanceProtocolError::InvalidRequest(
                "Batch credentials have inconsistent issuers".to_string(),
            ));
        }
    }
    Ok(())
}

async fn single_schema_format(
    credential: &Credential,
) -> Result<CredentialSchemaFormat, IssuanceProtocolError> {
    let schema = credential.schema.as_ref().await?;
    let schema_format = schema.formats.as_ref().await?;
    if schema_format.len() > 1 {
        return Err(IssuanceProtocolError::Failed(
            "Invalid parsed schema: multiple schema formats".to_string(),
        ));
    }
    schema_format
        .first()
        .cloned()
        .ok_or(IssuanceProtocolError::Failed(
            "Invalid parsed schema: no schema format".to_string(),
        ))
}

// fully owned, because the values originate from lazily loaded relations
#[derive(Eq, PartialEq)]
struct ClaimWithType {
    key: String,
    value: Option<String>,
    data_type: String,
}

async fn sorted_claim_entries(
    credential: &Credential,
) -> Result<Vec<ClaimWithType>, IssuanceProtocolError> {
    let claims = credential.claims.as_ref().await?;
    let mut claims_with_types = vec![];
    for claim in claims.iter() {
        let claim_schema = claim.schema.as_ref().await?;
        if claim_schema.metadata {
            // Skip metadata claims, issuer is validated separately
            continue;
        }
        claims_with_types.push(ClaimWithType {
            key: claim.path.to_owned(),
            value: claim.value.to_owned(),
            data_type: claim_schema.data_type.to_owned(),
        })
    }
    claims_with_types.sort_by(|a, b| a.key.cmp(&b.key));
    Ok(claims_with_types)
}

#[derive(Eq, PartialEq)]
enum ComparableIssuer {
    Did { did: DidValue },
    Certificate { fingerprint: String },
    Key { public_key: Vec<u8> },
}

async fn comparable_issuer(
    credential: &Credential,
) -> Result<ComparableIssuer, IssuanceProtocolError> {
    let issuer = credential
        .issuer_identifier
        .as_ref()
        .ok_or(IssuanceProtocolError::Failed(
            "missing parsed credential issuer".to_string(),
        ))?;
    match &issuer.as_ref().await?.data {
        IdentifierData::Key(key) => Ok(ComparableIssuer::Key {
            public_key: key.as_ref().await?.public_key.clone(),
        }),
        IdentifierData::Did(did) => Ok(ComparableIssuer::Did {
            did: did.as_ref().await?.did.clone(),
        }),
        IdentifierData::Certificate(_) | IdentifierData::CertificateAuthority(_) => {
            // Compare via `issuer_certificate`, which holds the exact leaf certificate that signed this credential.
            let certificate =
                credential
                    .issuer_certificate
                    .as_ref()
                    .ok_or(IssuanceProtocolError::Failed(
                        "missing parsed credential issuer certificate".to_string(),
                    ))?;
            Ok(ComparableIssuer::Certificate {
                fingerprint: certificate.as_ref().await?.fingerprint.to_owned(),
            })
        }
    }
}
