use one_crypto::Hasher;
use one_crypto::hasher::sha256::SHA256;
use shared_types::{DidValue, OrganisationId};

use super::mapper::credential_config_to_holder_signing_algs_and_key_storage_security;
use super::model::{
    OpenID4VCICredentialConfigurationData, OpenID4VCIIssuerInteractionDataDTO,
    OpenID4VCITokenRequestDTO,
};
use crate::config::core_config::KeySecurityLevelType;
use crate::error::ContextWithErrorCode;
use crate::model::credential::{Credential, CredentialStateEnum};
use crate::model::credential_schema_format::CredentialSchemaFormat;
use crate::model::holder_wallet_instance::{
    HolderWalletInstanceFilterValue, HolderWalletInstanceListQuery,
};
use crate::model::identifier::IdentifierType;
use crate::model::interaction::Interaction;
use crate::model::list_filter::ListFilterValue;
use crate::model::wallet_instance::WalletInstanceStatus;
use crate::provider::issuance_protocol::error::{
    IssuanceProtocolError, OpenID4VCIError, OpenIDIssuanceError,
};
use crate::provider::issuance_protocol::model::CredentialWithBlob;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_security_level::provider::KeySecurityLevelProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::repository::holder_wallet_instance_repository::HolderWalletInstanceRepository;

pub(crate) fn throw_if_token_request_invalid(
    request: &OpenID4VCITokenRequestDTO,
) -> Result<(), OpenIDIssuanceError> {
    match &request {
        OpenID4VCITokenRequestDTO::PreAuthorizedCode {
            pre_authorized_code,
            tx_code: _,
        } if pre_authorized_code.is_empty() => Err(OpenIDIssuanceError::OpenID4VCI(
            OpenID4VCIError::InvalidRequest,
        )),
        OpenID4VCITokenRequestDTO::RefreshToken { refresh_token } if refresh_token.is_empty() => {
            Err(OpenIDIssuanceError::OpenID4VCI(
                OpenID4VCIError::InvalidRequest,
            ))
        }

        _ => Ok(()),
    }
}

pub(crate) fn throw_if_tx_code_invalid(
    expected_code: Option<&String>,
    request: &OpenID4VCITokenRequestDTO,
) -> Result<(), OpenID4VCIError> {
    match (expected_code, request) {
        (
            Some(expected_code),
            OpenID4VCITokenRequestDTO::PreAuthorizedCode {
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
            OpenID4VCITokenRequestDTO::PreAuthorizedCode {
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
    credential_config: &OpenID4VCICredentialConfigurationData,
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
    holder_wallet_instance_repository: &dyn HolderWalletInstanceRepository,
    organisation_id: OrganisationId,
) -> Result<(), IssuanceProtocolError> {
    let list = holder_wallet_instance_repository
        .list(HolderWalletInstanceListQuery {
            filtering: Some(
                HolderWalletInstanceFilterValue::OrganisationIds(vec![organisation_id]).condition()
                    & HolderWalletInstanceFilterValue::Status(WalletInstanceStatus::Active),
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
            || schema_format.schema_id != reference_schema_format.schema_id
        {
            return Err(IssuanceProtocolError::Failed(
                "Batch credentials have inconsistent schema formats".to_string(),
            ));
        }
    }

    let reference_claims = sorted_claim_entries(&reference.credential)?;
    for credential in credentials.iter().skip(1) {
        if sorted_claim_entries(&credential.credential)? != reference_claims {
            return Err(IssuanceProtocolError::InvalidRequest(
                "Batch credentials have inconsistent claims".to_string(),
            ));
        }
    }

    let reference_issuer = comparable_issuer(&reference.credential)?;
    for credential in credentials.iter().skip(1) {
        let issuer = comparable_issuer(&credential.credential)?;
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
    let schema = credential
        .schema
        .as_ref()
        .ok_or(IssuanceProtocolError::Failed(
            "missing parsed credential schema".to_string(),
        ))?;
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

#[derive(Eq, PartialEq)]
struct ClaimWithType<'a> {
    key: &'a String,
    value: &'a Option<String>,
    data_type: &'a String,
}

fn sorted_claim_entries(
    credential: &Credential,
) -> Result<Vec<ClaimWithType<'_>>, IssuanceProtocolError> {
    let claims = credential
        .claims
        .as_ref()
        .ok_or(IssuanceProtocolError::Failed(
            "Invalid parsed schema: missing claims".to_string(),
        ))?;
    let mut claims_with_types = vec![];
    for claim in claims {
        let claim_schema = claim.schema.as_ref().ok_or(IssuanceProtocolError::Failed(
            "Invalid parsed schema: missing claim schema".to_string(),
        ))?;
        if claim_schema.metadata {
            // Skip metadata claims, issuer is validated separately
            continue;
        }
        claims_with_types.push(ClaimWithType {
            key: &claim.path,
            value: &claim.value,
            data_type: &claim_schema.data_type,
        })
    }
    claims_with_types.sort_by(|a, b| a.key.cmp(b.key));
    Ok(claims_with_types)
}

#[derive(Eq, PartialEq)]
enum ComparableIssuer<'a> {
    Did { did: &'a DidValue },
    Certificate { fingerprint: &'a String },
    Key { public_key: &'a [u8] },
}

fn comparable_issuer(
    credential: &Credential,
) -> Result<ComparableIssuer<'_>, IssuanceProtocolError> {
    let issuer = credential
        .issuer_identifier
        .as_ref()
        .ok_or(IssuanceProtocolError::Failed(
            "missing parsed credential issuer".to_string(),
        ))?;
    match issuer.r#type {
        IdentifierType::Key => {
            let key = issuer.key.as_ref().ok_or(IssuanceProtocolError::Failed(
                "missing parsed credential issuer key".to_string(),
            ))?;
            Ok(ComparableIssuer::Key {
                public_key: &key.public_key,
            })
        }
        IdentifierType::Did => {
            let did = issuer.did.as_ref().ok_or(IssuanceProtocolError::Failed(
                "missing parsed credential issuer did".to_string(),
            ))?;
            Ok(ComparableIssuer::Did { did: &did.did })
        }
        IdentifierType::Certificate | IdentifierType::CertificateAuthority => {
            // Compare via `issuer_certificate`, which holds the exact leaf certificate that signed this credential.
            let certificate =
                credential
                    .issuer_certificate
                    .as_ref()
                    .ok_or(IssuanceProtocolError::Failed(
                        "missing parsed credential issuer certificate".to_string(),
                    ))?;
            Ok(ComparableIssuer::Certificate {
                fingerprint: &certificate.fingerprint,
            })
        }
    }
}
