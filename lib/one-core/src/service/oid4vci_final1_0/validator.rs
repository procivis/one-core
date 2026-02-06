use one_crypto::Hasher;
use one_crypto::hasher::sha256::SHA256;
use standardized_types::jwk::PublicJwk;
use time::OffsetDateTime;

use crate::config::ConfigValidationError;
use crate::config::core_config::{CoreConfig, IssuanceProtocolType};
use crate::model::credential_schema::CredentialSchema;
use crate::proto::jwt::Jwt;
use crate::proto::jwt::model::DecomposedJwt;
use crate::provider::credential_formatter::model::{PublicKeySource, TokenVerifier};
use crate::provider::issuance_protocol::error::OpenID4VCIError;
use crate::provider::issuance_protocol::model::KeyStorageSecurityLevel;
use crate::provider::issuance_protocol::openid4vci_final1_0::model::{
    OpenID4VCICredentialRequestDTO, OpenID4VCICredentialRequestIdentifier, OpenID4VCIFinal1Params,
    OpenID4VCIIssuerInteractionDataDTO,
};
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::service::error::ServiceError;
use crate::service::wallet_provider::dto::{
    WalletInstanceAttestationClaims, WalletUnitAttestationClaims,
};
use crate::validator::{
    validate_expiration_time, validate_issuance_time, validate_not_before_time,
};

pub(crate) fn throw_if_credential_request_invalid(
    schema: &CredentialSchema,
    request: &OpenID4VCICredentialRequestDTO,
) -> Result<(), ServiceError> {
    if let OpenID4VCICredentialRequestIdentifier::CredentialConfigurationId(
        credential_configuration_id,
    ) = &request.credential
    {
        if &schema.schema_id != credential_configuration_id {
            return Err(ServiceError::OpenID4VCIError(
                OpenID4VCIError::UnsupportedCredentialType,
            ));
        }
    } else {
        return Err(ServiceError::OpenID4VCIError(
            OpenID4VCIError::InvalidRequest,
        ));
    }

    Ok(())
}

fn is_access_token_valid(
    interaction_data: &OpenID4VCIIssuerInteractionDataDTO,
    access_token: &str,
) -> bool {
    interaction_data.pre_authorized_code_used
        && SHA256
            .hash(access_token.as_bytes())
            .is_ok_and(|hash| hash == interaction_data.access_token_hash)
        && interaction_data
            .access_token_expires_at
            .is_some_and(|expires_at| expires_at > OffsetDateTime::now_utc())
}

pub(crate) fn throw_if_access_token_invalid(
    interaction_data: &OpenID4VCIIssuerInteractionDataDTO,
    access_token: &str,
) -> Result<(), ServiceError> {
    if !is_access_token_valid(interaction_data, access_token) {
        return Err(ServiceError::OpenID4VCIError(OpenID4VCIError::InvalidToken));
    }
    Ok(())
}

pub(crate) fn validate_timestamps(
    token: &DecomposedJwt<impl std::fmt::Debug>,
    leeway: u64,
) -> Result<(), ServiceError> {
    validate_issuance_time(&token.payload.issued_at, leeway)?;
    validate_not_before_time(&token.payload.invalid_before, leeway)?;
    validate_expiration_time(&token.payload.expires_at, leeway)?;
    Ok(())
}

pub(crate) fn validate_pop_audience(
    pop_token: &DecomposedJwt<()>,
    expected_audience: &str,
) -> Result<(), ServiceError> {
    let empty_vec = vec![];
    if !pop_token
        .payload
        .audience
        .as_ref()
        .unwrap_or(&empty_vec)
        .contains(&expected_audience.to_string())
    {
        return Err(ServiceError::OpenID4VCIError(
            OpenID4VCIError::InvalidRequest,
        ));
    }
    Ok(())
}

pub(crate) fn verify_pop_signature(
    pop_token: &DecomposedJwt<()>,
    wallet_unit_attestation: &DecomposedJwt<WalletInstanceAttestationClaims>,
    key_algorithm_provider: &dyn KeyAlgorithmProvider,
) -> Result<(), ServiceError> {
    let (_, alg) = key_algorithm_provider
        .key_algorithm_from_jose_alg(&pop_token.header.algorithm)
        .ok_or(ServiceError::OpenID4VCIError(
            OpenID4VCIError::InvalidRequest,
        ))?;

    let jwk = wallet_unit_attestation
        .payload
        .proof_of_possession_key
        .as_ref()
        .ok_or(ServiceError::OpenID4VCIError(
            OpenID4VCIError::InvalidRequest,
        ))?
        .jwk
        .jwk()
        .to_owned();

    let pop_signer_key_handle = alg
        .parse_jwk(&jwk)
        .map_err(|_| ServiceError::OpenID4VCIError(OpenID4VCIError::InvalidRequest))?;

    pop_signer_key_handle
        .signature()
        .ok_or(ServiceError::OpenID4VCIError(
            OpenID4VCIError::InvalidRequest,
        ))?
        .public()
        .verify(pop_token.unverified_jwt.as_bytes(), &pop_token.signature)
        .map_err(|_| ServiceError::OpenID4VCIError(OpenID4VCIError::InvalidRequest))?;

    Ok(())
}

#[tracing::instrument(level = "debug", skip_all, err(level = "info"))]
pub(crate) async fn verify_wia_signature(
    wallet_instance_attestation: &DecomposedJwt<WalletInstanceAttestationClaims>,
    verifier: &dyn TokenVerifier,
) -> Result<(), ServiceError> {
    let public_key_source = match (
        wallet_instance_attestation.header.jwk.as_ref(),
        wallet_instance_attestation.header.x5c.as_ref(),
    ) {
        (Some(jwk), None) => jwk.into(),
        (None, Some(x5c)) => PublicKeySource::X5c { x5c },
        _ => {
            tracing::info!("WIA issuer not specified");
            return Err(ServiceError::OpenID4VCIError(
                OpenID4VCIError::InvalidRequest,
            ));
        }
    };

    wallet_instance_attestation
        .verify_signature(public_key_source, verifier)
        .await
        .map_err(|_| ServiceError::OpenID4VCIError(OpenID4VCIError::InvalidRequest))?;

    Ok(())
}

pub(crate) fn extract_wallet_metadata(
    wallet_instance_attestation: &DecomposedJwt<WalletInstanceAttestationClaims>,
) -> Result<(String, String), ServiceError> {
    let name = wallet_instance_attestation
        .payload
        .custom
        .wallet_name
        .as_ref()
        .ok_or(ServiceError::OpenID4VCIError(
            OpenID4VCIError::InvalidRequest,
        ))?
        .clone();

    let link = wallet_instance_attestation
        .payload
        .custom
        .wallet_link
        .as_ref()
        .ok_or(ServiceError::OpenID4VCIError(
            OpenID4VCIError::InvalidRequest,
        ))?
        .clone();

    Ok((name, link))
}

pub(crate) async fn validate_key_attestation(
    key_attestation_jwt: &str,
    verifier: &dyn TokenVerifier,
    expected_key_storage_security_level: KeyStorageSecurityLevel,
    leeway: u64,
) -> Result<Vec<PublicJwk>, ServiceError> {
    let wua = Jwt::<WalletUnitAttestationClaims>::decompose_token(key_attestation_jwt)?;

    validate_timestamps(&wua, leeway)?;

    if !wua
        .payload
        .custom
        .key_storage
        .contains(&expected_key_storage_security_level)
    {
        tracing::debug!(
            "key attestation does not list expected key storage security level: {:?}",
            expected_key_storage_security_level
        );
        return Err(ServiceError::OpenID4VCIError(
            OpenID4VCIError::InvalidRequest,
        ));
    }

    let wua_issuer_key = match (&wua.header.jwk, &wua.header.x5c) {
        (Some(jwk), None) => jwk.into(),
        (None, Some(x5c)) => PublicKeySource::X5c { x5c },
        _ => {
            tracing::info!("WUA issuer not specified");
            return Err(ServiceError::OpenID4VCIError(
                OpenID4VCIError::InvalidRequest,
            ));
        }
    };

    wua.verify_signature(wua_issuer_key, verifier).await?;

    Ok(wua.payload.custom.attested_keys)
}

#[tracing::instrument(level = "debug", err(level = "debug"))]
pub(crate) fn verify_wua_wia_issuers_match(
    wua_jwt: &str,
    wia: &DecomposedJwt<WalletInstanceAttestationClaims>,
) -> Result<(), ServiceError> {
    let wua = Jwt::<WalletUnitAttestationClaims>::decompose_token(wua_jwt)?;

    let wia_issuer = (wia.header.jwk.as_ref(), wia.header.x5c.as_ref());
    let wua_issuer = (wua.header.jwk.as_ref(), wua.header.x5c.as_ref());

    if wia_issuer != wua_issuer {
        tracing::info!("WUA issuer does not match WIA issuer");
        return Err(ServiceError::OpenID4VCIError(
            OpenID4VCIError::InvalidRequest,
        ));
    }

    Ok(())
}

pub(super) fn get_config_entity(
    config: &CoreConfig,
) -> Result<OpenID4VCIFinal1Params, ConfigValidationError> {
    if let Some((key, fields)) = config
        .issuance_protocol
        .iter()
        .find(|(_, v)| v.r#type == IssuanceProtocolType::OpenId4VciFinal1_0)
    {
        let params = fields
            .deserialize::<OpenID4VCIFinal1Params>()
            .map_err(|source| ConfigValidationError::FieldsDeserialization {
                key: key.to_owned(),
                source,
            })?;
        Ok(params)
    } else {
        Err(ConfigValidationError::EntryNotFound(
            "No exchange method with type OPENID4VCI_FINAL1".to_string(),
        ))
    }
}
