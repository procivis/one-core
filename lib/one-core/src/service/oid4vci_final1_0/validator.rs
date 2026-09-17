use one_crypto::Hasher;
use one_crypto::hasher::sha256::SHA256;
use standardized_types::jwe::CompressionAlgorithm;
use standardized_types::oauth2::attestation_based_client_auth::OAuthClientAttestationPopCustomClaims;
use standardized_types::openid4vci::{
    CredentialRequest, CredentialRequestIdentifier, KeyStorageSecurityLevel, ResponseEncryption,
};
use time::Duration;

use super::error::{OID4VCIFinal1_0ServiceError, WalletAttestationError};
use crate::error::ContextWithErrorCode;
use crate::model::credential_schema::CredentialSchema;
use crate::model::credential_schema_format::CredentialSchemaFormat;
use crate::proto::jwt::Jwt;
use crate::proto::jwt::model::DecomposedJwt;
use crate::provider::credential_formatter::model::TokenVerifier;
use crate::provider::issuance_protocol::IssuanceProtocol;
use crate::provider::issuance_protocol::error::OpenID4VCIError;
use crate::provider::issuance_protocol::openid4vci_final1_0::model::{
    OpenID4VCIFinal1Params, OpenID4VCIIssuerInteractionDataDTO,
};
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::service::managed_instance::dto::{
    WalletInstanceAttestationClaims, WalletUnitAttestationClaims,
};
use crate::validator::{
    validate_expiration_time, validate_issuance_time, validate_not_before_time,
};

pub(crate) async fn validate_credential_request_format(
    schema: &CredentialSchema,
    request: &CredentialRequest,
) -> Result<CredentialSchemaFormat, OID4VCIFinal1_0ServiceError> {
    let CredentialRequestIdentifier::CredentialConfigurationId(credential_configuration_id) =
        &request.credential
    else {
        return Err(OpenID4VCIError::InvalidRequest.into());
    };

    let formats = schema.formats.as_ref().await?;
    let format = formats
        .into_iter()
        .find(|format| &format.ecosystem_schema_id == credential_configuration_id);

    Ok(format
        .cloned()
        .ok_or(OpenID4VCIError::UnsupportedCredentialType)?)
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
            .is_some_and(|expires_at| expires_at > crate::clock::now_utc())
}

pub(crate) fn throw_if_access_token_invalid(
    interaction_data: &OpenID4VCIIssuerInteractionDataDTO,
    access_token: &str,
) -> Result<(), OID4VCIFinal1_0ServiceError> {
    if !is_access_token_valid(interaction_data, access_token) {
        return Err(OpenID4VCIError::InvalidToken.into());
    }
    Ok(())
}

pub(crate) fn validate_timestamps(
    token: &DecomposedJwt<impl std::fmt::Debug>,
    leeway: Duration,
) -> Result<(), OID4VCIFinal1_0ServiceError> {
    validate_issuance_time(&token.payload.issued_at, leeway).error_while("checking validity")?;
    validate_not_before_time(&token.payload.invalid_before, leeway)
        .error_while("checking validity")?;
    validate_expiration_time(&token.payload.expires_at, leeway).error_while("checking validity")?;
    Ok(())
}

pub(crate) fn validate_pop_audience(
    pop_token: &DecomposedJwt<OAuthClientAttestationPopCustomClaims>,
    expected_audience: &str,
) -> Result<(), OID4VCIFinal1_0ServiceError> {
    let empty_vec = vec![];
    if !pop_token
        .payload
        .audience
        .as_ref()
        .unwrap_or(&empty_vec)
        .contains(&expected_audience.to_string())
    {
        return Err(OpenID4VCIError::InvalidRequest.into());
    }
    Ok(())
}

pub(crate) fn verify_pop_signature(
    pop_token: &DecomposedJwt<OAuthClientAttestationPopCustomClaims>,
    wallet_unit_attestation: &DecomposedJwt<WalletInstanceAttestationClaims>,
    key_algorithm_provider: &dyn KeyAlgorithmProvider,
) -> Result<(), OID4VCIFinal1_0ServiceError> {
    let (_, alg) = key_algorithm_provider
        .key_algorithm_from_jose_alg(&pop_token.header.algorithm)
        .ok_or(OpenID4VCIError::InvalidRequest)?;

    let jwk = wallet_unit_attestation
        .payload
        .proof_of_possession_key
        .as_ref()
        .ok_or(OpenID4VCIError::InvalidRequest)?
        .jwk
        .jwk()
        .to_owned();

    let pop_signer_key_handle = alg
        .parse_jwk(&jwk)
        .map_err(|_| OpenID4VCIError::InvalidRequest)?;

    pop_signer_key_handle
        .signature()
        .ok_or(OpenID4VCIError::InvalidRequest)?
        .public()
        .verify(pop_token.unverified_jwt.as_bytes(), &pop_token.signature)
        .map_err(|_| OpenID4VCIError::InvalidRequest)?;

    Ok(())
}

#[tracing::instrument(level = "debug", skip_all, err(level = "info"))]
pub(crate) async fn verify_wia_signature(
    wallet_instance_attestation: &DecomposedJwt<WalletInstanceAttestationClaims>,
    verifier: &dyn TokenVerifier,
) -> Result<(), OID4VCIFinal1_0ServiceError> {
    let public_key_source = wallet_instance_attestation
        .wallet_provider_key()
        .map_err(|e| WalletAttestationError::WiaMalformed(format!("extracting public key: {e}")))?;

    wallet_instance_attestation
        .verify_signature(public_key_source, verifier)
        .await
        .map_err(|e| {
            WalletAttestationError::WiaMalformed(format!("signature verification failed: {e}"))
        })?;

    Ok(())
}

pub(crate) fn extract_wallet_metadata(
    wallet_instance_attestation: &DecomposedJwt<WalletInstanceAttestationClaims>,
) -> Result<(String, String), OID4VCIFinal1_0ServiceError> {
    let name = wallet_instance_attestation
        .payload
        .custom
        .wallet_name
        .as_ref()
        .ok_or_else(|| {
            WalletAttestationError::WiaMalformed("missing wallet_name claim".to_string())
        })?
        .clone();

    let link = wallet_instance_attestation
        .payload
        .custom
        .wallet_link
        .as_ref()
        .ok_or_else(|| {
            WalletAttestationError::WiaMalformed("missing wallet_link claim".to_string())
        })?
        .clone();

    Ok((name, link))
}

pub(crate) async fn validate_key_attestation(
    key_attestation_jwt: &str,
    verifier: &dyn TokenVerifier,
    expected_key_storage_security_level: KeyStorageSecurityLevel,
    leeway: Duration,
) -> Result<DecomposedJwt<WalletUnitAttestationClaims>, OID4VCIFinal1_0ServiceError> {
    let ka = Jwt::<WalletUnitAttestationClaims>::decompose_token(key_attestation_jwt)
        .map_err(|e| WalletAttestationError::KaMalformed(format!("parsing: {e}")))?;

    validate_timestamps(&ka, leeway)?;

    if !ka
        .payload
        .custom
        .key_storage
        .contains(&expected_key_storage_security_level)
    {
        tracing::debug!(
            "key attestation does not list expected key storage security level: {:?}",
            expected_key_storage_security_level
        );
        return Err(WalletAttestationError::KeyStorageSecurityLevelMismatch(
            expected_key_storage_security_level,
        )
        .into());
    }

    let ka_issuer_key = ka
        .wallet_provider_key()
        .map_err(|e| WalletAttestationError::KaMalformed(format!("extracting public key: {e}")))?;
    ka.verify_signature(ka_issuer_key, verifier)
        .await
        .map_err(|e| WalletAttestationError::KaMalformed(format!("signature: {e}")))?;

    Ok(ka)
}

#[tracing::instrument(level = "debug", skip_all, err(level = "debug"))]
pub(crate) fn verify_ka_wia_issuers_match(
    ka: &DecomposedJwt<WalletUnitAttestationClaims>,
    wia: &DecomposedJwt<WalletInstanceAttestationClaims>,
) -> Result<(), OID4VCIFinal1_0ServiceError> {
    let wia_issuer = wia
        .wallet_provider_key()
        .map_err(|e| WalletAttestationError::WiaMalformed(format!("extracting public key: {e}")))?;
    let ka_issuer = ka
        .wallet_provider_key()
        .map_err(|e| WalletAttestationError::KaMalformed(format!("extracting public key: {e}")))?;

    if wia_issuer != ka_issuer {
        tracing::info!("KA issuer does not match WIA issuer");
        return Err(WalletAttestationError::WiaKaIssuerMismatch.into());
    }

    Ok(())
}

pub(crate) fn validate_response_encryption(
    response_encryption: Option<&ResponseEncryption>,
    params: &OpenID4VCIFinal1Params,
    protocol: &dyn IssuanceProtocol,
    key_algorithm_provider: &dyn KeyAlgorithmProvider,
) -> Result<(), OID4VCIFinal1_0ServiceError> {
    let Some(ResponseEncryption { jwk, enc, zip }) = response_encryption else {
        if params.credential_endpoint_encryption.response_required {
            tracing::info!(
                "Rejecting credential request without credential_response_encryption: encryption required"
            );
            return Err(OpenID4VCIError::InvalidEncryptionParameters.into());
        }
        return Ok(());
    };

    if !protocol
        .get_capabilities()
        .supported_encryption_algorithms
        .contains(enc)
    {
        tracing::info!("Unsupported credential response encryption enc value: {enc}");
        return Err(OpenID4VCIError::InvalidEncryptionParameters.into());
    }
    if let Some(zip) = zip
        && *zip != CompressionAlgorithm::DEF
    {
        tracing::info!("Unsupported credential response encryption zip value: {zip}");
        return Err(OpenID4VCIError::InvalidEncryptionParameters.into());
    }

    // the key has to be usable for key agreement here, as failing to encrypt the response after
    // the credential was issued would burn it
    let key_agreement_possible = key_algorithm_provider
        .parse_jwk(jwk)
        .is_ok_and(|parsed| parsed.key.key_agreement().is_some());
    if !key_agreement_possible {
        tracing::info!("Credential response encryption JWK cannot be used for key agreement");
        return Err(OpenID4VCIError::InvalidEncryptionParameters.into());
    }

    Ok(())
}
