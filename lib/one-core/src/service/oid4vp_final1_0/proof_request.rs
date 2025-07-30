use std::collections::HashMap;

use dcql::DcqlQuery;
use one_crypto::jwe::RemoteJwk;
use url::Url;

use crate::common_mapper::PublicKeyWithJwk;
use crate::model::did::{KeyFilter, KeyRole};
use crate::model::identifier::IdentifierType;
use crate::model::interaction::InteractionId;
use crate::model::key::{PublicKeyJwk, PublicKeyJwkEllipticData};
use crate::model::proof::Proof;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::error::KeyStorageError;
use crate::provider::key_storage::model::KeySecurity;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::verification_protocol::error::VerificationProtocolError;
use crate::provider::verification_protocol::openid4vp::final1_0::mappers::create_open_id_for_vp_client_metadata_final1_0;
use crate::provider::verification_protocol::openid4vp::final1_0::model::{
    AuthorizationRequest, OpenID4VPFinal1_0ClientMetadata,
};
use crate::provider::verification_protocol::openid4vp::model::{
    OpenID4VPMdocAlgs, OpenID4VPVcSdJwtAlgs, OpenID4VPW3CJwtAlgs, OpenID4VPW3CLdpAlgs,
    OpenID4VpPresentationFormat,
};
use crate::service::error::{ServiceError, ValidationError};

pub(crate) fn generate_authorization_request_params_final1_0(
    nonce: String,
    dcql_query: DcqlQuery,
    client_id: String,
    response_uri: String,
    interaction_id: &InteractionId,
    client_metadata: OpenID4VPFinal1_0ClientMetadata,
) -> Result<AuthorizationRequest, VerificationProtocolError> {
    Ok(AuthorizationRequest {
        response_type: Some("vp_token".to_string()),
        response_mode: Some(determine_response_mode_final1_0(&client_metadata)),
        client_id,
        client_metadata: Some(client_metadata.into()),
        response_uri: Some(
            Url::parse(&response_uri)
                .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?,
        ),
        nonce: Some(nonce),
        state: Some(interaction_id.to_string()),
        dcql_query: Some(dcql_query),
        redirect_uri: None,
    })
}

fn determine_response_mode_final1_0(metadata: &OpenID4VPFinal1_0ClientMetadata) -> String {
    if metadata.encrypted_response_enc_values_supported.is_some() {
        "direct_post.jwt".to_string()
    } else {
        "direct_post".to_string()
    }
}

pub(crate) fn generate_client_metadata_final1_0(
    proof: &Proof,
    key_algorithm_provider: &dyn KeyAlgorithmProvider,
    key_provider: &dyn KeyProvider,
) -> Result<OpenID4VPFinal1_0ClientMetadata, VerificationProtocolError> {
    let vp_formats_supported = generate_vp_formats_supported();
    let jwk = select_key_agreement_key_from_proof(proof, key_algorithm_provider, key_provider)
        .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

    Ok(create_open_id_for_vp_client_metadata_final1_0(
        jwk,
        vp_formats_supported,
    ))
}

pub(crate) fn generate_vp_formats_supported() -> HashMap<String, OpenID4VpPresentationFormat> {
    let mut formats = HashMap::new();

    let jose_algs = vec!["EdDSA".to_owned(), "ES256".to_owned()];
    let cose_algs = vec![-7, -8, -9, -19];

    // only including the entries specified in the final standard for now
    formats.insert(
        "jwt_vc_json".to_owned(),
        OpenID4VpPresentationFormat::W3CJwtAlgs(OpenID4VPW3CJwtAlgs {
            alg_values: jose_algs.to_owned(),
        }),
    );
    formats.insert(
        "ldp_vc".to_owned(),
        OpenID4VpPresentationFormat::W3CLdpAlgs(OpenID4VPW3CLdpAlgs {
            proof_type_values: vec!["DataIntegrityProof".to_string()],
            cryptosuite_values: vec![
                "bbs-2023".to_string(),
                "ecdsa-rdfc-2019".to_string(),
                "eddsa-rdfc-2022".to_string(),
            ],
        }),
    );
    formats.insert(
        "mso_mdoc".to_owned(),
        OpenID4VpPresentationFormat::MdocAlgs(OpenID4VPMdocAlgs {
            issuerauth_alg_values: cose_algs.to_owned(),
            deviceauth_alg_values: cose_algs,
        }),
    );
    formats.insert(
        "dc+sd-jwt".to_owned(),
        OpenID4VpPresentationFormat::SdJwtVcAlgs(OpenID4VPVcSdJwtAlgs {
            sd_jwt_alg_values: jose_algs.to_owned(),
            kb_jwt_alg_values: jose_algs,
        }),
    );

    formats
}

fn select_key_agreement_key_from_proof(
    proof: &Proof,
    key_algorithm_provider: &dyn KeyAlgorithmProvider,
    key_provider: &dyn KeyProvider,
) -> Result<Option<PublicKeyWithJwk>, VerificationProtocolError> {
    let Some(verifier_identifier) = proof.verifier_identifier.as_ref() else {
        return Err(VerificationProtocolError::Failed(
            "verifier_identifier is None".to_string(),
        ));
    };

    let Some(verifier_key) = proof.verifier_key.as_ref() else {
        return Err(VerificationProtocolError::Failed(
            "verifier_key is None".to_string(),
        ));
    };

    let candidate_encryption_key = match verifier_identifier.r#type {
        IdentifierType::Certificate | IdentifierType::Key => Some(verifier_key),
        IdentifierType::Did => {
            let Some(verifier_did) = verifier_identifier.did.as_ref() else {
                return Err(VerificationProtocolError::Failed(
                    "verifier_did is None".to_string(),
                ));
            };

            let key_agreement_key_filter = KeyFilter::role_filter(KeyRole::KeyAgreement);
            // We ensure the specified key is a key agreement key
            let encryption_key = verifier_did.find_key(&verifier_key.id, &key_agreement_key_filter);
            match encryption_key {
                Ok(Some(key)) => Some(&key.key),
                // If the key is not a key agreement key or not found, we try to find a matching key
                Err(ServiceError::Validation(ValidationError::InvalidKey(_))) | Ok(None) => {
                    verifier_did
                        .find_first_matching_key(&key_agreement_key_filter)
                        .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?
                        .map(|key| &key.key)
                }
                Err(error) => {
                    return Err(VerificationProtocolError::Failed(error.to_string()));
                }
            }
        }
    };

    // If no key is found, we return None, the verifier will only support the direct_post response_mode
    let Some(candidate_encryption_key) = candidate_encryption_key else {
        return Ok(None);
    };

    let key_algorithm = candidate_encryption_key
        .key_algorithm_type()
        .and_then(|key_type| key_algorithm_provider.key_algorithm_from_type(key_type))
        .ok_or(VerificationProtocolError::Failed(format!(
            "key algorithm not found for key type: {}",
            candidate_encryption_key.key_type
        )))?;
    let key_storage = key_provider
        .get_key_storage(&candidate_encryption_key.storage_type)
        .ok_or(KeyStorageError::NotSupported(
            candidate_encryption_key.storage_type.to_owned(),
        ))
        .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

    /*
     * TODO(ONE-5428): Azure vault doesn't work directly with encrypted JWE params
     * This needs more investigation and a refactor to support creating shared secret
     * through key storage
     */
    let r#use = if key_storage
        .get_capabilities()
        .security
        .contains(&KeySecurity::RemoteSecureElement)
    {
        None
    } else {
        Some("enc".to_string())
    };

    let key_agreement_key = key_algorithm
        .reconstruct_key(&candidate_encryption_key.public_key, None, r#use)
        .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?
        .key_agreement()
        .map(|k| k.public().as_jwk())
        .transpose()
        .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

    if let Some(key_agreement_key) = key_agreement_key {
        let public_key_jwk = remote_jwk_to_public_key_jwk(key_agreement_key)
            .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

        Ok(Some(PublicKeyWithJwk {
            key_id: candidate_encryption_key.id,
            jwk: public_key_jwk,
        }))
    } else {
        Ok(None)
    }
}

/// Converts a RemoteJwk (used for encryption) to PublicKeyJwk (used for general key operations)
fn remote_jwk_to_public_key_jwk(remote_jwk: RemoteJwk) -> Result<PublicKeyJwk, ServiceError> {
    match remote_jwk.kty.as_str() {
        "EC" => Ok(PublicKeyJwk::Ec(PublicKeyJwkEllipticData {
            alg: Some("ECDH-ES".to_string()),
            r#use: Some("enc".to_string()),
            kid: None,
            crv: remote_jwk.crv,
            x: remote_jwk.x,
            y: remote_jwk.y,
        })),
        "OKP" => Ok(PublicKeyJwk::Okp(PublicKeyJwkEllipticData {
            alg: Some("ECDH-ES".to_string()),
            r#use: Some("enc".to_string()),
            kid: None,
            crv: remote_jwk.crv,
            x: remote_jwk.x,
            y: remote_jwk.y,
        })),
        _ => Err(ServiceError::MappingError(format!(
            "Unsupported key type '{}' in RemoteJwk conversion",
            remote_jwk.kty
        ))),
    }
}
