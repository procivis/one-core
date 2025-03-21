use anyhow::Context;
use ct_codecs::{Base64UrlSafeNoPadding, Decoder, Encoder};
use shared_types::DidValue;

use crate::provider::did_method::common::{jwk_context, jwk_verification_method, ENC, SIG};
use crate::provider::did_method::error::DidMethodError;
use crate::provider::did_method::model::DidDocument;
use crate::service::key::dto::PublicKeyJwkDTO;

pub fn extract_jwk(did: &DidValue) -> Result<PublicKeyJwkDTO, DidMethodError> {
    let tail = did
        .as_str()
        .strip_prefix("did:jwk:")
        .ok_or_else(|| DidMethodError::ResolutionError("Invalid jwk did prefix".into()))?;

    let bytes = Base64UrlSafeNoPadding::decode_to_vec(tail, None).map_err(|err| {
        DidMethodError::ResolutionError(format!("Failed to decode base64url from jwk did: {err}"))
    })?;

    serde_json::from_slice(&bytes)
        .map_err(|err| DidMethodError::ResolutionError(format!("Failed to deserialize jwk: {err}")))
}

pub fn generate_document(did: &DidValue, jwk: PublicKeyJwkDTO) -> DidDocument {
    let did_url = format!("{}#0", did);
    let urls = Some(vec![did_url.clone()]);
    let verification_method = jwk_verification_method(did_url, did, jwk.clone().into());

    let mut template = DidDocument {
        context: jwk_context(),
        id: did.clone(),
        verification_method: vec![verification_method],
        authentication: None,
        assertion_method: None,
        key_agreement: None,
        capability_invocation: None,
        capability_delegation: None,
        also_known_as: None,
        service: None,
    };

    match jwk.get_use() {
        Some(val) if val == SIG => {
            template.authentication.clone_from(&urls);
            template.assertion_method.clone_from(&urls);
            template.capability_invocation.clone_from(&urls);
            template.capability_delegation = urls;
        }
        Some(val) if val == ENC => {
            template.key_agreement = urls;
        }
        _ => {
            template.authentication.clone_from(&urls);
            template.assertion_method.clone_from(&urls);
            template.key_agreement.clone_from(&urls);
            template.capability_invocation.clone_from(&urls);
            template.capability_delegation = urls;
        }
    }

    template
}

pub fn encode_to_did(jwk: &PublicKeyJwkDTO) -> Result<DidValue, DidMethodError> {
    let jwk = serde_json::to_string(jwk)
        .map_err(|err| DidMethodError::CouldNotCreate(format!("Failed to serialize jwk: {err}")))?;

    let encoded = Base64UrlSafeNoPadding::encode_to_string(jwk).map_err(|err| {
        DidMethodError::CouldNotCreate(format!("Failed to base64 encode jwk: {err}"))
    })?;

    format!("did:jwk:{encoded}")
        .parse()
        .context("did parsing error")
        .map_err(|e| DidMethodError::CouldNotCreate(e.to_string()))
}
