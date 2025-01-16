use serde::Deserialize;
use shared_types::DidValue;
use url::Url;

use crate::provider::did_method::common::{jwk_context, jwk_verification_method, ENC, SIG};
use crate::provider::did_method::model::{DidDocument, DidVerificationMethod};
use crate::service::key::dto::PublicKeyJwkDTO;

#[derive(Clone, Debug, Deserialize)]
pub(super) struct SdJwtVcIssuerMetadataDTO {
    pub issuer: String,
    #[serde(default)]
    pub jwks: Option<SdJwtVcIssuerMetadataJwkDTO>,
    #[serde(default)]
    pub jwks_uri: Option<Url>,
}

#[derive(Clone, Debug, Deserialize)]
pub(super) struct SdJwtVcIssuerMetadataJwkDTO {
    pub keys: Vec<SdJwtVcIssuerMetadataJwkKeyDTO>,
}

#[derive(Clone, Debug, Deserialize)]
pub(super) struct SdJwtVcIssuerMetadataJwkKeyDTO {
    // TODO: this could be used for matching SD-JWT header with key
    // #[serde(rename = "kid")]
    // pub key_id: String,
    #[serde(flatten)]
    pub jwk: PublicKeyJwkDTO,
}

pub fn generate_document(did: &DidValue, jwks: Vec<PublicKeyJwkDTO>) -> DidDocument {
    let verification_methods_with_use: Vec<(DidVerificationMethod, &Option<String>)> = jwks
        .iter()
        .enumerate()
        .map(|(idx, jwk)| {
            let key_id = format!(
                "{}#{}",
                did,
                jwk.get_kid().clone().unwrap_or(idx.to_string())
            );
            (
                jwk_verification_method(key_id, did, jwk.clone().into()),
                jwk.get_use(),
            )
        })
        .collect();

    let mut template = DidDocument {
        context: jwk_context(),
        id: did.clone(),
        verification_method: vec![],
        authentication: None,
        assertion_method: None,
        key_agreement: None,
        capability_invocation: None,
        capability_delegation: None,
        rest: Default::default(),
    };

    let mut signature_keys = vec![];
    let mut encryption_keys = vec![];

    for (method, use_) in verification_methods_with_use {
        template.verification_method.push(method.clone());

        match use_ {
            Some(val) if val == SIG => {
                signature_keys.push(method.id);
            }
            Some(val) if val == ENC => {
                encryption_keys.push(method.id);
            }
            _ => {
                signature_keys.push(method.id.clone());
                encryption_keys.push(method.id);
            }
        }
    }

    if !signature_keys.is_empty() {
        let keys = Some(signature_keys);
        template.authentication = keys.clone();
        template.assertion_method = keys.clone();
        template.capability_invocation = keys.clone();
        template.capability_delegation = keys;
    }

    if !encryption_keys.is_empty() {
        template.key_agreement = Some(encryption_keys);
    }

    template
}
