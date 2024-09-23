use shared_types::DidValue;

use crate::model::key::PublicKeyJwk;
use crate::provider::did_method::common::{jwk_context, jwk_verification_method};
use crate::provider::did_method::error::DidMethodError;
use crate::provider::did_method::model::DidDocument;

#[derive(Debug, Eq, PartialEq)]
pub enum DidKeyType {
    Eddsa,
    Ecdsa,
    Bbs,
}

pub struct DecodedDidKey {
    pub multibase: String,
    pub decoded_multibase: Vec<u8>,
    pub type_: DidKeyType,
}

pub fn decode_did(did: &DidValue) -> Result<DecodedDidKey, DidMethodError> {
    let tail = did
        .as_str()
        .strip_prefix("did:key:")
        .ok_or_else(|| DidMethodError::ResolutionError("Invalid did key prefix".into()))?;

    if !tail.starts_with("z") {
        return Err(DidMethodError::ResolutionError(
            "Invalid multicodec identifier, expected z".to_string(),
        ));
    };

    let type_ = if tail.starts_with("z6Mk") {
        DidKeyType::Eddsa
    } else if tail.starts_with("zDn") {
        DidKeyType::Ecdsa
    } else if tail.starts_with("zUC7") {
        DidKeyType::Bbs
    } else {
        return Err(DidMethodError::ResolutionError(
            "Unsupported key algorithm".to_string(),
        ));
    };

    let decoded = bs58::decode(&tail[1..]).into_vec().map_err(|err| {
        DidMethodError::ResolutionError(format!("Invalid did key multibase suffix: {err}"))
    })?;

    // currently all supported key algorithms have a multicodec prefix 2 bytes long
    let decoded_without_multibase_prefix = decoded[2..].into();

    Ok(DecodedDidKey {
        multibase: tail.into(),
        decoded_multibase: decoded_without_multibase_prefix,
        type_,
    })
}

pub fn generate_document(
    decoded: DecodedDidKey,
    did: &DidValue,
    public_key_jwk: PublicKeyJwk,
) -> Result<DidDocument, DidMethodError> {
    let verification_method = jwk_verification_method(
        format!("{}#{}", did, decoded.multibase),
        did,
        public_key_jwk,
    );

    Ok(DidDocument {
        context: jwk_context(),
        id: did.clone(),
        authentication: Some(vec![verification_method.id.clone()]),
        assertion_method: Some(vec![verification_method.id.clone()]),
        capability_invocation: Some(vec![verification_method.id.clone()]),
        capability_delegation: Some(vec![verification_method.id.clone()]),
        key_agreement: Some(vec![verification_method.id.clone()]),
        verification_method: vec![verification_method],
        rest: Default::default(),
    })
}
