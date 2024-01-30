use shared_types::DidValue;

use crate::provider::did_method::{
    common::{jwk_context, jwk_verification_method},
    dto::{DidDocumentDTO, PublicKeyJwkDTO},
    DidMethodError,
};

pub(super) enum DidKeyType {
    Eddsa,
    Ecdsa,
}

pub(super) struct DecodedDidKey {
    pub(super) multibase: String,
    pub(super) decoded_multibase: Vec<u8>,
    pub(super) type_: DidKeyType,
}

pub(super) fn decode_did(did: &DidValue) -> Result<DecodedDidKey, DidMethodError> {
    let tail = did
        .as_str()
        .strip_prefix("did:key:")
        .ok_or_else(|| DidMethodError::ResolutionError("Invalid did key prefix".into()))?;

    let type_ = if tail.starts_with("z6Mk") {
        DidKeyType::Eddsa
    } else if tail.starts_with("zDn") {
        DidKeyType::Ecdsa
    } else {
        return Err(DidMethodError::ResolutionError(
            "Unsupported key algorithm".to_string(),
        ));
    };

    let decoded = bs58::decode(&tail[1..]).into_vec().map_err(|err| {
        DidMethodError::ResolutionError(format!("Invalid did key multibase suffix: {err}"))
    })?;

    let decoded_without_multibase_prefix = decoded[2..].into();

    Ok(DecodedDidKey {
        multibase: tail.into(),
        decoded_multibase: decoded_without_multibase_prefix,
        type_,
    })
}

pub(super) fn generate_document(
    decoded: DecodedDidKey,
    did: &DidValue,
    public_key_jwk: PublicKeyJwkDTO,
) -> Result<DidDocumentDTO, DidMethodError> {
    let verification_method = jwk_verification_method(
        format!("{}#{}", did.as_str(), decoded.multibase),
        did,
        public_key_jwk,
    );

    Ok(DidDocumentDTO {
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
