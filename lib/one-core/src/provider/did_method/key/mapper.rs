use std::str::FromStr;

use did_key::Document;
use shared_types::DidValue;

use crate::provider::did_method::{
    dto::{DidDocumentDTO, DidVerificationMethodDTO, PublicKeyJwkDTO},
    DidMethodError,
};

pub(super) fn categorize_did(did_value: &DidValue) -> Result<String, DidMethodError> {
    if did_value.as_str().starts_with("did:key:z6Mk") {
        return Ok("EDDSA".to_owned());
    }
    if did_value.as_str().starts_with("did:key:zDn") {
        return Ok("ES256".to_owned());
    }

    Err(DidMethodError::ResolutionError(
        "Unsupported key algorithm".to_string(),
    ))
}

pub(super) fn convert_document(
    doc: Document,
    public_key_jwk: PublicKeyJwkDTO,
) -> Result<DidDocumentDTO, DidMethodError> {
    let method = doc
        .verification_method
        .first() // Get and convert first only
        .map(move |method| DidVerificationMethodDTO {
            id: method.id.clone(),
            r#type: method.key_type.clone(),
            controller: method.controller.clone(),
            public_key_jwk,
        })
        .ok_or(DidMethodError::ResolutionError(
            "Missing verification method".to_string(),
        ))?;

    let id = DidValue::from_str(&doc.id).map_err(|_| DidMethodError::NotSupported)?;

    Ok(DidDocumentDTO {
        context: vec![doc.context],
        id,
        verification_method: vec![method],
        authentication: doc.authentication,
        assertion_method: doc.assertion_method,
        key_agreement: doc.key_agreement,
        capability_invocation: doc.capability_invocation,
        capability_delegation: doc.capability_delegation,
    })
}
