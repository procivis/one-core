use shared_types::DidValue;

use crate::provider::did_method::DidMethodError;

pub(super) enum DidKeyType {
    Eddsa,
    Es256,
}

pub(super) fn categorize_did(did: &DidValue) -> Result<DidKeyType, DidMethodError> {
    if did.as_str().starts_with("did:key:z6Mk") {
        return Ok(DidKeyType::Eddsa);
    }
    if did.as_str().starts_with("did:key:zDn") {
        return Ok(DidKeyType::Es256);
    }

    Err(DidMethodError::ResolutionError(
        "Unsupported key algorithm".to_string(),
    ))
}
