use std::collections::HashSet;

use serde_json::json;
use shared_types::DidValue;

use super::DidKeys;
use super::error::DidMethodError;
use super::model::DidVerificationMethod;
use crate::model::key::{Key, PublicKeyJwk};

pub const ENC: &str = "enc";
pub const SIG: &str = "sig";

pub fn jwk_context() -> serde_json::Value {
    json!([
        "https://www.w3.org/ns/did/v1",
        "https://w3id.org/security/suites/jws-2020/v1",
    ])
}

pub fn jwk_verification_method(
    id: String,
    did: &DidValue,
    jwk: PublicKeyJwk,
) -> DidVerificationMethod {
    DidVerificationMethod {
        id,
        r#type: "JsonWebKey2020".into(),
        controller: did.to_string(),
        public_key_jwk: jwk,
    }
}

pub fn expect_one_key(keys: &DidKeys) -> Result<&Key, DidMethodError> {
    let DidKeys {
        authentication,
        assertion_method,
        key_agreement,
        capability_invocation,
        capability_delegation,
        update_keys: _,
    } = keys;

    let mut seen = HashSet::new();
    let mut unique_keys = [
        authentication,
        assertion_method,
        key_agreement,
        capability_invocation,
        capability_delegation,
    ]
    .into_iter()
    .flatten()
    // dedup keys
    .filter(|key| seen.insert(key.id));

    let Some(key) = unique_keys.next() else {
        return Err(DidMethodError::CouldNotCreate(
            "No keys provided for any role".to_string(),
        ));
    };

    let remaining_keys_count = unique_keys.count();
    if remaining_keys_count > 0 {
        return Err(DidMethodError::CouldNotCreate(format!(
            "Too many keys provided, expected exactly one, got {remaining_keys_count}"
        )));
    }

    Ok(key)
}
