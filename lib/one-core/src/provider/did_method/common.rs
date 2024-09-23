use serde_json::json;
use shared_types::DidValue;

use super::model::DidVerificationMethod;
use crate::model::key::PublicKeyJwk;

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
