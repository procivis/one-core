use shared_types::DidValue;

use super::dto::{DidVerificationMethodDTO, PublicKeyJwkDTO};

pub fn jwk_context() -> Vec<String> {
    vec![
        "https://www.w3.org/ns/did/v1".into(),
        "https://w3id.org/security/suites/jws-2020/v1".into(),
    ]
}

pub fn jwk_verification_method(
    id: String,
    did: &DidValue,
    jwk: PublicKeyJwkDTO,
) -> DidVerificationMethodDTO {
    DidVerificationMethodDTO {
        id,
        r#type: "JsonWebKey2020".into(),
        controller: did.as_str().into(),
        public_key_jwk: jwk,
    }
}
