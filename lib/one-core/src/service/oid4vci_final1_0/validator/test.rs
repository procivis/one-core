use std::sync::Arc;

use serde_json::{Value, json};
use similar_asserts::assert_eq;
use uuid::Uuid;

use super::*;
use crate::config::core_config::KeyAlgorithmType;
use crate::provider::key_algorithm::KeyAlgorithm;
use crate::provider::key_algorithm::ecdsa::Ecdsa;
use crate::provider::key_algorithm::key::KeyHandle;
use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;

fn dpop_proof(
    key: &KeyHandle,
    method: &str,
    url: &str,
    access_token: Option<&str>,
) -> (Value, Value) {
    let header = json!({
        "typ": "dpop+jwt",
        "alg": "ES256",
        "jwk": key.public_key_as_jwk().unwrap(),
    });
    let mut payload = json!({
        "htm": method,
        "htu": url,
        "iat": crate::clock::now_utc().unix_timestamp(),
        "jti": Uuid::new_v4().to_string(),
    });
    if let Some(access_token) = access_token {
        payload["ath"] = SHA256
            .hash_base64_url(access_token.as_bytes())
            .unwrap()
            .into();
    }
    (header, payload)
}

async fn sign(key: &KeyHandle, (header, payload): (Value, Value)) -> String {
    let jwt = [header.to_string(), payload.to_string()]
        .map(|part| Base64UrlSafeNoPadding::encode_to_string(part).unwrap())
        .join(".");
    let signature = key.sign(jwt.as_bytes()).await.unwrap();
    format!(
        "{jwt}.{}",
        Base64UrlSafeNoPadding::encode_to_string(signature).unwrap()
    )
}

fn validate(
    proof: &str,
    method: &str,
    url: &str,
    access_token: Option<&str>,
) -> Result<String, OID4VCIFinal1_0ServiceError> {
    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_key_algorithm_from_jose_alg()
        .returning(|_| Some((KeyAlgorithmType::Ecdsa, Arc::new(Ecdsa))));
    validate_dpop_proof(
        proof,
        method,
        &url.parse().unwrap(),
        access_token,
        &key_algorithm_provider,
    )
}

fn assert_invalid_dpop_proof(result: Result<String, OID4VCIFinal1_0ServiceError>) {
    assert!(matches!(
        result,
        Err(OID4VCIFinal1_0ServiceError::DpopProof(_))
    ));
}

#[tokio::test]
async fn test_validate_dpop_proof_returns_key_thumbprint() {
    let key = Ecdsa.generate_key().unwrap().key;
    let url = "https://issuer.example.com/credential";
    let proof = sign(&key, dpop_proof(&key, "POST", url, Some("access-token"))).await;

    let thumbprint = validate(&proof, "POST", url, Some("access-token")).unwrap();

    let expected = key.public_key_as_jwk().unwrap().thumbprint().unwrap();
    assert_eq!(
        Base64UrlSafeNoPadding::encode_to_string(expected).unwrap(),
        thumbprint
    );
}

#[tokio::test]
async fn test_validate_dpop_proof_rejects_other_request() {
    let key = Ecdsa.generate_key().unwrap().key;
    let url = "https://issuer.example.com/credential";
    let proof = sign(&key, dpop_proof(&key, "POST", url, Some("access-token"))).await;

    for (method, url, access_token) in [
        ("GET", url, Some("access-token")),
        ("post", url, Some("access-token")),
        (
            "POST",
            "https://issuer.example.com/notification",
            Some("access-token"),
        ),
        ("POST", url, Some("other-token")),
    ] {
        assert_invalid_dpop_proof(validate(&proof, method, url, access_token));
    }
}

#[tokio::test]
async fn test_validate_dpop_proof_rejects_invalid_header_or_claims() {
    let key = Ecdsa.generate_key().unwrap().key;
    let url = "https://issuer.example.com/token";
    let now = crate::clock::now_utc().unix_timestamp();

    let cases = [
        (true, "typ", json!("jwt")),
        (true, "alg", json!("EdDSA")),
        (true, "jwk", Value::Null),
        (false, "iat", json!(now - 600)),
        (false, "iat", json!(now + 120)),
        (false, "jti", Value::Null),
    ];
    for (in_header, field, value) in cases {
        let (mut header, mut payload) = dpop_proof(&key, "POST", url, None);
        let part = if in_header { &mut header } else { &mut payload };
        part[field] = value;
        let proof = sign(&key, (header, payload)).await;

        assert_invalid_dpop_proof(validate(&proof, "POST", url, None));
    }
}

#[tokio::test]
async fn test_validate_dpop_proof_rejects_invalid_signature() {
    let key = Ecdsa.generate_key().unwrap().key;
    let url = "https://issuer.example.com/token";
    let proof = sign(&key, dpop_proof(&key, "POST", url, None)).await;
    let (unverified, signature) = proof.rsplit_once('.').unwrap();
    let other_signature = if signature.starts_with('A') { "B" } else { "A" };
    let tampered = format!("{unverified}.{other_signature}{}", &signature[1..]);

    assert_invalid_dpop_proof(validate(&tampered, "POST", url, None));
}
