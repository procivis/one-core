use std::sync::Arc;

use serde_json::{Value, json};
use similar_asserts::assert_eq;
use uuid::Uuid;

use super::*;
use crate::config::core_config::KeyAlgorithmType;
use crate::provider::key_algorithm::KeyAlgorithm;
use crate::provider::key_algorithm::ecdsa::Ecdsa;
use crate::provider::key_algorithm::eddsa::Eddsa;
use crate::provider::key_algorithm::key::KeyHandle;
use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;
use crate::repository::interaction_repository::MockInteractionRepository;

fn dpop_proof(
    key: &KeyHandle,
    method: &str,
    url: &str,
    access_token: Option<&str>,
    nonce: Option<DpopNonce>,
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
    if let Some(nonce) = nonce {
        payload["nonce"] = json!(nonce.to_string());
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

fn dpop_params() -> DpopParams {
    DpopParams {
        nonce_validity: Duration::seconds(30),
        nonce_refresh_threshold: Default::default(),
        leeway: Default::default(),
        signing_key: hex::decode(
            "c213ff6fb1a57a0c7353443527a7cd5775c3c58b8f32476dee8200fb5767904d",
        )
        .unwrap()
        .into(),
        proof_signing_algorithms: vec![KeyAlgorithmType::Ecdsa],
        base_url: Some("https://issuer.example.com".to_string()),
    }
}

fn setup() -> DpopHandlerImpl {
    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_key_algorithm_from_jose_alg()
        .returning(|typ| match typ {
            "EdDSA" => Some((KeyAlgorithmType::Eddsa, Arc::new(Eddsa))),
            "ES256" => Some((KeyAlgorithmType::Ecdsa, Arc::new(Ecdsa))),
            _ => None,
        });
    let mut interaction_repository = MockInteractionRepository::new();
    interaction_repository
        .expect_mark_nonces_as_used()
        .returning(|_, _| Ok(()));
    DpopHandlerImpl::new(
        Arc::new(key_algorithm_provider),
        Arc::new(interaction_repository),
    )
}

#[tokio::test]
async fn test_validate_dpop_proof_returns_key_thumbprint() {
    let handler = setup();
    let nonce = handler.generate_nonce(dpop_params()).await.unwrap();
    let key = Ecdsa.generate_key().unwrap().key;
    let url = "https://issuer.example.com/credential";
    let proof = sign(
        &key,
        dpop_proof(&key, "POST", url, Some("access-token"), Some(nonce)),
    )
    .await;

    let result = handler
        .validate_proof(
            Uuid::new_v4().into(),
            proof.as_str(),
            Some("access-token"),
            ExpectedProofValues {
                method: "POST",
                url: Url::parse(url).unwrap(),
                jkt: None,
            },
            dpop_params(),
        )
        .await
        .unwrap();

    let expected = key.public_key_as_jwk().unwrap().thumbprint().unwrap();
    assert_eq!(
        Base64UrlSafeNoPadding::encode_to_string(expected).unwrap(),
        result.jkt
    );
}

#[tokio::test]
async fn test_validate_dpop_proof_rejects_invalid_proof_payloads() {
    let handler = setup();
    let nonce = handler.generate_nonce(dpop_params()).await.unwrap();
    let key = Ecdsa.generate_key().unwrap().key;
    let url = "https://issuer.example.com/credential";
    let proof = sign(
        &key,
        dpop_proof(&key, "POST", url, Some("access-token"), Some(nonce)),
    )
    .await;

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
        let result = handler
            .validate_proof(
                Uuid::new_v4().into(),
                proof.as_str(),
                access_token,
                ExpectedProofValues {
                    method,
                    url: Url::parse(url).unwrap(),
                    jkt: None,
                },
                dpop_params(),
            )
            .await;
        assert!(result.is_err());
    }
}

#[tokio::test]
async fn test_validate_dpop_proof_rejects_invalid_header_or_claims() {
    let handler = setup();
    let nonce = handler.generate_nonce(dpop_params()).await.unwrap();
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
        (false, "nonce", Value::Null),
    ];
    for (in_header, field, value) in cases {
        let (mut header, mut payload) = dpop_proof(&key, "POST", url, None, Some(nonce.clone()));
        let part = if in_header { &mut header } else { &mut payload };
        part[field] = value;
        let proof = sign(&key, (header, payload)).await;

        let result = handler
            .validate_proof(
                Uuid::new_v4().into(),
                proof.as_str(),
                None,
                ExpectedProofValues {
                    method: "POST",
                    url: Url::parse(url).unwrap(),
                    jkt: None,
                },
                dpop_params(),
            )
            .await;
        assert!(result.is_err());
    }
}

#[tokio::test]
async fn test_validate_dpop_proof_rejects_invalid_signature() {
    let handler = setup();
    let nonce = handler.generate_nonce(dpop_params()).await.unwrap();
    let key = Ecdsa.generate_key().unwrap().key;
    let url = "https://issuer.example.com/token";
    let proof = sign(&key, dpop_proof(&key, "POST", url, None, Some(nonce))).await;
    let (unverified, signature) = proof.rsplit_once('.').unwrap();
    let other_signature = if signature.starts_with('A') { "B" } else { "A" };
    let tampered = format!("{unverified}.{other_signature}{}", &signature[1..]);

    let result = handler
        .validate_proof(
            Uuid::new_v4().into(),
            tampered.as_str(),
            None,
            ExpectedProofValues {
                method: "POST",
                url: Url::parse(url).unwrap(),
                jkt: None,
            },
            dpop_params(),
        )
        .await;
    assert!(result.is_err());
}
