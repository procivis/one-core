use std::sync::Arc;

use async_trait::async_trait;
use one_crypto::SignerError;
use serde::{Deserialize, Serialize};
use similar_asserts::assert_eq;
use time::OffsetDateTime;
use time::macros::datetime;

use super::model::JWTPayload;
use super::{Jwt, TokenVerifier};
use crate::config::core_config::KeyAlgorithmType;
use crate::provider::credential_formatter::common::MockAuth;
use crate::provider::credential_formatter::model::PublicKeySource;
use crate::provider::key_algorithm::MockKeyAlgorithm;
use crate::provider::key_algorithm::provider::{KeyAlgorithmProvider, MockKeyAlgorithmProvider};

#[derive(Serialize, Deserialize, Debug, Default, Eq, PartialEq)]
struct Payload {
    test_field: String,
}

pub fn get_dummy_date() -> OffsetDateTime {
    datetime!(2005-04-02 21:37 +1)
}

pub struct TestVerify {
    issuer_did_value: Option<String>,
    algorithm: KeyAlgorithmType,
    token: String,
    signature: Vec<u8>,
    key_algorithm_provider: MockKeyAlgorithmProvider,
}

#[async_trait]
impl TokenVerifier for TestVerify {
    async fn verify<'a>(
        &self,
        public_key_source: PublicKeySource<'a>,
        algorithm: KeyAlgorithmType,
        token: &'a [u8],
        signature: &'a [u8],
    ) -> Result<(), SignerError> {
        match public_key_source {
            PublicKeySource::Did { did, .. } => {
                assert_eq!(
                    did.to_string(),
                    self.issuer_did_value.as_ref().unwrap().to_string()
                )
            }
            _ => return Err(SignerError::InvalidSignature),
        }
        assert_eq!(algorithm, self.algorithm);
        assert_eq!(token, self.token.as_bytes());

        if signature == self.signature {
            Ok(())
        } else {
            Err(SignerError::InvalidSignature)
        }
    }

    fn key_algorithm_provider(&self) -> &dyn KeyAlgorithmProvider {
        &self.key_algorithm_provider
    }
}

fn prepare_test_json() -> (Jwt<Payload>, String) {
    let now = get_dummy_date();

    let custom_payload = Payload {
        test_field: "test".to_owned(),
    };

    let payload = JWTPayload {
        issued_at: Some(now),
        expires_at: Some(now),
        invalid_before: Some(now),
        issuer: Some("did:issuer:123".to_owned()),
        subject: Some("did:subject:123".to_owned()),
        jwt_id: Some("ID".to_owned()),
        custom: custom_payload,
        ..Default::default()
    };
    let jwt: Jwt<Payload> = Jwt::new(
        "Type1".to_owned(),
        "Algorithm1".to_owned(),
        None,
        None,
        payload,
    );

    (jwt, "eyJhbGciOiJBbGdvcml0aG0xIiwidHlwIjoiVHlwZTEifQ.eyJpYXQiOjExMTI0NzQyMjAsImV4cCI6MTExMjQ3NDIyMCwibmJmIjoxMTEyNDc0MjIwLCJpc3MiOiJkaWQ6aXNzdWVyOjEyMyIsInN1YiI6ImRpZDpzdWJqZWN0OjEyMyIsImp0aSI6IklEIiwidGVzdF9maWVsZCI6InRlc3QifQ.AQID".to_string())
}

#[tokio::test]
async fn test_tokenize() {
    let (json, reference_token) = prepare_test_json();

    let reference_token_moved = reference_token.clone();

    let auth_fn = MockAuth(move |data: &[u8]| {
        let jwt = extract_jwt_part(reference_token_moved.clone());
        assert_eq!(data, jwt.as_bytes());

        vec![1u8, 2, 3]
    });

    let token = json.tokenize(Some(Box::new(auth_fn))).await.unwrap();

    assert_eq!(token, reference_token);
}

fn extract_jwt_part(token: String) -> String {
    let token_parts: Vec<&str> = token.split('.').collect();
    if let Some(result) = token_parts.get(..token_parts.len() - 1) {
        result.join(".")
    } else {
        panic!("Incorrect input data");
    }
}

#[tokio::test]
async fn test_build_from_token() {
    let (json, reference_token) = prepare_test_json();

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_key_algorithm_from_jose_alg()
        .once()
        .returning(move |_| {
            let mut key_algorithm = MockKeyAlgorithm::default();
            key_algorithm
                .expect_algorithm_type()
                .return_once(|| KeyAlgorithmType::Eddsa);

            Some((KeyAlgorithmType::Eddsa, Arc::new(key_algorithm)))
        });

    let jwt_part = extract_jwt_part(reference_token.clone());
    let jwt: Jwt<Payload> = Jwt::build_from_token(
        &reference_token,
        Some(
            &(Box::new(TestVerify {
                issuer_did_value: Some(String::from("did:issuer:123")),
                algorithm: KeyAlgorithmType::Eddsa,
                token: jwt_part,
                signature: vec![1, 2, 3],
                key_algorithm_provider,
            }) as Box<dyn TokenVerifier>),
        ),
        None,
    )
    .await
    .unwrap();

    assert_eq!(jwt.header.algorithm, json.header.algorithm);
    assert_eq!(jwt.header.r#type, json.header.r#type);

    assert_eq!(jwt.payload.custom, json.payload.custom);
    assert_eq!(jwt.payload.issuer, json.payload.issuer);
    assert_eq!(jwt.payload.jwt_id, json.payload.jwt_id);
}
