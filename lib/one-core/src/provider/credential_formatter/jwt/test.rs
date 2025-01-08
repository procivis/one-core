use async_trait::async_trait;
use one_crypto::SignerError;
use serde::{Deserialize, Serialize};
use shared_types::DidValue;
use time::macros::datetime;
use time::OffsetDateTime;

use super::model::JWTPayload;
use super::{Jwt, TokenVerifier};
use crate::provider::credential_formatter::common::MockAuth;

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
struct Payload {
    test_field: String,
}

pub fn get_dummy_date() -> OffsetDateTime {
    datetime!(2005-04-02 21:37 +1)
}

pub struct TestVerify {
    issuer_did_value: Option<String>,
    algorithm: String,
    token: String,
    signature: Vec<u8>,
}

#[async_trait]
impl TokenVerifier for TestVerify {
    async fn verify<'a>(
        &self,
        issuer_did_value: Option<DidValue>,
        _issuer_key_id: Option<&'a str>,
        algorithm: &'a str,
        token: &'a [u8],
        signature: &'a [u8],
    ) -> Result<(), SignerError> {
        assert_eq!(
            issuer_did_value.map(|v| v.to_string()),
            self.issuer_did_value
        );
        assert_eq!(algorithm, self.algorithm);
        assert_eq!(token, self.token.as_bytes());

        if signature == self.signature {
            Ok(())
        } else {
            Err(SignerError::InvalidSignature)
        }
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
        vc_type: None,
        proof_of_possession_key: None,
    };
    let jwt: Jwt<Payload> = Jwt::new(
        "Signature1".to_owned(),
        "Algorithm1".to_owned(),
        None,
        None,
        payload,
    );

    (jwt, "eyJhbGciOiJBbGdvcml0aG0xIiwidHlwIjoiU2lnbmF0dXJlMSJ9.eyJpYXQiOjExMTI0NzQyMjAsImV4cCI6MTExMjQ3NDIyMCwibmJmIjoxMTEyNDc0MjIwLCJpc3MiOiJkaWQ6aXNzdWVyOjEyMyIsInN1YiI6ImRpZDpzdWJqZWN0OjEyMyIsImp0aSI6IklEIiwidGVzdF9maWVsZCI6InRlc3QifQ.AQID".to_string())
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

    let jwt_part = extract_jwt_part(reference_token.clone());
    let jwt: Jwt<Payload> = Jwt::build_from_token(
        &reference_token,
        Some(Box::new(TestVerify {
            issuer_did_value: Some(String::from("did:issuer:123")),
            algorithm: String::from("Algorithm1"),
            token: jwt_part,
            signature: vec![1, 2, 3],
        })),
    )
    .await
    .unwrap();

    assert_eq!(jwt.header.algorithm, json.header.algorithm);
    assert_eq!(jwt.header.signature_type, json.header.signature_type);

    assert_eq!(jwt.payload.custom, json.payload.custom);
    assert_eq!(jwt.payload.issuer, json.payload.issuer);
    assert_eq!(jwt.payload.jwt_id, json.payload.jwt_id);
}
