use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use time::{macros::datetime, OffsetDateTime};

use crate::{
    crypto::signer::error::SignerError,
    provider::credential_formatter::jwt::{model::JWTPayload, Jwt},
};

use super::TokenVerifier;

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
        issuer_did_value: Option<String>,
        algorithm: &'a str,
        token: &'a str,
        signature: &'a [u8],
    ) -> Result<(), SignerError> {
        assert_eq!(issuer_did_value, self.issuer_did_value);
        assert_eq!(algorithm, self.algorithm);
        assert_eq!(token, self.token);

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
        issuer: Some("DID".to_owned()),
        subject: Some("DID".to_owned()),
        jwt_id: Some("ID".to_owned()),
        custom: custom_payload,
        nonce: None,
    };
    let jwt: Jwt<Payload> = Jwt::new(
        "Signature1".to_owned(),
        "Algorithm1".to_owned(),
        None,
        payload,
    );

    (jwt, "eyJhbGciOiJBbGdvcml0aG0xIiwidHlwIjoiU2lnbmF0dXJlMSJ9.eyJpYXQiOjExMTI0NzQyMjAsImV4cCI6MTExMjQ3NDIyMCwibmJmIjoxMTEyNDc0MjIwLCJpc3MiOiJESUQiLCJzdWIiOiJESUQiLCJqdGkiOiJJRCIsInRlc3RfZmllbGQiOiJ0ZXN0In0.AQID".to_string())
}

#[tokio::test]
async fn test_tokenize() {
    let (json, reference_token) = prepare_test_json();

    let reference_token_moved = reference_token.clone();

    let auth_fn = Box::new(move |data: &str| {
        let jwt = extract_jwt_part(reference_token_moved);
        assert_eq!(data, jwt);

        Ok(vec![1u8, 2, 3])
    });

    let token = json.tokenize(auth_fn).unwrap();

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
        TestVerify {
            issuer_did_value: Some(String::from("DID")),
            algorithm: String::from("Algorithm1"),
            token: jwt_part,
            signature: vec![1, 2, 3],
        },
    )
    .await
    .unwrap();

    assert_eq!(jwt.header.algorithm, json.header.algorithm);
    assert_eq!(jwt.header.signature_type, json.header.signature_type);

    assert_eq!(jwt.payload.custom, json.payload.custom);
    assert_eq!(jwt.payload.issuer, json.payload.issuer);
    assert_eq!(jwt.payload.jwt_id, json.payload.jwt_id);
}
