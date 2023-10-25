use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use time::{macros::datetime, OffsetDateTime};

use crate::{
    crypto::signer::SignerError,
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

pub struct DummyTestVerify;

#[async_trait]
impl TokenVerifier for DummyTestVerify {
    async fn verify<'a>(
        &self,
        _issuer_did_value: &'a str,
        _algorithm: &'a str,
        _token: &'a str,
        signature: &'a [u8],
    ) -> Result<(), SignerError> {
        if signature == vec![1, 2, 3] {
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

    let auth_fn = Box::new(|_: &_| Ok(vec![1u8, 2, 3]));

    let token = json.tokenize(auth_fn).unwrap();

    assert_eq!(token, reference_token);
}

#[tokio::test]
async fn test_build_from_token() {
    let (json, reference_token) = prepare_test_json();

    let jwt: Jwt<Payload> = Jwt::build_from_token(&reference_token, DummyTestVerify {})
        .await
        .unwrap();

    assert_eq!(jwt.header.algorithm, json.header.algorithm);
    assert_eq!(jwt.header.signature_type, json.header.signature_type);

    assert_eq!(jwt.payload.custom, json.payload.custom);
    assert_eq!(jwt.payload.issuer, json.payload.issuer);
    assert_eq!(jwt.payload.jwt_id, json.payload.jwt_id);
}
