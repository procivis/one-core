use std::ops::Add;

use one_core::proto::jwt::mapper::{bin_to_b64url_string, string_to_b64url_string};
use one_core::proto::jwt::model::JWTPayload;
use one_core::proto::jwt::{Jwt, JwtPublicKeyInfo};
use one_core::provider::key_algorithm::model::GeneratedKey;
use serde::Serialize;
use time::{Duration, OffsetDateTime};

pub(crate) async fn signed_jwt<T: Serialize>(
    key: &GeneratedKey,
    alg: &str,
    aud: Option<String>,
    iss: Option<String>,
    sub: Option<String>,
    custom: T,
    jwt_id: Option<String>,
) -> String {
    let now = OffsetDateTime::now_utc();
    let jwt = Jwt::new(
        "JWT".to_string(),
        alg.to_string(),
        None,
        iss.is_none().then_some(JwtPublicKeyInfo::Jwk(
            key.key.public_key_as_jwk().unwrap().into(),
        )),
        JWTPayload {
            issued_at: Some(now),
            expires_at: Some(now.add(Duration::hours(10))),
            invalid_before: Some(now),
            audience: aud.map(|aud| vec![aud]),
            jwt_id,
            issuer: iss,
            subject: sub,
            custom,
            proof_of_possession_key: None,
        },
    );

    let jwt_header_json = serde_json::to_string(&jwt.header).unwrap();
    let payload_json = serde_json::to_string(&jwt.payload).unwrap();
    let mut token = format!(
        "{}.{}",
        string_to_b64url_string(&jwt_header_json).unwrap(),
        string_to_b64url_string(&payload_json).unwrap(),
    );

    let signature = key.key.sign(token.as_bytes()).await.unwrap();
    let signature_encoded = bin_to_b64url_string(&signature).unwrap();

    token.push('.');
    token.push_str(&signature_encoded);
    token
}
