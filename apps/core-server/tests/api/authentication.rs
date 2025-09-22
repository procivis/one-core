use std::time::Duration;

use axum::http::Method;
use one_core::model::key::PublicKeyJwk;
use one_core::provider::key_algorithm::KeyAlgorithm;
use one_core::provider::key_algorithm::eddsa::Eddsa;
use one_core::provider::key_algorithm::model::GeneratedKey;
use one_core::util::jwt::mapper::bin_to_b64url_string;
use one_core::util::jwt::model::JWTPayload;
use one_core::util::jwt::{Jwt, JwtPublicKeyInfo};
use one_crypto::Signer;
use one_crypto::signer::eddsa::EDDSASigner;
use serde_json::json;
use time::OffsetDateTime;
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::utils::api_clients::http_client;
use crate::utils::context::TestContext;

#[tokio::test]
async fn test_insecure_none_authentication_success() {
    // given
    let config = indoc::indoc! {"
      app:
        auth:
            mode: INSECURE_NONE
    "}
    .to_string();
    let context = TestContext::new(Some(config)).await;

    // when
    let resp = http_client()
        .get(format!(
            "{}/api/config/v1",
            context.config.app.core_base_url
        ))
        .send()
        .await
        .unwrap();

    // then
    similar_asserts::assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn test_static_token_authentication_success() {
    // given
    let config = indoc::indoc! {"
      app:
        auth:
            mode: STATIC
            staticToken: 'test123'
    "}
    .to_string();
    let context = TestContext::new(Some(config)).await;

    // when
    let resp = http_client()
        .get(format!(
            "{}/api/config/v1",
            context.config.app.core_base_url
        ))
        .bearer_auth("test123")
        .send()
        .await
        .unwrap();

    // then
    similar_asserts::assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn test_static_token_authentication_fails_invalid_token() {
    // given
    let config = indoc::indoc! {"
      app:
        auth:
            mode: STATIC
            staticToken: 'test123'
    "}
    .to_string();
    let context = TestContext::new(Some(config)).await;

    // when
    let resp = http_client()
        .get(format!(
            "{}/api/config/v1",
            context.config.app.core_base_url
        ))
        .bearer_auth("123test")
        .send()
        .await
        .unwrap();

    // then
    similar_asserts::assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_sts_authentication_success() {
    // given
    let mock_server = MockServer::builder().start().await;
    let config = indoc::formatdoc! {"
      app:
        auth:
            mode: STS
            stsTokenValidation:
                aud: 'core'
                iss: 'bff'
                ttlJwks: 600
                jwksUri: {url}
    ",
    url = format!("{}/jwks.json", mock_server.uri())};
    let key = Eddsa.generate_key().unwrap();

    let jwk = to_jwk_with_kid(&key, Default::default());
    let jwks = json!({
        "keys": [
            jwk
        ]
    });
    Mock::given(method(Method::GET))
        .and(path("/jwks.json"))
        .respond_with(ResponseTemplate::new(500))
        .up_to_n_times(1)
        .expect(1)
        .mount(&mock_server)
        .await;
    Mock::given(method(Method::GET))
        .and(path("/jwks.json"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(serde_json::to_string(&jwks).unwrap()),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    let context = TestContext::new(Some(config)).await;
    let now = OffsetDateTime::now_utc();
    let token = Jwt::new(
        "STS".to_string(),
        "EdDSA".to_string(),
        jwk.kid().map(ToString::to_string),
        Some(JwtPublicKeyInfo::Jwk(jwk.into())),
        JWTPayload {
            issued_at: Some(now),
            expires_at: Some(now + Duration::from_secs(3600)),
            invalid_before: None,
            issuer: Some("bff".to_string()),
            subject: Some(Uuid::new_v4().to_string()),
            audience: Some(vec!["core".to_string()]),
            jwt_id: None,
            proof_of_possession_key: None,
            custom: (),
        },
    );

    let mut tokenized = token.tokenize(None).await.unwrap();
    let signature = EDDSASigner {}
        .sign(tokenized.as_bytes(), &key.public, &key.private)
        .unwrap();
    tokenized.push('.');
    tokenized.push_str(&bin_to_b64url_string(&signature).unwrap());

    // when
    let resp = http_client()
        .get(format!(
            "{}/api/config/v1",
            context.config.app.core_base_url
        ))
        .bearer_auth(tokenized)
        .send()
        .await
        .unwrap();

    // then
    similar_asserts::assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn test_sts_authentication_fails_invalid_aud() {
    let key = Eddsa.generate_key().unwrap();
    let jwk = to_jwk_with_kid(&key, Default::default());

    let now = OffsetDateTime::now_utc();
    let token = Jwt::new(
        "STS".to_string(),
        "EdDSA".to_string(),
        jwk.kid().map(ToString::to_string),
        Some(JwtPublicKeyInfo::Jwk(jwk.clone().into())),
        JWTPayload {
            issued_at: Some(now),
            expires_at: Some(now + Duration::from_secs(3600)),
            invalid_before: None,
            issuer: Some("bff".to_string()),
            subject: Some(Uuid::new_v4().to_string()),
            audience: Some(vec!["invalid".to_string()]),
            jwt_id: None,
            proof_of_possession_key: None,
            custom: (),
        },
    );
    test_sts_authentication_invalid_token(key, jwk, token).await;
}

#[tokio::test]
async fn test_sts_authentication_fails_invalid_iss() {
    let key = Eddsa.generate_key().unwrap();
    let jwk = to_jwk_with_kid(&key, Default::default());

    let now = OffsetDateTime::now_utc();
    let token = Jwt::new(
        "STS".to_string(),
        "EdDSA".to_string(),
        jwk.kid().map(ToString::to_string),
        Some(JwtPublicKeyInfo::Jwk(jwk.clone().into())),
        JWTPayload {
            issued_at: Some(now),
            expires_at: Some(now + Duration::from_secs(3600)),
            invalid_before: None,
            issuer: Some("invalid".to_string()),
            subject: Some(Uuid::new_v4().to_string()),
            audience: Some(vec!["core".to_string()]),
            jwt_id: None,
            proof_of_possession_key: None,
            custom: (),
        },
    );

    test_sts_authentication_invalid_token(key, jwk, token).await;
}

#[tokio::test]
async fn test_sts_authentication_fails_expired_token() {
    let key = Eddsa.generate_key().unwrap();
    let jwk = to_jwk_with_kid(&key, Default::default());

    let now = OffsetDateTime::now_utc();
    let token = Jwt::new(
        "STS".to_string(),
        "EdDSA".to_string(),
        jwk.kid().map(ToString::to_string),
        Some(JwtPublicKeyInfo::Jwk(jwk.clone().into())),
        JWTPayload {
            issued_at: Some(now),
            expires_at: Some(now - Duration::from_secs(5)),
            invalid_before: None,
            issuer: Some("bff".to_string()),
            subject: Some(Uuid::new_v4().to_string()),
            audience: Some(vec!["core".to_string()]),
            jwt_id: None,
            proof_of_possession_key: None,
            custom: (),
        },
    );
    test_sts_authentication_invalid_token(key, jwk, token).await;
}

#[tokio::test]
async fn test_sts_authentication_fails_invalid_nbf() {
    let key = Eddsa.generate_key().unwrap();
    let jwk = to_jwk_with_kid(&key, Default::default());

    let now = OffsetDateTime::now_utc();
    let token = Jwt::new(
        "STS".to_string(),
        "EdDSA".to_string(),
        jwk.kid().map(ToString::to_string),
        Some(JwtPublicKeyInfo::Jwk(jwk.clone().into())),
        JWTPayload {
            issued_at: Some(now),
            expires_at: Some(now + Duration::from_secs(3600)),
            invalid_before: Some(now + Duration::from_secs(5)),
            issuer: Some("bff".to_string()),
            subject: Some(Uuid::new_v4().to_string()),
            audience: Some(vec!["core".to_string()]),
            jwt_id: None,
            proof_of_possession_key: None,
            custom: (),
        },
    );
    test_sts_authentication_invalid_token(key, jwk, token).await;
}

#[tokio::test]
async fn test_sts_authentication_fails_invalid_signature() {
    let kid = Uuid::new_v4();
    let key_signer = Eddsa.generate_key().unwrap();

    let jwk = to_jwk_with_kid(&key_signer, kid);
    let now = OffsetDateTime::now_utc();
    let token = Jwt::new(
        "STS".to_string(),
        "EdDSA".to_string(),
        jwk.kid().map(ToString::to_string),
        Some(JwtPublicKeyInfo::Jwk(jwk.clone().into())),
        JWTPayload {
            issued_at: Some(now),
            expires_at: Some(now + Duration::from_secs(3600)),
            invalid_before: Some(now + Duration::from_secs(5)),
            issuer: Some("bff".to_string()),
            subject: Some(Uuid::new_v4().to_string()),
            audience: Some(vec!["core".to_string()]),
            jwt_id: None,
            proof_of_possession_key: None,
            custom: (),
        },
    );

    let key_verifier = Eddsa.generate_key().unwrap();
    let jwk = to_jwk_with_kid(&key_verifier, kid);
    test_sts_authentication_invalid_token(key_signer, jwk, token).await;
}

#[tokio::test]
async fn test_sts_authentication_fails_signed_with_different_kid() {
    let key = Eddsa.generate_key().unwrap();

    let jwk = to_jwk_with_kid(&key, Default::default());
    let now = OffsetDateTime::now_utc();
    let token = Jwt::new(
        "STS".to_string(),
        "EdDSA".to_string(),
        jwk.kid().map(ToString::to_string),
        Some(JwtPublicKeyInfo::Jwk(jwk.clone().into())),
        JWTPayload {
            issued_at: Some(now),
            expires_at: Some(now + Duration::from_secs(3600)),
            invalid_before: Some(now + Duration::from_secs(5)),
            issuer: Some("bff".to_string()),
            subject: Some(Uuid::new_v4().to_string()),
            audience: Some(vec!["core".to_string()]),
            jwt_id: None,
            proof_of_possession_key: None,
            custom: (),
        },
    );

    let jwk = to_jwk_with_kid(&key, Default::default());
    test_sts_authentication_invalid_token(key, jwk, token).await;
}

async fn test_sts_authentication_invalid_token(key: GeneratedKey, jwk: PublicKeyJwk, jwt: Jwt<()>) {
    // given
    let mock_server = MockServer::builder().start().await;
    let config = indoc::formatdoc! {"
      app:
        auth:
            mode: STS
            stsTokenValidation:
                aud: 'core'
                iss: 'bff'
                ttlJwks: 600
                jwksUri: {url}
    ",
    url = format!("{}/jwks.json", mock_server.uri())};
    let jwks = json!({
        "keys": [
            jwk
        ]
    });
    Mock::given(method(Method::GET))
        .and(path("/jwks.json"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(serde_json::to_string(&jwks).unwrap()),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    let context = TestContext::new(Some(config)).await;
    let mut tokenized = jwt.tokenize(None).await.unwrap();
    let signature = EDDSASigner {}
        .sign(tokenized.as_bytes(), &key.public, &key.private)
        .unwrap();
    tokenized.push('.');
    tokenized.push_str(&bin_to_b64url_string(&signature).unwrap());

    // when
    let resp = http_client()
        .get(format!(
            "{}/api/config/v1",
            context.config.app.core_base_url
        ))
        .bearer_auth(tokenized)
        .send()
        .await
        .unwrap();

    // then
    similar_asserts::assert_eq!(resp.status(), 401);
}

fn to_jwk_with_kid(key: &GeneratedKey, kid: Uuid) -> PublicKeyJwk {
    let mut jwk = key.key.public_key_as_jwk().unwrap();
    if let PublicKeyJwk::Okp(k) = &mut jwk {
        k.kid = Some(kid.to_string());
    }
    jwk
}
