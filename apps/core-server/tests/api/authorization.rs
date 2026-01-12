use std::time::Duration;

use one_core::proto::jwt::mapper::bin_to_b64url_string;
use one_core::proto::jwt::model::JWTPayload;
use one_core::proto::jwt::{Jwt, JwtPublicKeyInfo};
use one_core::provider::key_algorithm::KeyAlgorithm;
use one_core::provider::key_algorithm::eddsa::Eddsa;
use one_crypto::Signer;
use one_crypto::signer::eddsa::EDDSASigner;
use reqwest::{Method, StatusCode};
use serde::Serialize;
use serde_json::json;
use time::OffsetDateTime;
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::utils::api_clients::http_client;
use crate::utils::context::TestContext;

// This replicates the struct found in core_server::middleware,
// to avoid making it public.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StsToken {
    pub organisation_id: Option<()>,
    pub permissions: Vec<&'static str>,
}

#[tokio::test]
async fn test_authorization_success_no_permission_required() {
    test_authorization(Method::GET, "/api/config/v1", vec![], StatusCode::OK).await;
}

#[tokio::test]
async fn test_authorization_success_has_required_permission() {
    test_authorization(
        Method::DELETE,
        "/api/cache/v1?types[]=OPENID_METADATA",
        vec!["CACHE_DELETE"],
        StatusCode::NO_CONTENT,
    )
    .await;
}

#[tokio::test]
async fn test_authorization_failed_missing_required_permission() {
    test_authorization(
        Method::DELETE,
        "/api/cache/v1?types[]=OPENID_METADATA",
        vec![],
        StatusCode::FORBIDDEN,
    )
    .await;
}

async fn test_authorization(
    request_method: Method,
    request_url: &'static str,
    permissions: Vec<&'static str>,
    expected_status: StatusCode,
) {
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
                leeway: 0
    ",
    url = format!("{}/jwks.json", mock_server.uri())};
    let key = Eddsa.generate_key().unwrap();

    let jwk = crate::authentication::to_jwk_with_kid(&key, Default::default());
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
        Some(JwtPublicKeyInfo::Jwk(jwk)),
        JWTPayload {
            issued_at: Some(now),
            expires_at: Some(now + Duration::from_secs(3600)),
            invalid_before: None,
            issuer: Some("bff".to_string()),
            subject: Some(Uuid::new_v4().to_string()),
            audience: Some(vec!["core".to_string()]),
            jwt_id: None,
            proof_of_possession_key: None,
            custom: StsToken {
                organisation_id: None,
                permissions,
            },
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
        .request(
            request_method,
            format!("{}{}", context.config.app.core_base_url, request_url),
        )
        .bearer_auth(tokenized)
        .send()
        .await
        .unwrap();

    // then
    similar_asserts::assert_eq!(resp.status(), expected_status);
}
