use std::time::Duration;

use axum::http::Method;
use one_core::proto::jwt::mapper::bin_to_b64url_string;
use one_core::proto::jwt::model::JWTPayload;
use one_core::proto::jwt::{Jwt, JwtPublicKeyInfo};
use one_core::provider::key_algorithm::KeyAlgorithm;
use one_core::provider::key_algorithm::eddsa::Eddsa;
use one_crypto::Signer;
use one_crypto::signer::eddsa::EDDSASigner;
use serde_json::json;
use time::OffsetDateTime;
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::authorization::StsToken;

pub struct StsSetup {
    pub config: String,
    pub token: String,
    pub mock_server: MockServer,
}
pub async fn setup_sts(permissions: Vec<&'static str>) -> StsSetup {
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
    StsSetup {
        config,
        token: tokenized,
        mock_server,
    }
}
