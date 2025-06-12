use std::fmt::Display;

use reqwest::header::AUTHORIZATION;
use serde::Serialize;
use serde_json::json;
use time::OffsetDateTime;
use wiremock::http::Method;
use wiremock::matchers::{body_partial_json, body_string_contains, header, method, path};
use wiremock::{Mock, MockBuilder, ResponseTemplate};

pub struct MockServer {
    mock: wiremock::MockServer,
}

impl MockServer {
    pub async fn new() -> Self {
        let mock = wiremock::MockServer::start().await;
        Self { mock }
    }

    pub fn uri(&self) -> String {
        self.mock.uri()
    }

    pub async fn refresh_token(&self, schema_id: impl Display) {
        Mock::given(method(Method::POST))
            .and(path(format!(
                "/ssi/openid4vci/draft-13/{}/token",
                schema_id
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!(
                {
                   "access_token": "321",
                   "token_type": "bearer",
                   "expires_in": OffsetDateTime::now_utc().unix_timestamp() + 3600,
                   "refresh_token": "321",
                   "refresh_token_expires_in": OffsetDateTime::now_utc().unix_timestamp() + 3600,
                }
            )))
            .mount(&self.mock)
            .await;
    }

    pub async fn token_endpoint(&self, schema_id: impl Display, test_token: impl Serialize) {
        Mock::given(method(Method::POST))
            .and(path(format!(
                "/ssi/openid4vci/draft-13/{}/token",
                schema_id
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!(
                {
                    "access_token": test_token,
                    "expires_in": OffsetDateTime::now_utc().unix_timestamp() + 3600,
                    "refresh_token": test_token,
                    "refresh_token_expires_in": OffsetDateTime::now_utc().unix_timestamp() + 3600,
                    "token_type": "bearer"
                }
            )))
            .mount(&self.mock)
            .await;
    }

    pub async fn token_endpoint_tx_code(
        &self,
        schema_id: impl Display,
        test_token: impl Serialize,
        tx_code: impl Display,
    ) {
        Mock::given(method(Method::POST))
            .and(path(format!(
                "/ssi/openid4vci/draft-13/{}/token",
                schema_id
            )))
            .and(body_string_contains(format!("tx_code={tx_code}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!(
                {
                    "access_token": test_token,
                    "expires_in": OffsetDateTime::now_utc().unix_timestamp() + 3600,
                    "refresh_token": test_token,
                    "refresh_token_expires_in": OffsetDateTime::now_utc().unix_timestamp() + 3600,
                    "token_type": "bearer"
                }
            )))
            .mount(&self.mock)
            .await;
    }

    pub async fn ssi_credential_endpoint(
        &self,
        schema_id: impl Display,
        bearer_auth: impl Display,
        credential: impl Display,
        format: impl Display,
        expected_calls: u64,
        notification_id: Option<&str>,
    ) {
        Mock::given(method(Method::POST))
            .and(path(format!(
                "/ssi/openid4vci/draft-13/{}/credential",
                schema_id
            )))
            .and(header(AUTHORIZATION, format!("Bearer {bearer_auth}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "credential": credential.to_string(),
                "format": format.to_string(),
                "notification_id": notification_id
            })))
            .expect(expected_calls)
            .mount(&self.mock)
            .await;
    }

    pub async fn ssi_notification_endpoint(
        &self,
        schema_id: impl Display,
        notification_id: impl Display,
        bearer_auth: impl Display,
        expected_calls: u64,
    ) {
        Mock::given(method(Method::POST))
            .and(path(format!(
                "/ssi/openid4vci/draft-13/{}/notification",
                schema_id
            )))
            .and(header(AUTHORIZATION, format!("Bearer {bearer_auth}")))
            .and(body_partial_json(json!({
                "notification_id": notification_id.to_string()
            })))
            .respond_with(ResponseTemplate::new(204))
            .expect(expected_calls)
            .mount(&self.mock)
            .await;
    }

    pub async fn ssi_credential_schema_endpoint(&self, id: impl Display, body: serde_json::Value) {
        Mock::given(method(Method::GET))
            .and(path(format!("/ssi/schema/v1/{id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .expect(1)
            .mount(&self.mock)
            .await;
    }

    pub async fn ssi_request_uri_endpoint(
        &self,
        matcher: Option<impl Fn(MockBuilder) -> MockBuilder>,
    ) {
        let mut mock_builder = Mock::given(method(Method::POST))
            .and(path("/ssi/openid4vp/draft-20/response".to_owned()));
        if let Some(matcher) = matcher {
            mock_builder = matcher(mock_builder);
        }
        mock_builder
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&self.mock)
            .await;
    }

    pub async fn universal_resolving(&self, did: &str, document: serde_json::Value) {
        Mock::given(method(Method::GET))
            .and(path(format!("/1.0/identifiers/{did}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "didDocument": document,
            })))
            .expect(1)
            .mount(&self.mock)
            .await;
    }

    pub async fn fail_universal_resolving(&self, did: &str) {
        Mock::given(method(Method::GET))
            .and(path(format!("/1.0/identifiers/{did}")))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(&self.mock)
            .await;
    }

    pub async fn fail_crl_download(&self, crl_id: &str) {
        Mock::given(method(Method::GET))
            .and(path(format!("/crl/{crl_id}")))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&self.mock)
            .await;
    }

    pub async fn crl_download(&self, crl_id: &str, content: &[u8]) {
        Mock::given(method(Method::GET))
            .and(path(format!("/crl/{crl_id}")))
            .respond_with(ResponseTemplate::new(200).set_body_raw(content, "application/pkix-crl"))
            .expect(1)
            .mount(&self.mock)
            .await;
    }
}
