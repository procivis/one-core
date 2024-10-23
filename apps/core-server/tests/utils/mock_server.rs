use std::fmt::Display;

use reqwest::header::AUTHORIZATION;
use serde_json::json;
use time::OffsetDateTime;
use wiremock::http::Method;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, ResponseTemplate};

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

    pub async fn credential_endpoint(&self, redirect_uri: Option<String>) {
        Mock::given(method(Method::POST))
            .and(path("/credential"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "credential": "eyJhbGciOiJFRERTQSIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE3MDEyNTk2MzcsImV4cCI6MTc2NDMzMTYzNywibmJmIjoxNzAxMjU5NTc3LCJpc3MiOiJkaWQ6a2V5Ono2TWt2M0hMNTJYSk5oNHJkdG5QS1BSbmRHd1U4bkF1VnBFN3lGRmllNVNOeFprWCIsInN1YiI6ImRkMmZmMDE2LTVmYmUtNDNiMC1hMmJhLTNiMDIzZWNjNTRmYiIsImp0aSI6IjNjNDgwYjUxLTI0ZDQtNGM3OS05MDViLTI3MTQ4YjYyY2RlNiIsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwiaHR0cHM6Ly93M2lkLm9yZy92Yy9zdGF0dXMtbGlzdC8yMDIxL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiXSwiY3JlZGVudGlhbFN1YmplY3QiOnsic3RyaW5nIjoic3RyaW5nIn0sImNyZWRlbnRpYWxTdGF0dXMiOnsiaWQiOiJodHRwOi8vMC4wLjAuMDozMDAwL3NzaS9yZXZvY2F0aW9uL3YxL2xpc3QvOGJmNmRjOGYtMjI4Zi00MTVjLTgzZjItOTVkODUxYzE5MjdiIzAiLCJ0eXBlIjoiU3RhdHVzTGlzdDIwMjFFbnRyeSIsInN0YXR1c1B1cnBvc2UiOiJyZXZvY2F0aW9uIiwic3RhdHVzTGlzdENyZWRlbnRpYWwiOiJodHRwOi8vMC4wLjAuMDozMDAwL3NzaS9yZXZvY2F0aW9uL3YxL2xpc3QvOGJmNmRjOGYtMjI4Zi00MTVjLTgzZjItOTVkODUxYzE5MjdiIiwic3RhdHVzTGlzdEluZGV4IjoiMCJ9fX0.JUe1lljvJAXMMLr9mKOKLMFJ1XQr_GzL0i8JTOvt1_uNwVgQzMFQPqMUZ-sQg2JtWogDHLaUsjW64yFyc7ExCg",
                "format": "JWT",
                "redirectUri": redirect_uri
            })))
            .expect(1)
            .mount(&self.mock)
            .await;
    }

    pub async fn refresh_token(&self, schema_id: impl Display) {
        Mock::given(method(Method::POST))
            .and(path(format!("/ssi/oidc-issuer/v1/{}/token", schema_id)))
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

    pub async fn ssi_credential_endpoint(
        &self,
        schema_id: impl Display,
        bearer_auth: impl Display,
        credential: impl Display,
        format: impl Display,
    ) {
        Mock::given(method(Method::POST))
            .and(path(format!(
                "/ssi/oidc-issuer/v1/{}/credential",
                schema_id
            )))
            .and(header(AUTHORIZATION, format!("Bearer {bearer_auth}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "credential": credential.to_string(),
                "format": format.to_string(),
            })))
            .expect(1)
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
}
