use std::fmt::Display;

use one_core::proto::jwt::Jwt;
use one_core::provider::key_algorithm::model::GeneratedKey;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use serde::Serialize;
use serde_json::json;
use shared_types::DidValue;
use wiremock::http::Method;
use wiremock::matchers::{body_partial_json, body_string_contains, header, method, path};
use wiremock::{Mock, MockBuilder, MockGuard, Request, ResponseTemplate};

use crate::fixtures::presentation::w3c_jwt_vc;

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

    pub async fn received_requests(&self) -> Option<Vec<wiremock::Request>> {
        self.mock.received_requests().await
    }

    pub async fn refresh_token(&self, schema_id: impl Display) {
        let expires_in = one_core::clock::now_utc().unix_timestamp() + 3600;
        self.refresh_token_with_expiries(schema_id, expires_in, expires_in)
            .await;
    }

    /// Token endpoint rotating the refresh token, with the expiries given as unix timestamps
    pub async fn refresh_token_with_expiries(
        &self,
        schema_id: impl Display,
        expires_in: i64,
        refresh_token_expires_in: i64,
    ) {
        Mock::given(method(Method::POST))
            .and(path(format!("/ssi/openid4vci/final-1.0/{schema_id}/token")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!(
                {
                   "access_token": "321",
                   "token_type": "Bearer",
                   "expires_in": expires_in,
                   "refresh_token": "321",
                   "refresh_token_expires_in": refresh_token_expires_in,
                }
            )))
            .expect(1)
            .mount(&self.mock)
            .await;
    }

    pub async fn token_endpoint(&self, schema_id: impl Display, test_token: impl Serialize) {
        Mock::given(method(Method::POST))
            .and(path(format!("/ssi/openid4vci/final-1.0/{schema_id}/token")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!(
                {
                    "access_token": test_token,
                    "expires_in": one_core::clock::now_utc().unix_timestamp() + 3600,
                    "refresh_token": test_token,
                    "refresh_token_expires_in": one_core::clock::now_utc().unix_timestamp() + 3600,
                    "token_type": "Bearer"
                }
            )))
            .mount(&self.mock)
            .await;
    }

    pub async fn token_endpoint_without_refresh_token(
        &self,
        schema_id: impl Display,
        test_token: impl Serialize,
    ) {
        Mock::given(method(Method::POST))
            .and(path(format!("/ssi/openid4vci/final-1.0/{schema_id}/token")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!(
                {
                    "access_token": test_token,
                    "expires_in": one_core::clock::now_utc().unix_timestamp() + 3600,
                    "token_type": "Bearer"
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
            .and(path(format!("/ssi/openid4vci/final-1.0/{schema_id}/token")))
            .and(body_string_contains(format!("tx_code={tx_code}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!(
                {
                    "access_token": test_token,
                    "expires_in": one_core::clock::now_utc().unix_timestamp() + 3600,
                    "refresh_token": test_token,
                    "refresh_token_expires_in": one_core::clock::now_utc().unix_timestamp() + 3600,
                    "token_type": "Bearer"
                }
            )))
            .mount(&self.mock)
            .await;
    }

    pub async fn ssi_credential_endpoint(
        &self,
        schema_id: impl Display,
        bearer_auth: impl Display,
        credentials: &[impl Display],
        expected_calls: u64,
        notification_id: Option<&str>,
    ) {
        let credentials: Vec<_> = credentials
            .iter()
            .map(|credential| json!({"credential": credential.to_string()}))
            .collect();
        Mock::given(method(Method::POST))
            .and(path(format!(
                "/ssi/openid4vci/final-1.0/{schema_id}/credential"
            )))
            .and(header(AUTHORIZATION, format!("Bearer {bearer_auth}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "credentials": credentials,
                "notification_id": notification_id
            })))
            .expect(expected_calls)
            .mount(&self.mock)
            .await;
    }

    /// Like [`Self::ssi_credential_endpoint`], but for batch requests where the wallet
    /// auto-generates one holder-binding key per proof: since those keys/DIDs only exist once
    /// the server creates them, they can't be known up front to pre-sign matching credentials.
    /// Instead this mock inspects each incoming request's `proofs.jwt`, recovers the holder DID
    /// each proof was bound to (from its `kid` header), and signs one matching credential per
    /// proof on the fly, so the response has as many credentials as proofs were sent, unless
    /// capped by `max_credentials`.
    pub async fn ssi_credential_endpoint_dynamic(
        &self,
        schema_id: impl Display,
        bearer_auth: impl Display,
        issuer_key: GeneratedKey,
        issuer_did: DidValue,
        max_credentials: Option<usize>,
        expected_calls: u64,
    ) {
        Mock::given(method(Method::POST))
            .and(path(format!(
                "/ssi/openid4vci/final-1.0/{schema_id}/credential"
            )))
            .and(header(AUTHORIZATION, format!("Bearer {bearer_auth}")))
            .respond_with(move |request: &Request| {
                let body: serde_json::Value = request
                    .body_json()
                    .expect("credential request body must be JSON");
                let proofs = body["proofs"]["jwt"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default();

                let credentials: Vec<_> = proofs
                    .iter()
                    .take(max_credentials.unwrap_or(usize::MAX))
                    .map(|proof| {
                        let proof = proof.as_str().expect("proof must be a JWT string");
                        let decomposed = Jwt::<serde_json::Value>::decompose_token(proof)
                            .expect("failed to decompose proof JWT");
                        let kid = decomposed
                            .header
                            .key_id
                            .expect("proof JWT header must have a kid");
                        let holder_did: DidValue = kid
                            .split('#')
                            .next()
                            .expect("kid must not be empty")
                            .parse()
                            .expect("kid prefix must be a valid DID");

                        let credential = futures::executor::block_on(w3c_jwt_vc(
                            &issuer_key,
                            "ES256",
                            issuer_did.clone(),
                            holder_did,
                            json!({"string":"string"}),
                        ));
                        json!({"credential": credential})
                    })
                    .collect();

                ResponseTemplate::new(200).set_body_json(json!({
                    "credentials": credentials,
                    "notification_id": null,
                }))
            })
            .expect(expected_calls)
            .mount(&self.mock)
            .await;
    }

    /// Rejects credential requests for the given credential configuration,
    /// takes precedence over the catch-all credential endpoint mocks.
    pub async fn ssi_credential_endpoint_failure(
        &self,
        schema_id: impl Display,
        bearer_auth: impl Display,
        credential_configuration_id: impl Display,
    ) {
        Mock::given(method(Method::POST))
            .and(path(format!(
                "/ssi/openid4vci/final-1.0/{schema_id}/credential"
            )))
            .and(header(AUTHORIZATION, format!("Bearer {bearer_auth}")))
            .and(body_partial_json(json!({
                "credential_configuration_id": credential_configuration_id.to_string()
            })))
            .respond_with(ResponseTemplate::new(400).set_body_json(json!({
                "error": "invalid_credential_request"
            })))
            .with_priority(1)
            .expect(1)
            .mount(&self.mock)
            .await;
    }

    pub async fn ssi_nonce_endpoint(
        &self,
        protocol_name: impl Display,
        c_nonce: impl Display,
        expected_calls: u64,
    ) {
        Mock::given(method(Method::POST))
            .and(path(format!(
                "/ssi/openid4vci/final-1.0/{protocol_name}/nonce"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "c_nonce": c_nonce.to_string(),
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
                "/ssi/openid4vci/final-1.0/{schema_id}/notification"
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
        let mut mock_builder =
            Mock::given(method(Method::POST)).and(path("/mock/response".to_owned()));
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

    pub async fn webhook(&self, expected_content: serde_json::Value) -> MockGuard {
        Mock::given(method(Method::POST))
            .and(path("/webhook"))
            .and(header(CONTENT_TYPE, "application/json"))
            .and(body_partial_json(expected_content))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount_as_scoped(&self.mock)
            .await
    }
}
