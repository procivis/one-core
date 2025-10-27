use std::sync::Arc;

use one_crypto::Hasher;
use one_crypto::hasher::sha256::SHA256;
use one_crypto::utilities::generate_alphanumeric;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

use crate::provider::http_client::HttpClient;
use crate::provider::issuance_protocol::openid4vci_final1_0::model::{
    OAuthAuthorizationServerMetadata, OAuthCodeChallengeMethod,
};

pub(crate) struct OAuthClient {
    http_client: Arc<dyn HttpClient>,
}

impl OAuthClient {
    pub(crate) async fn initiate_authorization_code_flow(
        &self,
        authorization_server: Url,
        request: OAuthAuthorizationRequest,
    ) -> Result<OAuthAuthorizationResponse, OAuthClientError> {
        let metadata = self
            .fetch_authorization_server_metadata(authorization_server.clone())
            .await?;

        if metadata.issuer != authorization_server {
            return Err(OAuthClientError::Failed(
                "Issuer mismatch between request and authorization server metadata".to_string(),
            ));
        }

        // optional support for PKCE
        let (request, code_verifier) = if metadata
            .code_challenge_methods_supported
            .contains(&OAuthCodeChallengeMethod::S256)
        {
            // SHA-256 result has 32 bytes. 44 of (completely random) alphanumeric characters should contain
            // a similar amount of entropy (around 32-33 bytes). So it does not really make sense to generate
            // more as the hash cannot contain more entropy.
            let code_verifier = generate_alphanumeric(44);
            let code_challenge = SHA256
                .hash_base64_url(code_verifier.as_bytes())
                .map_err(|e| OAuthClientError::Failed(e.to_string()))?;
            (
                request.with_code_challenge(code_challenge, OAuthCodeChallengeMethod::S256),
                Some(code_verifier),
            )
        } else {
            (request, None)
        };

        let response_params =
            if let Some(par_endpoint) = metadata.pushed_authorization_request_endpoint {
                serde_urlencoded::to_string(self.send_par_request(par_endpoint, request).await?)?
            } else {
                serde_urlencoded::to_string(request)?
            };

        // construct authorization URL by adding all necessary query parameters
        let mut url = metadata.authorization_endpoint.ok_or_else(|| {
            OAuthClientError::Failed(
                "Authorization endpoint not found in authorization server metadata".to_string(),
            )
        })?;
        url.set_query(Some(&response_params));

        Ok(OAuthAuthorizationResponse { url, code_verifier })
    }

    async fn send_par_request(
        &self,
        par_endpoint: Url,
        request: OAuthAuthorizationRequest,
    ) -> Result<OAuthResponseParamsPAR, OAuthClientError> {
        let client_id = request.client_id.clone();
        let response: OAuthPARResponse = self
            .http_client
            .post(par_endpoint.as_str())
            .form(request)
            .map_err(|e| OAuthClientError::Failed(e.to_string()))?
            .send()
            .await
            .map_err(|e| OAuthClientError::Failed(e.to_string()))?
            .error_for_status()
            .map_err(|e| OAuthClientError::Failed(e.to_string()))?
            .json()
            .map_err(|e| OAuthClientError::Failed(e.to_string()))?;

        Ok(OAuthResponseParamsPAR {
            request_uri: response.request_uri,
            client_id,
        })
    }

    async fn fetch_authorization_server_metadata(
        &self,
        issuer_url: Url,
    ) -> Result<OAuthAuthorizationServerMetadata, OAuthClientError> {
        // obtain OAuth 2.0 Authorization server metadata (https://datatracker.ietf.org/doc/html/rfc8414#section-3)
        // prepend `.well-known/oauth-authorization-server` to path to construct provider metadata endpoint
        let original_path_segments: Vec<_> = issuer_url
            .path_segments()
            .ok_or(OAuthClientError::Failed("invalid issuer URL".to_string()))?
            .filter_map(|segment| {
                if segment.is_empty() {
                    None
                } else {
                    Some(segment.to_string())
                }
            })
            .collect();

        let mut authorization_server_metadata_endpoint = issuer_url;
        {
            let mut segments = authorization_server_metadata_endpoint
                .path_segments_mut()
                .map_err(|_| OAuthClientError::Failed("invalid issuer URL".to_string()))?;

            segments
                .clear()
                .push(".well-known")
                .push("oauth-authorization-server");
            if !original_path_segments.is_empty() {
                segments.extend(&original_path_segments);
            }
        }

        self.http_client
            .get(authorization_server_metadata_endpoint.as_str())
            .send()
            .await
            .map_err(|e| OAuthClientError::Failed(e.to_string()))?
            .error_for_status()
            .map_err(|e| OAuthClientError::Failed(e.to_string()))?
            .json()
            .map_err(|e| OAuthClientError::Failed(e.to_string()))
    }
}

#[derive(Debug, Clone, Serialize)]
struct OAuthResponseParamsPAR {
    request_uri: String,
    client_id: String,
}

pub(crate) trait OAuthClientProvider {
    fn oauth_client(&self) -> OAuthClient;
}

impl OAuthClientProvider for Arc<dyn HttpClient> {
    fn oauth_client(&self) -> OAuthClient {
        OAuthClient {
            http_client: self.clone(),
        }
    }
}

#[derive(Debug, Error)]
pub(crate) enum OAuthClientError {
    #[error("OAuth client failure: `{0}`")]
    Failed(String),

    #[error("OAuth client serialization failure: `{0}`")]
    Serialization(#[from] serde_urlencoded::ser::Error),
}

/// <https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1>
#[derive(Clone, Debug, Serialize)]
pub(crate) struct OAuthAuthorizationRequest {
    pub client_id: String,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub redirect_uri: Option<String>,
    pub authorization_details: Option<String>,
    pub response_type: String,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<OAuthCodeChallengeMethod>,

    /// <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-5.1.3-2.1>
    pub issuer_state: Option<String>,
}

impl OAuthAuthorizationRequest {
    pub fn new(
        client_id: String,
        scope: Option<String>,
        state: Option<String>,
        redirect_uri: Option<String>,
        authorization_details: Option<String>,
    ) -> Self {
        Self {
            client_id,
            scope,
            state,
            redirect_uri,
            authorization_details,
            response_type: "code".to_string(),
            code_challenge: None,
            code_challenge_method: None,
            issuer_state: None,
        }
    }

    fn with_code_challenge(
        self,
        code_challenge: String,
        code_challenge_method: OAuthCodeChallengeMethod,
    ) -> Self {
        Self {
            code_challenge: Some(code_challenge),
            code_challenge_method: Some(code_challenge_method),
            ..self
        }
    }

    pub(crate) fn with_issuer_state(self, issuer_state: String) -> Self {
        Self {
            issuer_state: Some(issuer_state),
            ..self
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct OAuthAuthorizationResponse {
    pub url: Url,
    pub code_verifier: Option<String>,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct OAuthPARResponse {
    pub request_uri: String,
    pub expires_in: i32,
}

#[cfg(test)]
mod tests {
    use reqwest::Method;
    use serde_json::json;
    use wiremock::matchers::{body_string_contains, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::provider::http_client::reqwest_client::ReqwestClient;

    #[tokio::test]
    async fn send_authorization_request_plain() {
        // given
        let client = (Arc::new(ReqwestClient::default()) as Arc<dyn HttpClient>).oauth_client();
        let mock_server = MockServer::start().await;

        let issuer = mock_server.uri();
        Mock::given(method(Method::GET))
            .and(path("/.well-known/oauth-authorization-server"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                OAuthAuthorizationServerMetadata {
                    issuer: issuer.parse().unwrap(),
                    authorization_endpoint: Some(
                        Url::parse("https://authorize.com/authorize").unwrap(),
                    ),
                    token_endpoint: None,
                    pushed_authorization_request_endpoint: None,
                    jwks_uri: None,
                    code_challenge_methods_supported: vec![],
                    response_types_supported: vec![],
                    grant_types_supported: vec![],
                    token_endpoint_auth_methods_supported: vec![],
                    challenge_endpoint: None,
                    client_attestation_signing_alg_values_supported: None,
                    client_attestation_pop_signing_alg_values_supported: None,
                },
            ))
            .expect(1)
            .mount(&mock_server)
            .await;

        // when
        let result = client
            .initiate_authorization_code_flow(
                issuer.parse().unwrap(),
                OAuthAuthorizationRequest::new(
                    "clientId".to_string(),
                    Some("scope1 scope2".to_string()),
                    Some("testState".to_string()),
                    Some("http://redirect.uri".to_string()),
                    Some(
                        json!([{
                            "credential_configuration_id": "configurationId",
                            "type": "type",
                        }])
                        .to_string(),
                    ),
                )
                .with_issuer_state("issuerState".to_string()),
            )
            .await
            .unwrap();

        // then
        let url = result.url.to_string();
        assert!(url.contains("https://authorize.com/"));
        assert!(url.contains("response_type=code"));
        assert!(url.contains("client_id=clientId"));
        assert!(url.contains("state=testState"));
        assert!(url.contains("redirect_uri=http%3A%2F%2Fredirect.uri"));
        assert!(url.contains("scope=scope1+scope2"));
        assert!(url.contains("authorization_details=%5B%7B%22credential_configuration_id%22%3A%22configurationId%22%2C%22type%22%3A%22type%22%7D%5D"));
        assert!(url.contains("issuer_state=issuerState"));

        assert!(!url.contains("code_challenge="));
        assert!(!url.contains("code_challenge_method="));
        assert!(!url.contains("request_uri="));
    }

    #[tokio::test]
    async fn send_authorization_request_pkce() {
        // given
        let client = (Arc::new(ReqwestClient::default()) as Arc<dyn HttpClient>).oauth_client();
        let mock_server = MockServer::start().await;

        let issuer = mock_server.uri();
        Mock::given(method(Method::GET))
            .and(path("/.well-known/oauth-authorization-server"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                OAuthAuthorizationServerMetadata {
                    issuer: issuer.parse().unwrap(),
                    authorization_endpoint: Some(
                        Url::parse("https://authorize.com/authorize").unwrap(),
                    ),
                    token_endpoint: None,
                    pushed_authorization_request_endpoint: None,
                    jwks_uri: None,
                    code_challenge_methods_supported: vec![OAuthCodeChallengeMethod::S256],
                    response_types_supported: vec![],
                    grant_types_supported: vec![],
                    token_endpoint_auth_methods_supported: vec![],
                    challenge_endpoint: None,
                    client_attestation_signing_alg_values_supported: None,
                    client_attestation_pop_signing_alg_values_supported: None,
                },
            ))
            .expect(1)
            .mount(&mock_server)
            .await;

        // when
        let result = client
            .initiate_authorization_code_flow(
                issuer.parse().unwrap(),
                OAuthAuthorizationRequest::new(
                    "clientId".to_string(),
                    Some("scope1 scope2".to_string()),
                    Some("testState".to_string()),
                    Some("http://redirect.uri".to_string()),
                    Some(
                        json!([{
                            "credential_configuration_id": "configurationId",
                            "type": "type",
                        }])
                        .to_string(),
                    ),
                ),
            )
            .await
            .unwrap();

        // then
        let url = result.url.to_string();
        assert!(url.contains("https://authorize.com/"));
        assert!(url.contains("response_type=code"));
        assert!(url.contains("client_id=clientId"));
        assert!(url.contains("state=testState"));
        assert!(url.contains("redirect_uri=http%3A%2F%2Fredirect.uri"));
        assert!(url.contains("scope=scope1+scope2"));
        assert!(url.contains("authorization_details=%5B%7B%22credential_configuration_id%22%3A%22configurationId%22%2C%22type%22%3A%22type%22%7D%5D"));
        assert!(url.contains("code_challenge="));
        assert!(url.contains("code_challenge_method=S256"));

        assert!(!url.contains("request_uri="));
    }

    #[tokio::test]
    async fn send_authorization_request_par() {
        // given
        let client = (Arc::new(ReqwestClient::default()) as Arc<dyn HttpClient>).oauth_client();
        let mock_server = MockServer::start().await;

        let issuer = mock_server.uri();
        Mock::given(method(Method::GET))
            .and(path("/.well-known/oauth-authorization-server"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                OAuthAuthorizationServerMetadata {
                    issuer: issuer.parse().unwrap(),
                    authorization_endpoint: Some(
                        Url::parse("https://authorize.com/authorize").unwrap(),
                    ),
                    token_endpoint: None,
                    pushed_authorization_request_endpoint: Some(
                        Url::parse(&format!("{issuer}/par")).unwrap(),
                    ),
                    jwks_uri: None,
                    code_challenge_methods_supported: vec![OAuthCodeChallengeMethod::S256],
                    response_types_supported: vec![],
                    grant_types_supported: vec![],
                    token_endpoint_auth_methods_supported: vec![],
                    challenge_endpoint: None,
                    client_attestation_signing_alg_values_supported: None,
                    client_attestation_pop_signing_alg_values_supported: None,
                },
            ))
            .expect(1)
            .mount(&mock_server)
            .await;

        Mock::given(method(Method::POST))
            .and(path("/par"))
            .and(body_string_contains("client_id=clientId"))
            .and(body_string_contains("response_type=code"))
            .and(body_string_contains("scope=scope1+scope2"))
            .and(body_string_contains("redirect_uri=http%3A%2F%2Fredirect.uri"))
            .and(body_string_contains("state=testState"))
            .and(body_string_contains("authorization_details=%5B%7B%22credential_configuration_id%22%3A%22configurationId%22%2C%22type%22%3A%22type%22%7D%5D"))
            .and(body_string_contains("code_challenge_method=S256"))
            .respond_with(ResponseTemplate::new(200).set_body_json(OAuthPARResponse {
                request_uri: "testRequestUri".to_string(),
                expires_in: 300,
            }))
            .expect(1)
            .mount(&mock_server)
            .await;

        // when
        let result = client
            .initiate_authorization_code_flow(
                issuer.parse().unwrap(),
                OAuthAuthorizationRequest::new(
                    "clientId".to_string(),
                    Some("scope1 scope2".to_string()),
                    Some("testState".to_string()),
                    Some("http://redirect.uri".to_string()),
                    Some(
                        json!([{
                            "credential_configuration_id": "configurationId",
                            "type": "type",
                        }])
                        .to_string(),
                    ),
                ),
            )
            .await
            .unwrap();

        // then
        let url = result.url.to_string();
        assert!(url.contains("https://authorize.com/"));
        assert!(url.contains("client_id=clientId"));
        assert!(url.contains("request_uri=testRequestUri"));

        assert!(!url.contains("response_type="));
        assert!(!url.contains("state="));
        assert!(!url.contains("redirect_uri="));
        assert!(!url.contains("scope="));
        assert!(!url.contains("authorization_details="));
        assert!(!url.contains("code_challenge="));
        assert!(!url.contains("code_challenge_method="));
    }

    #[tokio::test]
    async fn send_authorization_request_par_with_issuer_state() {
        // given
        let client = (Arc::new(ReqwestClient::default()) as Arc<dyn HttpClient>).oauth_client();
        let mock_server = MockServer::start().await;

        let issuer = mock_server.uri();
        Mock::given(method(Method::GET))
            .and(path("/.well-known/oauth-authorization-server"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                OAuthAuthorizationServerMetadata {
                    issuer: issuer.parse().unwrap(),
                    authorization_endpoint: Some(
                        Url::parse("https://authorize.com/authorize").unwrap(),
                    ),
                    token_endpoint: None,
                    pushed_authorization_request_endpoint: Some(
                        Url::parse(&format!("{issuer}/par")).unwrap(),
                    ),
                    jwks_uri: None,
                    code_challenge_methods_supported: vec![OAuthCodeChallengeMethod::S256],
                    response_types_supported: vec![],
                    grant_types_supported: vec![],
                    token_endpoint_auth_methods_supported: vec![],
                    challenge_endpoint: None,
                    client_attestation_signing_alg_values_supported: None,
                    client_attestation_pop_signing_alg_values_supported: None,
                },
            ))
            .expect(1)
            .mount(&mock_server)
            .await;

        Mock::given(method(Method::POST))
            .and(path("/par"))
            .and(body_string_contains("issuer_state=testing-state"))
            .respond_with(ResponseTemplate::new(200).set_body_json(OAuthPARResponse {
                request_uri: "testRequestUri".to_string(),
                expires_in: 300,
            }))
            .expect(1)
            .mount(&mock_server)
            .await;

        // when
        let result = client
            .initiate_authorization_code_flow(
                issuer.parse().unwrap(),
                OAuthAuthorizationRequest::new("clientId".to_string(), None, None, None, None)
                    .with_issuer_state("testing-state".to_string()),
            )
            .await
            .unwrap();

        // then
        let url = result.url.to_string();
        assert!(url.contains("https://authorize.com/"));
        assert!(url.contains("client_id=clientId"));
        assert!(url.contains("request_uri=testRequestUri"));

        assert!(!url.contains("issuer_state="));
    }
}
