use std::sync::Arc;

use one_crypto::Hasher;
use one_crypto::hasher::sha256::SHA256;
use one_crypto::utilities::generate_alphanumeric;
use serde::Serialize;
use standardized_types::oauth2::authorization_request::AuthorizationRequest;
use standardized_types::oauth2::authorization_server_metadata::{
    AuthorizationServerMetadata, CodeChallengeMethod,
};
use standardized_types::oauth2::pushed_authorization_request::{
    PushedAuthorizationReference, PushedAuthorizationResponse,
};
use thiserror::Error;
use url::Url;

use crate::error::{ContextWithErrorCode, ErrorCode, ErrorCodeMixin, NestedError};
use crate::proto::http_client::HttpClient;
use crate::provider::caching_loader::openid_metadata::OpenIDMetadataFetcher;

/// A PKCE (RFC 7636) `S256` verifier/challenge pair.
pub(crate) struct Pkce {
    pub verifier: String,
    pub challenge: String,
}

impl Pkce {
    pub(crate) fn generate() -> Result<Self, one_crypto::HasherError> {
        // SHA-256 has 32 bytes of output; 44 random alphanumeric characters
        // carry a comparable amount of entropy.
        let verifier = generate_alphanumeric(44);
        let challenge = SHA256.hash_base64_url(verifier.as_bytes())?;
        Ok(Self {
            verifier,
            challenge,
        })
    }
}

pub(crate) struct OAuthClient {
    http_client: Arc<dyn HttpClient>,
    metadata_cache: Arc<dyn OpenIDMetadataFetcher>,
}

impl OAuthClient {
    pub(crate) async fn initiate_authorization_code_flow(
        &self,
        authorization_server: Url,
        request: AuthorizationRequest,
    ) -> Result<OAuthAuthorizationResponse, OAuthClientError> {
        let metadata = self
            .fetch_authorization_server_metadata(authorization_server.clone())
            .await?;

        if metadata.issuer != authorization_server {
            return Err(OAuthClientError::IssuerMismatch);
        }

        // optional support for PKCE
        let (request, code_verifier) = if metadata
            .code_challenge_methods_supported
            .contains(&CodeChallengeMethod::S256)
        {
            let pkce = Pkce::generate()?;
            (
                request.with_code_challenge(pkce.challenge, CodeChallengeMethod::S256),
                Some(pkce.verifier),
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
        let mut url = metadata
            .authorization_endpoint
            .ok_or(OAuthClientError::MissingURL)?;
        url.set_query(Some(&response_params));

        Ok(OAuthAuthorizationResponse { url, code_verifier })
    }

    async fn send_par_request(
        &self,
        par_endpoint: Url,
        request: AuthorizationRequest,
    ) -> Result<PushedAuthorizationReference, OAuthClientError> {
        let client_id = request.client_id.clone();
        let response: PushedAuthorizationResponse = async {
            self.http_client
                .post(par_endpoint.as_str())
                .form(request)?
                .send()
                .await?
                .error_for_status()?
                .json()
        }
        .await
        .error_while("PAR request")?;

        Ok(PushedAuthorizationReference {
            request_uri: response.request_uri,
            client_id,
        })
    }

    async fn fetch_authorization_server_metadata(
        &self,
        issuer_url: Url,
    ) -> Result<AuthorizationServerMetadata, OAuthClientError> {
        // obtain OAuth 2.0 Authorization server metadata (https://datatracker.ietf.org/doc/html/rfc8414#section-3)
        Ok(self
            .metadata_cache
            .fetch_json_well_known(&issuer_url, "oauth-authorization-server")
            .await
            .error_while("fetching authorization server metadata")?)
    }
}

pub(crate) trait OAuthClientProvider {
    fn oauth_client(&self, metadata_cache: Arc<dyn OpenIDMetadataFetcher>) -> OAuthClient;
}

impl OAuthClientProvider for Arc<dyn HttpClient> {
    fn oauth_client(&self, metadata_cache: Arc<dyn OpenIDMetadataFetcher>) -> OAuthClient {
        OAuthClient {
            http_client: self.clone(),
            metadata_cache,
        }
    }
}

#[derive(Debug, Error)]
pub(crate) enum OAuthClientError {
    #[error("OAuth issuer mismatch between request and authorization server metadata")]
    IssuerMismatch,
    #[error("OAuth Authorization endpoint not found in authorization server metadata")]
    MissingURL,

    #[error("OAuth client serialization failure: `{0}`")]
    Serialization(#[from] serde_urlencoded::ser::Error),
    #[error("Hash error: `{0}`")]
    HasherError(#[from] one_crypto::HasherError),

    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for OAuthClientError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::HasherError(_) => ErrorCode::BR_0000,
            Self::IssuerMismatch | Self::MissingURL | Self::Serialization(_) => ErrorCode::BR_0360,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct OAuthAuthorizationResponse {
    pub url: Url,
    pub code_verifier: Option<String>,
}

#[cfg(test)]
mod tests {
    use mockall::predicate::eq;
    use reqwest::Method;
    use serde_json::json;
    use wiremock::matchers::{body_string_contains, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::proto::http_client::reqwest_client::ReqwestClient;
    use crate::provider::caching_loader::openid_metadata::MockOpenIDMetadataFetcher;

    fn authorization_server_metadata(issuer: &str) -> AuthorizationServerMetadata {
        AuthorizationServerMetadata {
            issuer: issuer.parse().unwrap(),
            authorization_endpoint: Some(Url::parse("https://authorize.com/authorize").unwrap()),
            token_endpoint: None,
            pushed_authorization_request_endpoint: None,
            jwks_uri: None,
            code_challenge_methods_supported: vec![],
            scopes_supported: vec![],
            response_types_supported: vec![],
            grant_types_supported: vec![],
            token_endpoint_auth_methods_supported: vec![],
            challenge_endpoint: None,
            client_attestation_signing_alg_values_supported: None,
            client_attestation_pop_signing_alg_values_supported: None,
            dpop_signing_alg_values_supported: None,
            signed_metadata: None,
        }
    }

    /// An OAuth client whose metadata cache serves `metadata` for the `issuer` well-known endpoint.
    fn oauth_client(issuer: &str, metadata: AuthorizationServerMetadata) -> OAuthClient {
        let mut metadata_cache = MockOpenIDMetadataFetcher::new();
        metadata_cache
            .expect_get()
            .with(
                eq(format!("{issuer}/.well-known/oauth-authorization-server")),
                eq("application/json"),
            )
            .once()
            .return_once(move |_, _| Ok(serde_json::to_vec(&metadata).unwrap()));

        (Arc::new(ReqwestClient::default()) as Arc<dyn HttpClient>)
            .oauth_client(Arc::new(metadata_cache))
    }

    #[tokio::test]
    async fn send_authorization_request_plain() {
        // given
        let issuer = "https://issuer.com";
        let client = oauth_client(issuer, authorization_server_metadata(issuer));

        // when
        let result = client
            .initiate_authorization_code_flow(
                issuer.parse().unwrap(),
                AuthorizationRequest::builder()
                    .client_id("clientId".to_string())
                    .scope("scope1 scope2".to_string())
                    .state("testState".to_string())
                    .redirect_uri("http://redirect.uri".to_string())
                    .authorization_details(
                        json!([{
                            "credential_configuration_id": "configurationId",
                            "type": "type",
                        }])
                        .to_string(),
                    )
                    .issuer_state("issuerState".to_string())
                    .build(),
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
        let issuer = "https://issuer.com";
        let client = oauth_client(
            issuer,
            AuthorizationServerMetadata {
                code_challenge_methods_supported: vec![CodeChallengeMethod::S256],
                ..authorization_server_metadata(issuer)
            },
        );

        // when
        let result = client
            .initiate_authorization_code_flow(
                issuer.parse().unwrap(),
                AuthorizationRequest::builder()
                    .client_id("clientId".to_string())
                    .scope("scope1 scope2".to_string())
                    .state("testState".to_string())
                    .redirect_uri("http://redirect.uri".to_string())
                    .authorization_details(
                        json!([{
                            "credential_configuration_id": "configurationId",
                            "type": "type",
                        }])
                        .to_string(),
                    )
                    .build(),
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
        let mock_server = MockServer::start().await;
        let issuer = mock_server.uri();

        let client = oauth_client(
            &issuer,
            AuthorizationServerMetadata {
                pushed_authorization_request_endpoint: Some(
                    Url::parse(&format!("{issuer}/par")).unwrap(),
                ),
                code_challenge_methods_supported: vec![CodeChallengeMethod::S256],
                ..authorization_server_metadata(&issuer)
            },
        );

        Mock::given(method(Method::POST))
            .and(path("/par"))
            .and(body_string_contains("client_id=clientId"))
            .and(body_string_contains("response_type=code"))
            .and(body_string_contains("scope=scope1+scope2"))
            .and(body_string_contains("redirect_uri=http%3A%2F%2Fredirect.uri"))
            .and(body_string_contains("state=testState"))
            .and(body_string_contains("authorization_details=%5B%7B%22credential_configuration_id%22%3A%22configurationId%22%2C%22type%22%3A%22type%22%7D%5D"))
            .and(body_string_contains("code_challenge_method=S256"))
            .respond_with(ResponseTemplate::new(200).set_body_json(PushedAuthorizationResponse {
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
                AuthorizationRequest::builder()
                    .client_id("clientId".to_string())
                    .scope("scope1 scope2".to_string())
                    .state("testState".to_string())
                    .redirect_uri("http://redirect.uri".to_string())
                    .authorization_details(
                        json!([{
                            "credential_configuration_id": "configurationId",
                            "type": "type",
                        }])
                        .to_string(),
                    )
                    .build(),
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
        let mock_server = MockServer::start().await;
        let issuer = mock_server.uri();

        let client = oauth_client(
            &issuer,
            AuthorizationServerMetadata {
                pushed_authorization_request_endpoint: Some(
                    Url::parse(&format!("{issuer}/par")).unwrap(),
                ),
                code_challenge_methods_supported: vec![CodeChallengeMethod::S256],
                ..authorization_server_metadata(&issuer)
            },
        );

        Mock::given(method(Method::POST))
            .and(path("/par"))
            .and(body_string_contains("issuer_state=testing-state"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(PushedAuthorizationResponse {
                    request_uri: "testRequestUri".to_string(),
                    expires_in: 300,
                }),
            )
            .expect(1)
            .mount(&mock_server)
            .await;

        // when
        let result = client
            .initiate_authorization_code_flow(
                issuer.parse().unwrap(),
                AuthorizationRequest::builder()
                    .client_id("clientId".to_string())
                    .issuer_state("testing-state".to_string())
                    .build(),
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
