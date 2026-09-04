//! OAuth 2.0 Authorization Server Metadata
//!
//! Spec: <https://datatracker.ietf.org/doc/html/rfc8414#section-2>
//!
//! Also covers the corresponding OpenID Connect Discovery provider metadata:
//! <https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata>

use serde::{Deserialize, Serialize};
use url::Url;

use super::dynamic_client_registration::TokenEndpointAuthMethod;

#[cfg_attr(feature = "utoipa", proc_macros::options_not_nullable)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct AuthorizationServerMetadata {
    pub issuer: Url,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_endpoint: Option<Url>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint: Option<Url>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pushed_authorization_request_endpoint: Option<Url>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub code_challenge_methods_supported: Vec<CodeChallengeMethod>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes_supported: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub response_types_supported: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub grant_types_supported: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub token_endpoint_auth_methods_supported: Vec<TokenEndpointAuthMethod>,

    /// Attestation-Based Client Authentication challenge endpoint
    /// <https://datatracker.ietf.org/doc/html/draft-ietf-oauth-attestation-based-client-auth-07#section-13.1>
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge_endpoint: Option<Url>,

    /// Attestation-Based Client Authentication - supported signing algorithms for client attestation
    /// <https://datatracker.ietf.org/doc/html/draft-ietf-oauth-attestation-based-client-auth-07#section-10.1>
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_attestation_signing_alg_values_supported: Option<Vec<String>>,

    /// Attestation-Based Client Authentication - supported signing algorithms for client attestation PoP
    /// <https://datatracker.ietf.org/doc/html/draft-ietf-oauth-attestation-based-client-auth-07#section-10.1>
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_attestation_pop_signing_alg_values_supported: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub dpop_signing_alg_values_supported: Option<Vec<String>>,

    /// A JWT carrying the metadata parameters of this document as claims, signed by the
    /// authorization server.
    ///
    /// Spec: <https://datatracker.ietf.org/doc/html/rfc8414#section-2.1>
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_metadata: Option<String>,
}

/// PKCE code challenge method.
///
/// [IANA registry](https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml#pkce-code-challenge-method)
///
/// Spec: [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636.html#section-4.2)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub enum CodeChallengeMethod {
    #[serde(rename = "plain")]
    Plain,
    #[serde(rename = "S256")]
    S256,
}
