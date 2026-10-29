//! OAuth 2.0 Authorization Server Metadata
//!
//! Spec: <https://datatracker.ietf.org/doc/html/rfc8414#section-2>
//!
//! Also covers the corresponding OpenID Connect Discovery provider metadata:
//! <https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata>

use serde::{Deserialize, Deserializer, Serialize};
use url::Url;

use super::attestation_based_client_auth::ClientAttestationPopMethod;
use super::dynamic_client_registration::TokenEndpointAuthMethod;

#[cfg_attr(feature = "utoipa", proc_macros::options_not_nullable)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct AuthorizationServerMetadata {
    /// Authorization server's issuer identifier, kept verbatim: it must be compared and used
    /// (e.g. as audience) exactly as published, which a parsed [`Url`] does not guarantee
    /// (`https://as.example.com` would turn into `https://as.example.com/`).
    ///
    /// Spec: <https://datatracker.ietf.org/doc/html/rfc8414#section-3.3>
    #[serde(deserialize_with = "deserialize_url_string")]
    pub issuer: String,
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

    /// Attestation-Based Client Authentication - supported proof of possession methods
    /// <https://datatracker.ietf.org/doc/html/draft-ietf-oauth-attestation-based-client-auth-12#section-8>
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_attestation_pop_methods_supported: Option<Vec<ClientAttestationPopMethod>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub dpop_signing_alg_values_supported: Option<Vec<String>>,

    /// A JWT carrying the metadata parameters of this document as claims, signed by the
    /// authorization server.
    ///
    /// Spec: <https://datatracker.ietf.org/doc/html/rfc8414#section-2.1>
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_metadata: Option<String>,
}

impl AuthorizationServerMetadata {
    pub fn issuer_url(&self) -> Result<Url, url::ParseError> {
        self.issuer.parse()
    }
}

/// a string that must be a valid URL
fn deserialize_url_string<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    let value = String::deserialize(deserializer)?;
    Url::parse(&value).map_err(serde::de::Error::custom)?;
    Ok(value)
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

#[cfg(test)]
mod test {
    use similar_asserts::assert_eq;

    use super::*;

    #[test]
    fn test_issuer_is_kept_verbatim() {
        let json = serde_json::json!({ "issuer": "https://as.example.com" });
        let metadata: AuthorizationServerMetadata = serde_json::from_value(json.clone()).unwrap();

        assert_eq!("https://as.example.com", metadata.issuer);
        assert_eq!(json, serde_json::to_value(&metadata).unwrap());
    }

    #[test]
    fn test_issuer_must_be_url() {
        assert!(
            serde_json::from_value::<AuthorizationServerMetadata>(
                serde_json::json!({ "issuer": "not a url" })
            )
            .is_err()
        );
    }
}
