//! OAuth 2.0 Dynamic Client Registration Protocol
//!
//! Spec: <https://datatracker.ietf.org/doc/html/rfc7591>

use serde::{Deserialize, Serialize};

/// Token endpoint authentication method.
///
/// Spec: <https://datatracker.ietf.org/doc/html/rfc7591#section-2>
///
/// Standard values from IANA "OAuth Token Endpoint Authentication Methods" registry.
/// Custom/extension values are captured by the `Other` variant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub enum TokenEndpointAuthMethod {
    #[serde(rename = "client_secret_basic")]
    ClientSecretBasic,
    #[serde(rename = "client_secret_post")]
    ClientSecretPost,
    #[serde(rename = "none")]
    None,
    /// Attestation-based client authentication
    /// Spec: <https://datatracker.ietf.org/doc/html/draft-ietf-oauth-attestation-based-client-auth>
    #[serde(rename = "attest_jwt_client_auth")]
    AttestJwtClientAuth,
    /// Custom/extension authentication method
    #[serde(untagged)]
    Other(String),
}
