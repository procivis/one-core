//! OAuth 2.0 Attestation-Based Client Authentication
//!
//! Spec: <https://datatracker.ietf.org/doc/html/draft-ietf-oauth-attestation-based-client-auth-07>
//!
//! The corresponding token endpoint authentication method is
//! [`super::dynamic_client_registration::TokenEndpointAuthMethod::AttestJwtClientAuth`].

use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

/// Response of the challenge endpoint.
///
/// Spec: <https://datatracker.ietf.org/doc/html/draft-ietf-oauth-attestation-based-client-auth-07#section-8>
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct ChallengeResponse {
    pub attestation_challenge: String,
}

/// <https://datatracker.ietf.org/doc/html/draft-ietf-oauth-attestation-based-client-auth-11#name-client-attestation-pop-jwt>
#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OAuthClientAttestationPopCustomClaims {
    pub challenge: Option<String>,
}

/// Proof of possession method for the Client Attestation.
///
/// Spec: <https://datatracker.ietf.org/doc/html/draft-ietf-oauth-attestation-based-client-auth-12#section-15.5.2>
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub enum ClientAttestationPopMethod {
    /// Client Attestation PoP JWT (normal mode)
    #[serde(rename = "attestation_pop_jwt")]
    AttestationPopJwt,
    /// DPoP proof serving as the combined proof of possession
    #[serde(rename = "dpop_combined")]
    DpopCombined,
    /// Client Attestation may be omitted
    #[serde(rename = "none")]
    None,
    #[serde(untagged)]
    Other(String),
}
