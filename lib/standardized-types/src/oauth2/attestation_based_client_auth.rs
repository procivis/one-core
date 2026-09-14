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
