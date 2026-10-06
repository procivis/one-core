//! OAuth 2.0 related specifications.

use serde::{Deserialize, Deserializer, Serialize};
use strum::Display;

pub mod attestation_based_client_auth;
pub mod authorization_request;
pub mod authorization_server_metadata;
pub mod dpop;
pub mod dynamic_client_registration;
pub mod pushed_authorization_request;
pub mod token;

/// Access token type issued by the token endpoint.
///
/// Spec: https://datatracker.ietf.org/doc/html/rfc6750#section-6.1.1
///
/// Standard values from the IANA "OAuth Access Token Types" registry.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Display)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub enum TokenType {
    /// Uses uppercase B matches usage in the Authorization header, so it seems sensible to use this casing.
    /// However, as per spec, implementations _should_ be lenient towards any casing when used as
    /// `token_type` in the token endpoint response.
    #[default]
    Bearer,
    DPoP,
}

impl<'de> Deserialize<'de> for TokenType {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // Case-insensitive as per https://datatracker.ietf.org/doc/html/rfc6749#section-5.1
        let value = String::deserialize(deserializer)?;
        if value.eq_ignore_ascii_case("bearer") {
            Ok(Self::Bearer)
        } else {
            Err(serde::de::Error::unknown_variant(&value, &["Bearer"]))
        }
    }
}

#[cfg(test)]
mod test {
    use similar_asserts::assert_eq;

    use super::*;

    #[test]
    fn test_token_type_serializes_with_capital_b() {
        assert_eq!(
            r#""Bearer""#,
            serde_json::to_string(&TokenType::Bearer).unwrap()
        );
        assert_eq!("Bearer", TokenType::Bearer.to_string());
    }

    #[test]
    fn test_token_type_deserialization_is_case_insensitive() {
        for input in [r#""Bearer""#, r#""bearer""#, r#""BEARER""#] {
            assert_eq!(
                TokenType::Bearer,
                serde_json::from_str::<TokenType>(input).unwrap()
            );
        }
    }

    #[test]
    fn test_token_type_deserialization_fails_for_unknown_value() {
        assert!(serde_json::from_str::<TokenType>(r#""DPoP""#).is_err());
    }
}
