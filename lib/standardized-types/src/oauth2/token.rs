//! OAuth 2.0 Token Endpoint
//!
//! Spec: [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749#section-4)
//!
//! Includes the `pre-authorized_code` grant added by OpenID4VCI:
//! <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-token-endpoint>

use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use strum::Display;

use super::TokenType;
use crate::mapper::{opt_secret_string, secret_string};

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "grant_type")]
pub enum TokenRequest {
    /// [OpenID4VCI](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-token-request)
    #[serde(rename = "urn:ietf:params:oauth:grant-type:pre-authorized_code")]
    PreAuthorizedCode {
        #[serde(rename = "pre-authorized_code")]
        pre_authorized_code: String,
        tx_code: Option<String>,
    },

    /// [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3)
    #[serde(rename = "authorization_code")]
    AuthorizationCode {
        #[serde(rename = "code")]
        authorization_code: String,
        client_id: String,
        redirect_uri: Option<String>,

        /// [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636#section-4.5)
        code_verifier: Option<String>,
    },

    #[serde(rename = "refresh_token")]
    RefreshToken { refresh_token: String },
}

impl TokenRequest {
    pub fn is_pre_authorized_code(&self) -> bool {
        matches!(self, Self::PreAuthorizedCode { .. })
    }

    pub fn is_refresh_token(&self) -> bool {
        matches!(self, Self::RefreshToken { .. })
    }
}

/// Lifetime of a token, in seconds from the time of the response.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct ExpiresIn(pub i64);

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct TokenResponse {
    #[serde(with = "secret_string")]
    #[cfg_attr(feature = "utoipa", schema(value_type = String, example = "secret"))]
    pub access_token: SecretString,
    pub token_type: TokenType,
    pub expires_in: ExpiresIn,
    #[serde(default, with = "opt_secret_string")]
    #[cfg_attr(
        feature = "utoipa",
        schema(value_type = String, example = "secret", nullable = false)
    )]
    pub refresh_token: Option<SecretString>,
    #[serde(default)]
    #[cfg_attr(feature = "utoipa", schema(nullable = false))]
    pub refresh_token_expires_in: Option<ExpiresIn>,
}

/// Error response of the token endpoint.
///
/// Spec: [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749#section-5.2)
#[skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenErrorResponse {
    pub error: TokenErrorCode,
    pub error_description: Option<String>,
    pub error_uri: Option<String>,
}

/// Error code of a [`TokenErrorResponse`].
///
/// The values defined by [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749#section-5.2)
/// and the extensions registered by other specifications; the registry is extensible, so
/// unrecognized codes are preserved in `Other`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum TokenErrorCode {
    InvalidRequest,
    InvalidClient,
    InvalidGrant,
    UnauthorizedClient,
    UnsupportedGrantType,
    InvalidScope,

    /// The DPoP proof the request carried was rejected.
    ///
    /// Spec: [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html#name-oauth-extensions-error-regi)
    InvalidDpopProof,

    /// The request has to be repeated with a nonce of the server's choosing.
    ///
    /// Spec: [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html#name-oauth-extensions-error-regi)
    UseDpopNonce,

    #[serde(untagged)]
    #[strum(to_string = "{0}")]
    Other(String),
}

#[cfg(test)]
mod test {
    use secrecy::ExposeSecret;
    use similar_asserts::assert_eq;

    use super::*;

    #[test]
    fn test_pre_authorized_code_token_request_serialization() {
        let request = TokenRequest::PreAuthorizedCode {
            pre_authorized_code: "adhjhdjajkdkhjhdj".to_string(),
            tx_code: Some("493536".to_string()),
        };

        assert!(request.is_pre_authorized_code());
        assert!(!request.is_refresh_token());
        assert_eq!(
            serde_json::json!({
                "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                "pre-authorized_code": "adhjhdjajkdkhjhdj",
                "tx_code": "493536"
            }),
            serde_json::to_value(&request).unwrap()
        );
    }

    #[test]
    fn test_authorization_code_token_request_renames_code() {
        let request = TokenRequest::AuthorizationCode {
            authorization_code: "SplxlOBeZQQ".to_string(),
            client_id: "wallet".to_string(),
            redirect_uri: None,
            code_verifier: Some("verifier".to_string()),
        };

        assert_eq!(
            serde_json::json!({
                "grant_type": "authorization_code",
                "code": "SplxlOBeZQQ",
                "client_id": "wallet",
                "code_verifier": "verifier"
            }),
            serde_json::to_value(&request).unwrap()
        );
    }

    /// The token endpoint takes `application/x-www-form-urlencoded`, so the form encoding of every
    /// grant is part of the wire contract.
    #[test]
    fn test_token_request_form_encoding() {
        assert_eq!(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code\
             &pre-authorized_code=adhjhdjajkdkhjhdj&tx_code=493536",
            serde_urlencoded::to_string(TokenRequest::PreAuthorizedCode {
                pre_authorized_code: "adhjhdjajkdkhjhdj".to_string(),
                tx_code: Some("493536".to_string()),
            })
            .unwrap()
        );

        assert_eq!(
            "grant_type=refresh_token&refresh_token=tGzv3JOkF0XG5Qx2TlKWIA",
            serde_urlencoded::to_string(TokenRequest::RefreshToken {
                refresh_token: "tGzv3JOkF0XG5Qx2TlKWIA".to_string(),
            })
            .unwrap()
        );

        assert_eq!(
            "grant_type=authorization_code&code=SplxlOBeZQQ&client_id=wallet&code_verifier=verifier",
            serde_urlencoded::to_string(TokenRequest::AuthorizationCode {
                authorization_code: "SplxlOBeZQQ".to_string(),
                client_id: "wallet".to_string(),
                redirect_uri: None,
                code_verifier: Some("verifier".to_string()),
            })
            .unwrap()
        );
    }

    #[test]
    fn test_token_error_response_deserialization() {
        let response: TokenErrorResponse = serde_json::from_value(serde_json::json!({
            "error": "invalid_grant",
            "error_description": "Transaction code is incorrect"
        }))
        .unwrap();

        assert_eq!(TokenErrorCode::InvalidGrant, response.error);
        assert_eq!(
            Some("Transaction code is incorrect".to_string()),
            response.error_description
        );
    }

    #[test]
    fn test_token_error_response_retains_unregistered_codes() {
        let response: TokenErrorResponse =
            serde_json::from_value(serde_json::json!({ "error": "something_new" })).unwrap();

        assert_eq!(
            TokenErrorCode::Other("something_new".to_string()),
            response.error
        );
    }

    #[test]
    fn test_token_response_deserialization() {
        let response: TokenResponse = serde_json::from_value(serde_json::json!({
            "access_token": "eyJhbGci",
            "token_type": "bearer",
            "expires_in": 86400
        }))
        .unwrap();

        assert_eq!("eyJhbGci", response.access_token.expose_secret());
        assert_eq!(TokenType::Bearer, response.token_type);
        assert_eq!(ExpiresIn(86400), response.expires_in);
        assert!(response.refresh_token.is_none());
    }
}
