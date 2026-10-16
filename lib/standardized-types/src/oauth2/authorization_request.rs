//! OAuth 2.0 Authorization Request
//!
//! Spec: [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1)

use bon::Builder;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use super::authorization_server_metadata::CodeChallengeMethod;

/// Authorization Request parameters, sent as the query string of the authorization endpoint.
///
/// Carries the PKCE parameters of [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636.html#section-4.3),
/// the DPoP authorization code binding of [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html#section-10)
/// and the `issuer_state` parameter added by OpenID4VCI.
#[skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Builder)]
pub struct AuthorizationRequest {
    pub client_id: String,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub redirect_uri: Option<String>,

    /// JSON-encoded [RFC 9396](https://www.rfc-editor.org/rfc/rfc9396.html) authorization details.
    pub authorization_details: Option<String>,

    /// Defaults to `code`, the only response type used by the authorization code flow.
    #[builder(default = "code".to_string())]
    pub response_type: String,

    /// [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636.html#section-4.3)
    pub code_challenge: Option<String>,
    /// [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636.html#section-4.3)
    pub code_challenge_method: Option<CodeChallengeMethod>,

    /// <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-5.1.3-2.1>
    pub issuer_state: Option<String>,

    /// JWK SHA-256 thumbprint of the DPoP key the authorization code is bound to.
    ///
    /// Spec: [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html#section-10)
    pub dpop_jkt: Option<String>,
}

impl AuthorizationRequest {
    pub fn with_code_challenge(
        self,
        code_challenge: String,
        code_challenge_method: CodeChallengeMethod,
    ) -> Self {
        Self {
            code_challenge: Some(code_challenge),
            code_challenge_method: Some(code_challenge_method),
            ..self
        }
    }
}

#[cfg(test)]
mod test {
    use similar_asserts::assert_eq;

    use super::*;

    #[test]
    fn test_authorization_request_omits_absent_parameters() {
        let request = AuthorizationRequest::builder()
            .client_id("wallet".to_string())
            .build();

        assert_eq!("code", request.response_type);
        assert_eq!(
            "client_id=wallet&response_type=code",
            serde_urlencoded::to_string(&request).unwrap()
        );
    }

    #[test]
    fn test_authorization_request_form_encoding() {
        let request = AuthorizationRequest::builder()
            .client_id("wallet".to_string())
            .scope("scope1 scope2".to_string())
            .state("testState".to_string())
            .redirect_uri("http://redirect.uri".to_string())
            .issuer_state("issuerState".to_string())
            .dpop_jkt("jkt".to_string())
            .build()
            .with_code_challenge("challenge".to_string(), CodeChallengeMethod::S256);

        assert_eq!(
            "client_id=wallet&scope=scope1+scope2&state=testState\
             &redirect_uri=http%3A%2F%2Fredirect.uri&response_type=code\
             &code_challenge=challenge&code_challenge_method=S256&issuer_state=issuerState\
             &dpop_jkt=jkt",
            serde_urlencoded::to_string(&request).unwrap()
        );
    }
}
