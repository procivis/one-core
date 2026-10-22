//! Holder-side DPoP: proof creation and handling of the nonces provided by the issuer.
//!
//! Spec: [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html)

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use one_crypto::Hasher;
use one_crypto::hasher::sha256::SHA256;
use secrecy::{ExposeSecret, SecretString};
use shared_types::KeyId;
use standardized_types::jwk::PublicJwk;
use standardized_types::oauth2::dpop::{DPOP_JWT_TYPE, DPOP_NONCE_HEADER, DPoPClaims};
use standardized_types::oauth2::token::{TokenErrorCode, TokenErrorResponse};
use url::Url;
use uuid::Uuid;

use crate::error::ContextWithErrorCode;
use crate::proto::http_client::{HttpClient, Method, Response};
use crate::proto::jwt::model::JWTPayload;
use crate::proto::jwt::{Jwt, JwtPublicKeyInfo};
use crate::provider::credential_formatter::model::AuthenticationFn;
use crate::provider::issuance_protocol::error::IssuanceProtocolError;

/// Signs the DPoP proofs of one issuance flow with the binding key of the interaction and keeps
/// track of the most recent nonce the issuer handed out.
pub(super) struct DpopContext {
    key_id: KeyId,
    auth_fn: AuthenticationFn,
    jwk: PublicJwk,
    nonce: Mutex<Option<String>>,
    /// swiyu mode only, see [`DpopContext::with_swiyu_nonce_endpoint`]. Taken on use, so the
    /// nonce endpoint is called at most once per flow for the sake of the workaround.
    swiyu_nonce_endpoint: Mutex<Option<SwiyuNonceEndpoint>>,
}

struct SwiyuNonceEndpoint {
    client: Arc<dyn HttpClient>,
    url: String,
}

impl DpopContext {
    pub(super) fn new(
        key_id: KeyId,
        auth_fn: AuthenticationFn,
        jwk: PublicJwk,
        nonce: Option<String>,
    ) -> Self {
        Self {
            key_id,
            auth_fn,
            jwk,
            nonce: Mutex::new(nonce),
            swiyu_nonce_endpoint: Mutex::new(None),
        }
    }

    /// Workaround for swiyu issuer:
    ///  - it returns DPoP nonces only in the response of the nonce endpoint (and not the token endpoint)
    ///  - it expects a nonce in all DPoP proofs
    ///
    /// In this mode, a nonce, if absent, will be fetched from the provided nonce endpoint explicitly
    /// before creating any DPoP proof.
    pub(super) fn with_swiyu_nonce_endpoint(
        self,
        client: Arc<dyn HttpClient>,
        nonce_endpoint: String,
    ) -> Self {
        Self {
            nonce: Mutex::new(None),
            swiyu_nonce_endpoint: Mutex::new(Some(SwiyuNonceEndpoint {
                client,
                url: nonce_endpoint,
            })),
            ..self
        }
    }

    /// The binding key the proofs are signed with.
    pub(super) fn key_id(&self) -> KeyId {
        self.key_id
    }

    /// The last nonce received from the issuer, to be persisted in the interaction data.
    pub(super) fn nonce(&self) -> Option<String> {
        lock(&self.nonce).clone()
    }

    pub(super) fn record_nonce(&self, response: &Response) -> bool {
        let Some(nonce) = response.header_get(DPOP_NONCE_HEADER) else {
            return false;
        };
        let mut current = lock(&self.nonce);
        if current.as_ref() == Some(nonce) {
            return false;
        }
        *current = Some(nonce.to_owned());
        true
    }

    /// Creates the proof of possession for a single request.
    ///
    /// Spec: <https://www.rfc-editor.org/rfc/rfc9449.html#section-4.2>
    pub(super) async fn create_proof(
        &self,
        method: Method,
        url: &Url,
        access_token: Option<&SecretString>,
    ) -> Result<String, IssuanceProtocolError> {
        self.fetch_swiyu_nonce_if_unknown().await?;

        // the proof binds the access token it is sent with
        // https://www.rfc-editor.org/rfc/rfc9449.html#section-4.2-6.1
        let ath = access_token
            .map(|token| SHA256.hash_base64_url(token.expose_secret().as_bytes()))
            .transpose()
            .map_err(|error| {
                IssuanceProtocolError::Failed(format!(
                    "failed to hash access token for DPoP proof: {error}"
                ))
            })?;

        let payload = JWTPayload {
            issued_at: Some(crate::clock::now_utc()),
            expires_at: None,
            invalid_before: None,
            issuer: None,
            subject: None,
            audience: None,
            jwt_id: Some(Uuid::new_v4().to_string()),
            proof_of_possession_key: None,
            custom: DPoPClaims {
                htm: method.to_string(),
                htu: url.to_owned(),
                ath,
                nonce: self.nonce(),
            },
        };

        let jwt = Jwt::new(
            DPOP_JWT_TYPE.to_string(),
            self.auth_fn.jose_alg().error_while("getting JOSE alg")?,
            None,
            Some(JwtPublicKeyInfo::Jwk(self.jwk.to_owned())),
            payload,
        );

        Ok(jwt
            .tokenize(Some(&*self.auth_fn))
            .await
            .error_while("creating DPoP proof")?)
    }

    /// Part of the swiyu workaround, see [`DpopContext::with_swiyu_nonce_endpoint`]. The nonce is
    /// already known if the request is preceded by a call to the nonce endpoint anyway, like the
    /// credential request fetching its `c_nonce`.
    async fn fetch_swiyu_nonce_if_unknown(&self) -> Result<(), IssuanceProtocolError> {
        if self.nonce().is_some() {
            return Ok(());
        }
        let endpoint = lock(&self.swiyu_nonce_endpoint).take();
        let Some(SwiyuNonceEndpoint { client, url }) = endpoint else {
            return Ok(());
        };

        let response = client
            .post(&url)
            .send()
            .await
            .and_then(Response::error_for_status)
            .error_while("requesting DPoP nonce")?;
        self.record_nonce(&response);
        Ok(())
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The `htu` claim of a proof carries the request URL without query and fragment.
///
/// Spec: <https://www.rfc-editor.org/rfc/rfc9449.html#name-dpop-proof-jwt-syntax>
pub(super) fn proof_url(url: &str) -> Result<Url, IssuanceProtocolError> {
    let mut url: Url = url
        .parse()
        .map_err(|error| IssuanceProtocolError::Failed(format!("invalid request URL: {error}")))?;
    url.set_query(None);
    url.set_fragment(None);
    Ok(url)
}

/// Whether the server rejected the request because it wants it repeated with the nonce it just
/// provided. The token endpoint signals this in the error response body, a protected resource in
/// the `WWW-Authenticate` header.
///
/// Spec: <https://www.rfc-editor.org/rfc/rfc9449.html#section-8.2> and
/// <https://www.rfc-editor.org/rfc/rfc9449.html#section-9>
pub(super) fn requires_dpop_nonce(response: &Response) -> bool {
    if !response.status.is_client_error() {
        return false;
    }

    response
        .header_get("WWW-Authenticate")
        .is_some_and(|challenge| challenge.contains(&TokenErrorCode::UseDpopNonce.to_string()))
        || serde_json::from_slice::<TokenErrorResponse>(&response.body)
            .is_ok_and(|error| error.error == TokenErrorCode::UseDpopNonce)
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use similar_asserts::assert_eq;
    use standardized_types::jwk::PublicJwkEc;

    use super::*;
    use crate::proto::http_client::{Request, StatusCode};
    use crate::provider::credential_formatter::model::MockSignatureProvider;

    fn response(status: u16, headers: &[(&str, &str)], body: &str) -> Response {
        Response {
            body: body.as_bytes().to_vec(),
            headers: headers
                .iter()
                .map(|(key, value)| (key.to_string(), value.to_string()))
                .collect(),
            status: StatusCode(status),
            request: Request {
                body: None,
                headers: HashMap::new(),
                method: Method::Post,
                url: "https://example.com/token".to_string(),
                timeout: None,
            },
        }
    }

    #[test]
    fn test_proof_url_strips_query_and_fragment() {
        assert_eq!(
            "https://example.com/token",
            proof_url("https://example.com/token?foo=bar#baz")
                .unwrap()
                .as_str()
        );
    }

    #[test]
    fn test_requires_dpop_nonce_from_token_error_response() {
        assert!(requires_dpop_nonce(&response(
            400,
            &[],
            r#"{"error":"use_dpop_nonce","error_description":"nonce required"}"#
        )));
        assert!(!requires_dpop_nonce(&response(
            400,
            &[],
            r#"{"error":"invalid_dpop_proof"}"#
        )));
    }

    #[test]
    fn test_requires_dpop_nonce_from_resource_challenge() {
        assert!(requires_dpop_nonce(&response(
            401,
            &[("WWW-Authenticate", r#"DPoP error="use_dpop_nonce""#)],
            "",
        )));
        assert!(!requires_dpop_nonce(&response(
            401,
            &[("WWW-Authenticate", r#"DPoP error="invalid_dpop_proof""#)],
            "",
        )));
    }

    #[test]
    fn test_requires_dpop_nonce_ignores_successful_responses() {
        assert!(!requires_dpop_nonce(&response(
            200,
            &[],
            r#"{"error":"use_dpop_nonce"}"#
        )));
    }

    #[test]
    fn test_record_nonce_reports_only_changes() {
        let context = DpopContext::new(
            Uuid::new_v4().into(),
            Box::new(MockSignatureProvider::new()),
            PublicJwk::Okp(PublicJwkEc {
                alg: None,
                r#use: None,
                kid: None,
                crv: "Ed25519".to_string(),
                x: "x".to_string(),
                y: None,
            }),
            None,
        );

        assert!(context.record_nonce(&response(400, &[("DPoP-Nonce", "first")], "")));
        assert_eq!(Some("first".to_string()), context.nonce());

        assert!(!context.record_nonce(&response(400, &[("DPoP-Nonce", "first")], "")));
        assert!(context.record_nonce(&response(200, &[("dpop-nonce", "second")], "")));
        assert_eq!(Some("second".to_string()), context.nonce());

        assert!(!context.record_nonce(&response(200, &[], "")));
        assert_eq!(Some("second".to_string()), context.nonce());
    }
}
