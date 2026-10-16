//! Cloud Signature Consortium (CSC) v2 API client.

use std::sync::Arc;

use ct_codecs::{Base64, Base64UrlSafe, Base64UrlSafeNoPadding, Decoder, Encoder};
use one_crypto::utilities::ecdsa_sig_from_der;
use one_crypto::{HasherError, SignerError};
use secrecy::{ExposeSecret, SecretSlice, SecretString};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha384, Sha512};
use standardized_types::csc::{
    AuthorizeRequest, CredentialInfoRequest, CredentialInfoResponse, CredentialListInfo,
    CredentialListRequest, CredentialListResponse, HashAlgorithm, OperationMode, SignDocDocument,
    SignDocRequest, SignDocResponse, SignHashRequest, SignHashResponse, TokenResponse,
};
use standardized_types::oauth2::token::TokenResponse as OAuth2TokenResponse;
use thiserror::Error;
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

use crate::error::{ContextWithErrorCode, ErrorCode, ErrorCodeMixin, NestedError};
use crate::proto::csc::model::{
    Authorization, AuthorizationCode, AuthorizationUrlRequest, AuthorizeTlsRequest,
    ClientCredentialsRequest, CredentialToken, SignDocumentRequest, SignHashesRequest,
    TokenRequest,
};
use crate::proto::http_client::{HttpClient, RequestBuilder};
use crate::proto::jwt::Jwt;
use crate::proto::jwt::hmac::HS256Signer;
use crate::proto::jwt::model::JWTPayload;
use crate::proto::oauth_client::Pkce;

pub mod model;

/// SIGN8's gateway rejects requests without a `User-Agent`, reqwest sends none by default.
const USER_AGENT: &str = "procivis-one-core";
const CLIENT_ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

pub(crate) struct CscClientImpl {
    client: Arc<dyn HttpClient>,
}

#[derive(Debug, Error)]
pub enum CscClientError {
    #[error("Base64 encoding error: {0}")]
    Base64Encoding(#[from] ct_codecs::Error),
    #[error("URL encoding error: {0}")]
    UrlEncoding(#[from] serde_urlencoded::ser::Error),
    #[error("invalid URL: {0}")]
    InvalidUrl(#[from] url::ParseError),
    #[error("hashing error: {0}")]
    HasherError(#[from] HasherError),
    #[error("signer error: {0}")]
    SignerError(#[from] SignerError),
    #[error("CSC API returned no signed document")]
    EmptySignedDocuments,
    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for CscClientError {
    fn error_code(&self) -> ErrorCode {
        match self {
            CscClientError::Nested(err) => err.error_code(),
            _ => ErrorCode::BR_0456,
        }
    }
}

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait CscClient: Send + Sync {
    async fn authorization_url<'a>(
        &'a self,
        request: AuthorizationUrlRequest<'a>,
    ) -> Result<Authorization, CscClientError>;

    /// SIGN8's headless variant of the authorization code flow: the code comes from
    /// `/oauth2/authorize_tls` over mTLS, no browser redirect.
    async fn authorize_tls<'a>(
        &'a self,
        request: AuthorizeTlsRequest<'a>,
    ) -> Result<AuthorizationCode, CscClientError>;

    async fn exchange_code<'a>(
        &'a self,
        request: TokenRequest<'a>,
    ) -> Result<CredentialToken, CscClientError>;

    /// Client credentials grant with a `private_key_jwt` client assertion ([RFC 7523](https://www.rfc-editor.org/rfc/rfc7523))
    async fn client_credentials_token<'a>(
        &'a self,
        request: ClientCredentialsRequest<'a>,
    ) -> Result<String, CscClientError>;

    async fn credential_info(
        &self,
        api_url: &str,
        access_token: &str,
        credential_id: &str,
    ) -> Result<CredentialInfoResponse, CscClientError>;

    async fn credential_list(
        &self,
        api_url: &str,
        access_token: &str,
    ) -> Result<Vec<CredentialListInfo>, CscClientError>;

    async fn sign_document<'a>(
        &'a self,
        request: SignDocumentRequest<'a>,
    ) -> Result<Vec<u8>, CscClientError>;

    async fn sign_hash<'a>(
        &'a self,
        request: SignHashesRequest<'a>,
    ) -> Result<Vec<Vec<u8>>, CscClientError>;

    async fn revoke_access_token(
        &self,
        oauth_url: &str,
        access_token: &str,
        client_id: &str,
        client_secret: &str,
    );
}

impl CscClientImpl {
    pub(crate) fn new(client: Arc<dyn HttpClient>) -> Self {
        Self { client }
    }

    fn post(&self, url: &str) -> RequestBuilder {
        self.client.post(url).header("User-Agent", USER_AGENT)
    }
}

#[async_trait::async_trait]
impl CscClient for CscClientImpl {
    async fn authorization_url<'a>(
        &'a self,
        request: AuthorizationUrlRequest<'a>,
    ) -> Result<Authorization, CscClientError> {
        let hash = encode_base64url(request.hash)?;

        let pkce = Pkce::generate()?;
        let query = serde_urlencoded::to_string(AuthorizeRequest {
            response_type: "code",
            client_id: request.client_id,
            redirect_uri: request.redirect_uri,
            scope: "credential",
            code_challenge: &pkce.challenge,
            code_challenge_method: "S256",
            signature_qualifier: request.signature_qualifier,
            num_signatures: 1,
            hashes: &hash,
            hash_algorithm: request.hash_algorithm,
            account_token: request.account_token,
        })?;

        let mut url = Url::parse(&format!("{}/oauth2/authorize", request.oauth_url))?;
        url.set_query(Some(&query));

        Ok(Authorization {
            authorization_url: url.to_string(),
            code_verifier: pkce.verifier,
        })
    }

    async fn authorize_tls<'a>(
        &'a self,
        request: AuthorizeTlsRequest<'a>,
    ) -> Result<AuthorizationCode, CscClientError> {
        let pkce = Pkce::generate()?;
        let hashes = request
            .hashes
            .iter()
            .map(Base64UrlSafe::encode_to_string)
            .collect::<Result<Vec<_>, _>>()?
            .join(",");
        let num_signatures = request.hashes.len().to_string();

        let response: CodeResponse = async {
            self.post(&format!("{}/oauth2/authorize_tls", request.oauth_url))
                .form([
                    ("scope", "credential"),
                    ("account_token", request.account_token),
                    ("response_type", "code"),
                    ("client_id", request.client_id),
                    ("code_challenge", &pkce.challenge),
                    ("code_challenge_method", "S256"),
                    ("credentialID", request.credential_id),
                    ("numSignatures", &num_signatures),
                    ("hashes", &hashes),
                    ("hashAlgorithmOID", request.hash_algorithm.oid()),
                    ("redirect_uri", request.redirect_uri),
                ])?
                .send()
                .await?
                .error_for_status()?
                .json()
        }
        .await
        .error_while("authorize tls request")?;
        Ok(AuthorizationCode {
            code: response.code,
            code_verifier: pkce.verifier,
        })
    }

    async fn exchange_code<'a>(
        &'a self,
        request: TokenRequest<'a>,
    ) -> Result<CredentialToken, CscClientError> {
        let token: TokenResponse = async {
            self.post(&format!("{}/oauth2/token", request.oauth_url))
                .form([
                    ("grant_type", "authorization_code"),
                    ("code", request.code),
                    ("client_id", request.client_id),
                    ("client_secret", request.client_secret),
                    ("redirect_uri", request.redirect_uri),
                    ("code_verifier", request.code_verifier),
                ])?
                .send()
                .await?
                .error_for_status()?
                .json()
        }
        .await
        .error_while("credential token request")?;
        Ok(CredentialToken {
            access_token: token.access_token,
            credential_id: token.credential_id,
        })
    }

    async fn client_credentials_token<'a>(
        &'a self,
        request: ClientCredentialsRequest<'a>,
    ) -> Result<String, CscClientError> {
        let mut form = vec![
            ("grant_type", "client_credentials"),
            ("client_id", request.client_id),
            ("client_assertion_type", CLIENT_ASSERTION_TYPE),
            ("client_assertion", request.client_assertion),
            ("scope", request.scope),
        ];
        if let Some(authorization_details) = request.authorization_details {
            form.push(("authorization_details", authorization_details));
        }
        let token: OAuth2TokenResponse = async {
            self.post(request.token_url)
                .form(form)?
                .send()
                .await?
                .error_for_status()?
                .json()
        }
        .await
        .error_while("client credentials token request")?;
        Ok(token.access_token.expose_secret().to_string())
    }

    async fn credential_info(
        &self,
        api_url: &str,
        access_token: &str,
        credential_id: &str,
    ) -> Result<CredentialInfoResponse, CscClientError> {
        async {
            self.post(&format!("{api_url}/csc/v2/credentials/info"))
                .bearer_auth(access_token)
                .json(&CredentialInfoRequest {
                    credential_id: credential_id.to_string(),
                    certificates: "single".to_string(),
                    cert_info: true,
                })?
                .send()
                .await?
                .error_for_status()?
                .json()
        }
        .await
        .error_while("credential info request")
        .map_err(Into::into)
    }

    async fn credential_list(
        &self,
        api_url: &str,
        access_token: &str,
    ) -> Result<Vec<CredentialListInfo>, CscClientError> {
        let list: CredentialListResponse = async {
            self.post(&format!("{api_url}/csc/v2/credentials/list"))
                .bearer_auth(access_token)
                .json(&CredentialListRequest {
                    credential_info: true,
                    certificates: "single".to_string(),
                    cert_info: true,
                })?
                .send()
                .await?
                .error_for_status()?
                .json()
        }
        .await
        .error_while("credential list request")?;
        Ok(list.credential_infos)
    }

    async fn sign_document<'a>(
        &'a self,
        request: SignDocumentRequest<'a>,
    ) -> Result<Vec<u8>, CscClientError> {
        let document = Base64::encode_to_string(request.document)?;

        let signed: SignDocResponse = async {
            self.post(&format!("{}/csc/v2/signatures/signDoc", request.api_url))
                .bearer_auth(request.access_token)
                .json(&SignDocRequest {
                    credential_id: request.credential_id.to_string(),
                    operation_mode: OperationMode::Synchronous,
                    // We only consume the signed bytes; skip embedded revocation material.
                    return_validation_info: false,
                    documents: vec![SignDocDocument {
                        document,
                        sign_algo: request.sign_algo.to_string(),
                        signature_format: request.signature_format,
                        conformance_level: request.conformance_level,
                    }],
                })?
                .send()
                .await?
                .error_for_status()?
                .json()
        }
        .await
        .error_while("signDoc request")?;

        let signed_b64 = signed
            .document_with_signatures
            .into_iter()
            .next()
            .ok_or_else(|| CscClientError::EmptySignedDocuments)?;
        Base64::decode_to_vec(&signed_b64, None).map_err(Into::into)
    }

    async fn sign_hash<'a>(
        &'a self,
        request: SignHashesRequest<'a>,
    ) -> Result<Vec<Vec<u8>>, CscClientError> {
        let hashes = request
            .hashes
            .iter()
            .map(Base64::encode_to_string)
            .collect::<Result<Vec<_>, _>>()?;

        let response: SignHashResponse = async {
            self.post(&format!("{}/csc/v2/signatures/signHash", request.api_url))
                .bearer_auth(request.access_token)
                .json(&SignHashRequest {
                    credential_id: request.credential_id.to_string(),
                    operation_mode: OperationMode::Synchronous,
                    hashes,
                    sign_algo: request.sign_algo,
                    hash_algorithm: request.hash_algo,
                })?
                .send()
                .await?
                .error_for_status()?
                .json()
        }
        .await
        .error_while("signHash request")?;

        let encoded_sigs = response
            .signatures
            .into_iter()
            .map(|signature| Base64::decode_to_vec(&signature, None))
            .collect::<Result<Vec<_>, _>>()?;
        encoded_sigs
            .into_iter()
            .map(|sig| ecdsa_sig_from_der(&sig))
            .collect::<Result<_, _>>()
            .map_err(Into::into)
    }

    /// Best-effort revoke of an access token (cleanup; failures are logged).
    async fn revoke_access_token(
        &self,
        oauth_url: &str,
        access_token: &str,
        client_id: &str,
        client_secret: &str,
    ) {
        let result = async {
            self.post(&format!("{oauth_url}/oauth2/revoke"))
                .bearer_auth(access_token)
                .form([
                    ("token", access_token),
                    ("token_type_hint", "access_token"),
                    ("client_id", client_id),
                    ("client_secret", client_secret),
                ])?
                .send()
                .await?
                .error_for_status()
        }
        .await;
        if let Err(err) = result {
            tracing::warn!("failed to revoke csc credential token: {err}");
        }
    }
}

#[derive(Deserialize)]
struct CodeResponse {
    code: String,
}

fn encode_base64url(bytes: &[u8]) -> Result<String, CscClientError> {
    Base64UrlSafeNoPadding::encode_to_string(bytes).map_err(Into::into)
}

pub(crate) fn hash(algorithm: HashAlgorithm, data: &[u8]) -> Vec<u8> {
    match algorithm {
        HashAlgorithm::Sha256 => Sha256::digest(data).to_vec(),
        HashAlgorithm::Sha384 => Sha384::digest(data).to_vec(),
        HashAlgorithm::Sha512 => Sha512::digest(data).to_vec(),
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct AccountTokenClaims {
    azp: String,
}

/// SIGN8-proprietary gateway-auth token (not part of CSC); the CSC client forwards it.
pub(crate) async fn build_sign8_account_token(
    account_id: &str,
    client_id: &str,
    client_secret: &SecretString,
    now: OffsetDateTime,
) -> Result<String, NestedError> {
    let payload = JWTPayload::<AccountTokenClaims> {
        subject: Some(account_id.to_owned()),
        issued_at: Some(now),
        jwt_id: Some(Uuid::new_v4().to_string()),
        custom: AccountTokenClaims {
            azp: client_id.to_owned(),
        },
        ..Default::default()
    };

    let signing_key =
        SecretSlice::from(Sha256::digest(client_secret.expose_secret().as_bytes()).to_vec());

    Jwt::new("JWT".to_string(), "HS256".to_string(), None, None, payload)
        .tokenize(Some(&HS256Signer::new(signing_key)))
        .await
        .error_while("creating account token")
}

#[cfg(test)]
mod test {
    use similar_asserts::assert_eq;
    use wiremock::matchers::{body_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::error::{ErrorCode, ErrorCodeMixin};
    use crate::proto::http_client::reqwest_client::ReqwestClient;

    #[tokio::test]
    async fn exchange_code_then_sign_document_runs_optimized_flow() {
        use standardized_types::csc::{ConformanceLevel, SignatureFormat};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth2/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "atok", "credentialID": "cred-1",
                "token_type": "Bearer", "expires_in": 3600
            })))
            .mount(&server)
            .await;
        let signed_b64 = Base64::encode_to_string(b"signed-pdf-bytes").unwrap();
        Mock::given(method("POST"))
            .and(path("/csc/v2/signatures/signDoc"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "DocumentWithSignatures": [signed_b64]
            })))
            .mount(&server)
            .await;

        let csc = CscClientImpl::new(Arc::new(ReqwestClient::new(Default::default()).unwrap()));

        let token = csc
            .exchange_code(TokenRequest {
                oauth_url: &server.uri(),
                code: "code",
                client_id: "cid",
                client_secret: "sec",
                redirect_uri: "wallet://cb",
                code_verifier: "verifier",
            })
            .await
            .unwrap();
        assert_eq!(token.credential_id, "cred-1");

        let signed = csc
            .sign_document(SignDocumentRequest {
                api_url: &server.uri(),
                access_token: &token.access_token,
                credential_id: &token.credential_id,
                document: b"%PDF-1.7 doc",
                sign_algo: "1.2.840.10045.4.3.2",
                signature_format: SignatureFormat::PAdES,
                conformance_level: ConformanceLevel::AdESBLT,
            })
            .await
            .unwrap();
        assert_eq!(signed, b"signed-pdf-bytes");
    }

    #[tokio::test]
    async fn credential_info_reads_key_algorithms() {
        use standardized_types::csc::{HashAlgorithm, SignatureAlgorithm};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/csc/v2/credentials/info"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "key": { "status": "enabled", "algo": ["1.2.840.113549.1.1.1"] }
            })))
            .mount(&server)
            .await;

        let csc = CscClientImpl::new(Arc::new(ReqwestClient::new(Default::default()).unwrap()));
        let info = csc
            .credential_info(&server.uri(), "atok", "cred-1")
            .await
            .unwrap();

        assert_eq!(info.key.algo, vec!["1.2.840.113549.1.1.1".to_string()]);
        assert_eq!(
            info.signing_algorithm(HashAlgorithm::Sha256),
            Some(SignatureAlgorithm::Rsa)
        );
    }

    #[tokio::test]
    async fn credential_list_returns_credential_ids_with_their_info() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/csc/v2/credentials/list"))
            .and(body_json(serde_json::json!({
                "credentialInfo": true, "certificates": "single", "certInfo": true
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "credentialIDs": ["cred-1"],
                "credentialInfos": [{
                    "credentialID": "cred-1",
                    "key": { "status": "enabled", "algo": ["1.2.840.10045.4.3.2"] },
                    "cert": { "status": "valid", "certificates": ["MIIB"] }
                }]
            })))
            .mount(&server)
            .await;

        let csc = CscClientImpl::new(Arc::new(ReqwestClient::new(Default::default()).unwrap()));
        let credentials = csc.credential_list(&server.uri(), "atok").await.unwrap();

        let [credential] = credentials.as_slice() else {
            panic!("expected one credential");
        };
        assert_eq!(credential.credential_id, "cred-1");
        assert_eq!(
            credential.info.key.algo,
            vec!["1.2.840.10045.4.3.2".to_string()]
        );
        assert_eq!(
            credential.info.cert.as_ref().unwrap().certificates,
            vec!["MIIB".to_string()]
        );
    }

    #[tokio::test]
    async fn maps_client_error_status_to_error_code() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth2/token"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": "invalid_grant", "error_description": "Token already used"
            })))
            .mount(&server)
            .await;

        let csc = CscClientImpl::new(Arc::new(ReqwestClient::new(Default::default()).unwrap()));
        let err = csc
            .exchange_code(TokenRequest {
                oauth_url: &server.uri(),
                code: "code",
                client_id: "cid",
                client_secret: "sec",
                redirect_uri: "wallet://cb",
                code_verifier: "verifier",
            })
            .await
            .unwrap_err();
        assert_eq!(err.error_code(), ErrorCode::BR_0395);
    }
}
