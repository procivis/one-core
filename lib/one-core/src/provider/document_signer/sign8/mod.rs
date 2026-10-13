use std::sync::Arc;

use proc_macros::Provider;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use standardized_types::csc::{
    ConformanceLevel, HashAlgorithm, SignatureAlgorithm, SignatureFormat, SignatureQualifier,
};
use standardized_types::mapper::secret_string;

use crate::error::{ContextWithErrorCode, ErrorCodeMixinExt};
use crate::proto::csc::CscClient;
use crate::proto::csc::model::{AuthorizationUrlRequest, SignDocumentRequest, TokenRequest};
use crate::provider::document_signer::DocumentSigner;
use crate::provider::document_signer::error::DocumentSignerError;
use crate::provider::document_signer::model::{
    Authorization, AuthorizationRequest, DocumentSignerCapabilities, SignRequest, SignedDocument,
};
use crate::provider::provider_directory::InitializationError;
use crate::service::error::ServiceError;
use crate::util::sign8;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Sign8Params {
    pub client_id: String,
    #[serde(with = "secret_string")]
    pub client_secret: SecretString,
    pub account_id: String,
    pub csc_base_url: String,
    pub oauth_url: String,
    pub redirect_uri: String,
    #[serde(default)]
    pub signature_qualifier: SignatureQualifier,
    #[serde(default)]
    pub signature_format: SignatureFormat,
    #[serde(default)]
    pub conformance_level: ConformanceLevel,
    #[serde(default)]
    pub hash_algorithm: HashAlgorithm,
    #[serde(default)]
    pub signature_algorithm: Option<SignatureAlgorithm>,
}

#[derive(Provider)]
pub(crate) struct Sign8 {
    config_name: String,
    params: Sign8Params,
    csc: Arc<dyn CscClient>,
}

impl Sign8 {
    pub fn new(
        config_name: String,
        params: serde_json::Value,
        csc: Arc<dyn CscClient>,
    ) -> Result<Self, InitializationError> {
        let params: Sign8Params = serde_json::from_value(params).map_err(|source| {
            InitializationError::InvalidParams {
                key: config_name.clone(),
                source,
            }
        })?;
        let signer = Self {
            config_name,
            params,
            csc,
        };
        signer.validate_params()?;
        Ok(signer)
    }

    fn validate_params(&self) -> Result<(), InitializationError> {
        let caps = self.get_capabilities();
        let params = &self.params;

        let unsupported = |detail: String| InitializationError::UnsupportedConfiguration {
            key: self.config_name.clone(),
            detail,
        };

        if !caps
            .signature_qualifiers
            .contains(&params.signature_qualifier)
        {
            return Err(unsupported(format!(
                "signatureQualifier {:?} is not supported",
                params.signature_qualifier
            )));
        }
        if !caps.signature_formats.contains(&params.signature_format) {
            return Err(unsupported(format!(
                "signatureFormat {:?} is not supported",
                params.signature_format
            )));
        }
        if !caps.conformance_levels.contains(&params.conformance_level) {
            return Err(unsupported(format!(
                "conformanceLevel {:?} is not supported",
                params.conformance_level
            )));
        }
        if !caps.hash_algorithms.contains(&params.hash_algorithm) {
            return Err(unsupported(format!(
                "hashAlgorithm {:?} is not supported",
                params.hash_algorithm
            )));
        }
        if let Some(signature_algorithm) = params.signature_algorithm {
            if !caps.signature_algorithms.contains(&signature_algorithm) {
                return Err(unsupported(format!(
                    "signatureAlgorithm {signature_algorithm:?} is not supported"
                )));
            }
            // An ECDSA `signAlgo` pins a digest; it must equal the configured `hashAlgorithm`.
            if let Some(required) = signature_algorithm.digest()
                && required != params.hash_algorithm
            {
                return Err(unsupported(format!(
                    "signatureAlgorithm {signature_algorithm:?} requires hashAlgorithm {required:?}, but {:?} is configured",
                    params.hash_algorithm
                )));
            }
        }
        Ok(())
    }

    fn validate_document(&self, content: &[u8]) -> Result<(), DocumentSignerError> {
        let ok = match self.params.signature_format {
            SignatureFormat::PAdES => content.starts_with(b"%PDF"),
            // Unreachable: `validate_params` rejects non-PAdES formats at construction.
            SignatureFormat::CAdES | SignatureFormat::XAdES | SignatureFormat::JAdES => false,
        };
        if ok {
            Ok(())
        } else {
            Err(DocumentSignerError::InvalidDocument)
        }
    }

    fn document_hash(&self, content: &[u8]) -> Result<Vec<u8>, DocumentSignerError> {
        self.validate_document(content)?;
        Ok(crate::proto::csc::hash(self.params.hash_algorithm, content))
    }
}

#[async_trait::async_trait]
impl DocumentSigner for Sign8 {
    fn config_name(&self) -> &str {
        &self.config_name
    }

    fn get_capabilities(&self) -> DocumentSignerCapabilities {
        DocumentSignerCapabilities {
            signature_qualifiers: vec![
                SignatureQualifier::EuEidasAes,
                SignatureQualifier::EuEidasQes,
                SignatureQualifier::EuEidasAesEal,
                SignatureQualifier::EuEidasQesEal,
            ],
            signature_formats: vec![SignatureFormat::PAdES],
            conformance_levels: vec![
                ConformanceLevel::AdESBB,
                ConformanceLevel::AdESBT,
                ConformanceLevel::AdESBLT,
            ],
            hash_algorithms: vec![
                HashAlgorithm::Sha256,
                HashAlgorithm::Sha384,
                HashAlgorithm::Sha512,
            ],
            signature_algorithms: vec![
                SignatureAlgorithm::Rsa,
                SignatureAlgorithm::EcdsaSha256,
                SignatureAlgorithm::EcdsaSha384,
                SignatureAlgorithm::EcdsaSha512,
            ],
        }
    }

    async fn get_authorization_request(
        &self,
        request: AuthorizationRequest,
    ) -> Result<Authorization, DocumentSignerError> {
        let hash = self.document_hash(&request.document)?;

        let account_token = sign8::build_account_token(
            &self.params.account_id,
            &self.params.client_id,
            &self.params.client_secret,
            crate::clock::now_utc(),
        )
        .await?;

        let redirect_uri = request
            .redirect_uri
            .as_ref()
            .unwrap_or(&self.params.redirect_uri);

        let authorization = self
            .csc
            .authorization_url(AuthorizationUrlRequest {
                oauth_url: &self.params.oauth_url,
                client_id: &self.params.client_id,
                redirect_uri,
                account_token: &account_token,
                signature_qualifier: self.params.signature_qualifier,
                hash: &hash,
                hash_algorithm: self.params.hash_algorithm,
            })
            .await
            .error_while("building authorization url")?;

        Ok(Authorization {
            authorization_url: authorization.authorization_url,
            code_verifier: authorization.code_verifier,
        })
    }

    async fn sign(&self, request: SignRequest) -> Result<SignedDocument, DocumentSignerError> {
        self.validate_document(&request.document)?;

        let redirect_uri = request
            .redirect_uri
            .as_ref()
            .unwrap_or(&self.params.redirect_uri);

        let token = self
            .csc
            .exchange_code(TokenRequest {
                oauth_url: &self.params.oauth_url,
                code: &request.code,
                client_id: &self.params.client_id,
                client_secret: self.params.client_secret.expose_secret(),
                redirect_uri,
                code_verifier: &request.code_verifier,
            })
            .await
            .error_while("exchanging authorization code")?;

        let result = async {
            let sign_algo = match self.params.signature_algorithm {
                Some(configured) => configured.oid().to_string(),
                None => {
                    let info = self
                        .csc
                        .credential_info(
                            &self.params.csc_base_url,
                            &token.access_token,
                            &token.credential_id,
                        )
                        .await
                        .error_while("retrieving credential info")?;
                    let algorithm = info
                        .signing_algorithm(self.params.hash_algorithm)
                        .ok_or_else(|| {
                            ServiceError::MappingError(format!(
                                "credential exposes no supported signAlgo (key advertised {:?})",
                                info.key.algo
                            ))
                            .error_while("selecting csc signing algorithm")
                        })?;
                    algorithm.oid().to_string()
                }
            };
            self.csc
                .sign_document(SignDocumentRequest {
                    api_url: &self.params.csc_base_url,
                    access_token: &token.access_token,
                    credential_id: &token.credential_id,
                    document: &request.document,
                    sign_algo: &sign_algo,
                    signature_format: self.params.signature_format,
                    conformance_level: self.params.conformance_level,
                })
                .await
                .error_while("signing document")
        }
        .await;

        self.csc
            .revoke_access_token(
                &self.params.oauth_url,
                &token.access_token,
                &self.params.client_id,
                self.params.client_secret.expose_secret(),
            )
            .await;

        Ok(SignedDocument { content: result? })
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use ct_codecs::{Base64, Base64UrlSafeNoPadding, Decoder, Encoder};
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use similar_asserts::assert_eq;
    use url::Url;

    use super::*;
    use crate::proto::csc::{CscClientImpl, MockCscClient};
    use crate::proto::http_client::MockHttpClient;

    fn test_params() -> Sign8Params {
        Sign8Params {
            client_id: "client-123".to_string(),
            client_secret: "super-secret".to_string().into(),
            account_id: "account-456".to_string(),
            csc_base_url: "https://csc.example".to_string(),
            oauth_url: "https://oauth.example".to_string(),
            signature_qualifier: SignatureQualifier::EuEidasQes,
            signature_format: SignatureFormat::PAdES,
            conformance_level: ConformanceLevel::AdESBB,
            hash_algorithm: HashAlgorithm::Sha256,
            signature_algorithm: None,
            redirect_uri: "http://localhost/capture".to_string(),
        }
    }

    fn signer_with(params: Sign8Params) -> Result<Sign8, InitializationError> {
        Sign8::new(
            "SIGN8".to_string(),
            serde_json::to_value(params).unwrap(),
            Arc::new(MockCscClient::new()),
        )
    }

    fn test_signer() -> Sign8 {
        signer_with(test_params()).unwrap()
    }

    fn pdf_request(content: &[u8]) -> AuthorizationRequest {
        AuthorizationRequest {
            document: content.to_vec(),
            redirect_uri: None,
        }
    }

    #[test]
    fn advertises_sign8_capabilities_as_oids() {
        let caps = serde_json::to_value(test_signer().get_capabilities()).unwrap();
        assert_eq!(
            caps["signatureQualifiers"],
            json!([
                "eu_eidas_aes",
                "eu_eidas_qes",
                "eu_eidas_aeseal",
                "eu_eidas_qeseal"
            ])
        );
        assert_eq!(caps["signatureFormats"], json!(["P"]));
        assert_eq!(
            caps["conformanceLevels"],
            json!(["Ades-B-B", "Ades-B-T", "Ades-B-LT"])
        );
        assert_eq!(
            caps["signatureAlgorithms"],
            json!([
                "1.2.840.113549.1.1.1",
                "1.2.840.10045.4.3.2",
                "1.2.840.10045.4.3.3",
                "1.2.840.10045.4.3.4"
            ])
        );
    }

    #[test]
    fn accepts_configuration_within_capabilities() {
        let params = Sign8Params {
            signature_algorithm: Some(SignatureAlgorithm::Rsa),
            hash_algorithm: HashAlgorithm::Sha384,
            ..test_params()
        };
        assert!(signer_with(params).is_ok());
    }

    #[test]
    fn rejects_signature_format_outside_capabilities() {
        let params = Sign8Params {
            signature_format: SignatureFormat::CAdES,
            ..test_params()
        };
        assert!(matches!(
            signer_with(params),
            Err(InitializationError::UnsupportedConfiguration { .. })
        ));
    }

    #[test]
    fn rejects_signature_algorithm_incompatible_with_hash() {
        let params = Sign8Params {
            signature_algorithm: Some(SignatureAlgorithm::EcdsaSha512),
            hash_algorithm: HashAlgorithm::Sha256,
            ..test_params()
        };
        assert!(matches!(
            signer_with(params),
            Err(InitializationError::UnsupportedConfiguration { .. })
        ));
    }

    #[test]
    fn accepts_signature_algorithm_matching_hash() {
        let params = Sign8Params {
            signature_algorithm: Some(SignatureAlgorithm::EcdsaSha512),
            hash_algorithm: HashAlgorithm::Sha512,
            ..test_params()
        };
        assert!(signer_with(params).is_ok());
    }

    #[tokio::test]
    async fn rejects_non_pdf_document() {
        let result = test_signer()
            .get_authorization_request(pdf_request(b"not a pdf"))
            .await;
        assert!(matches!(result, Err(DocumentSignerError::InvalidDocument)));
    }

    #[tokio::test]
    async fn sign_rejects_non_pdf_document() {
        let result = test_signer()
            .sign(SignRequest {
                code: "c".to_string(),
                code_verifier: "v".to_string(),
                redirect_uri: None,
                document: b"not a pdf".to_vec(),
            })
            .await;
        assert!(matches!(result, Err(DocumentSignerError::InvalidDocument)));
    }

    #[tokio::test]
    async fn signs_a_document() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        use crate::proto::http_client::reqwest_client::ReqwestClient;

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth2/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "atok", "credentialID": "cred-1",
                "token_type": "Bearer", "expires_in": 3600
            })))
            .mount(&server)
            .await;
        let signed_b64 = Base64::encode_to_string(b"signed-pdf").unwrap();
        Mock::given(method("POST"))
            .and(path("/csc/v2/signatures/signDoc"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "DocumentWithSignatures": [signed_b64]
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/oauth2/revoke"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;

        let signer = Sign8::new(
            "SIGN8".to_string(),
            serde_json::to_value(Sign8Params {
                csc_base_url: server.uri(),
                oauth_url: server.uri(),
                signature_algorithm: Some(SignatureAlgorithm::Rsa),
                ..test_params()
            })
            .unwrap(),
            Arc::new(CscClientImpl::new(Arc::new(
                ReqwestClient::new(Default::default()).unwrap(),
            ))),
        )
        .unwrap();

        let signed = signer
            .sign(SignRequest {
                code: "c".to_string(),
                code_verifier: "v".to_string(),
                redirect_uri: None,
                document: b"%PDF valid".to_vec(),
            })
            .await
            .unwrap();

        assert_eq!(signed.content, b"signed-pdf");
    }

    #[tokio::test]
    async fn builds_authorization_url_via_csc() {
        const PDF: &[u8] = b"%PDF-1.7 fake pdf content";
        let signer = Sign8::new(
            "SIGN8".to_string(),
            serde_json::to_value(test_params()).unwrap(),
            Arc::new(CscClientImpl::new(Arc::new(MockHttpClient::new()))),
        )
        .unwrap();
        let auth = signer
            .get_authorization_request(pdf_request(PDF))
            .await
            .unwrap();

        let url = Url::parse(&auth.authorization_url).unwrap();
        assert_eq!(url.path(), "/oauth2/authorize");
        let params: HashMap<String, String> = url.query_pairs().into_owned().collect();
        assert_eq!(params["client_id"], "client-123");
        assert_eq!(params["scope"], "credential");
        assert_eq!(params["signatureQualifier"], "eu_eidas_qes");
        assert_eq!(params["hashAlgorithmOID"], "2.16.840.1.101.3.4.2.1");
        assert_eq!(params["redirect_uri"], "http://localhost/capture");

        let expected_hash = Base64UrlSafeNoPadding::encode_to_string(Sha256::digest(PDF)).unwrap();
        assert_eq!(params["hashes"], expected_hash);

        let expected_challenge =
            Base64UrlSafeNoPadding::encode_to_string(Sha256::digest(auth.code_verifier.as_bytes()))
                .unwrap();
        assert_eq!(params["code_challenge"], expected_challenge);

        let payload_bytes = Base64UrlSafeNoPadding::decode_to_vec(
            params["account_token"].split('.').nth(1).unwrap(),
            None,
        )
        .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
        assert_eq!(payload["sub"], "account-456");
        assert_eq!(payload["azp"], "client-123");
    }

    #[tokio::test]
    async fn request_redirect_uri_overrides_the_configured_default() {
        let request = AuthorizationRequest {
            document: b"%PDF-1.7 doc".to_vec(),
            redirect_uri: Some("https://override.example/cb".to_string()),
        };
        let signer = Sign8::new(
            "SIGN8".to_string(),
            serde_json::to_value(test_params()).unwrap(),
            Arc::new(CscClientImpl::new(Arc::new(MockHttpClient::new()))),
        )
        .unwrap();
        let auth = signer.get_authorization_request(request).await.unwrap();

        let url = Url::parse(&auth.authorization_url).unwrap();
        let params: HashMap<String, String> = url.query_pairs().into_owned().collect();
        assert_eq!(params["redirect_uri"], "https://override.example/cb");
    }
}
