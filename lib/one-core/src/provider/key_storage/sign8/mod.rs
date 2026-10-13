use std::sync::Arc;

use async_trait::async_trait;
use one_crypto::Hasher;
use one_crypto::hasher::sha256::SHA256;
use proc_macros::Provider;
use reqwest::Identity;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use shared_types::KeyId;
use standardized_types::csc::{HashAlgorithm, SignatureAlgorithm};
use standardized_types::jwk::PrivateJwk;

use crate::clock::now_utc;
use crate::config::core_config::KeyAlgorithmType;
use crate::error::ContextWithErrorCode;
use crate::mapper::x509::x5c_into_pem_chain;
use crate::model::key::Key;
use crate::proto::certificate_validator::{
    CertificatePurpose, CertificateValidationOptions, CertificateValidator, ParsedCertificate,
};
use crate::proto::csc::CscClient;
use crate::proto::csc::model::{CredentialToken, SignHashesRequest, TokenRequest};
use crate::proto::http_client::HttpClient;
use crate::provider::key_algorithm::ecdsa::EcdsaPublicKeyHandle;
use crate::provider::key_algorithm::key::{
    KeyHandle, KeyHandleError, SignatureKeyHandle, SignaturePrivateKeyHandle,
};
use crate::provider::key_storage::KeyStorage;
use crate::provider::key_storage::error::KeyStorageError;
use crate::provider::key_storage::model::{Features, KeyStorageCapabilities, StorageGeneratedKey};
use crate::provider::provider_directory::InitializationError;
use crate::util::sign8::{AuthorizeTlsRequest, authorize_tls, build_account_token};

#[cfg(test)]
mod test;

#[derive(Clone, Provider)]
pub struct Sign8KeyProvider {
    config_id: String,
    params: Params,
    client: Arc<dyn HttpClient>,
    certificate_validator: Arc<dyn CertificateValidator>,
    csc_client: Arc<dyn CscClient>,
}

impl Sign8KeyProvider {
    pub fn new(
        config_id: String,
        csc_client: Arc<dyn CscClient>,
        client: Arc<dyn HttpClient>,
        certificate_validator: Arc<dyn CertificateValidator>,
        params: serde_json::Value,
    ) -> Result<Self, InitializationError> {
        let params =
            serde_json::from_value(params).map_err(|err| InitializationError::InvalidParams {
                key: config_id.to_string(),
                source: err,
            })?;
        Ok(Self {
            config_id,
            csc_client,
            client,
            certificate_validator,
            params,
        })
    }

    fn mtls_client(&self) -> Result<Arc<dyn HttpClient>, KeyStorageError> {
        let combined_pem: SecretString = format!(
            "{}\n{}",
            self.params.private_key.expose_secret(),
            self.params.certificate
        )
        .into();
        let identity = Identity::from_pem(combined_pem.expose_secret().as_bytes())?;
        let mtls_client = self
            .client
            .with_identity(identity)
            .error_while("creating HTTP client with mTLS auth")?;
        Ok(mtls_client)
    }

    async fn fetch_access_token(
        &self,
        credential_id: &str,
        hashes: Option<&[&[u8]]>,
    ) -> Result<CredentialToken, KeyStorageError> {
        let account_token = build_account_token(
            &self.params.account_id,
            &self.params.client_id,
            &self.params.client_secret,
            now_utc(),
        )
        .await?;
        let auth = authorize_tls(
            &*self.mtls_client()?,
            AuthorizeTlsRequest {
                oauth_url: &self.params.oauth_url,
                redirect_url: Some(&self.params.redirect_url),
                credential_id,
                client_id: &self.params.client_id,
                account_token: &account_token,
                hashes,
            },
        )
        .await?;
        let token = self
            .csc_client
            .exchange_code(TokenRequest {
                oauth_url: &self.params.oauth_url,
                code: &auth.code,
                client_id: &self.params.client_id,
                client_secret: self.params.client_secret.expose_secret(),
                redirect_uri: &self.params.redirect_url,
                code_verifier: &auth.code_verifier,
            })
            .await
            .error_while("exchanging code for token")?;
        Ok(token)
    }

    async fn sign(&self, credential_id: &str, message: &[u8]) -> Result<Vec<u8>, KeyStorageError> {
        let hash = SHA256.hash(message)?;
        let token = self
            .fetch_access_token(credential_id, Some(&[&hash]))
            .await
            .error_while("fetching access token")?;

        let sign_result = self
            .csc_client
            .sign_hash(SignHashesRequest {
                api_url: self.params.csc_base_url.as_str(),
                access_token: &token.access_token,
                credential_id,
                hashes: &[&hash],
                sign_algo: SignatureAlgorithm::EcdsaSha256,
                hash_algo: HashAlgorithm::Sha256,
            })
            .await
            .error_while("signing hash");

        self.csc_client
            .revoke_access_token(
                &self.params.oauth_url,
                &token.access_token,
                &self.params.client_id,
                self.params.client_secret.expose_secret(),
            )
            .await;

        let Some(first) = sign_result?.into_iter().next() else {
            return Err(KeyStorageError::Failed(
                "CSC API returned no signature".to_string(),
            ));
        };
        Ok(first)
    }
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Params {
    pub csc_base_url: String,
    pub oauth_url: String,
    pub redirect_url: String,
    pub account_id: String,
    pub certificate: String,
    pub client_id: String,
    pub client_secret: SecretString,
    pub private_key: SecretString,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GenerateParams {
    pub credential_id: String,
}

#[async_trait::async_trait]
impl KeyStorage for Sign8KeyProvider {
    fn get_capabilities(&self) -> KeyStorageCapabilities {
        KeyStorageCapabilities {
            features: vec![Features::RequiresCredentialId],
            algorithms: vec![KeyAlgorithmType::Ecdsa],
        }
    }

    fn config_name(&self) -> String {
        self.config_id.clone()
    }

    async fn generate(
        &self,
        _key_id: KeyId,
        _key_algorithm: KeyAlgorithmType,
        params: serde_json::Value,
    ) -> Result<StorageGeneratedKey, KeyStorageError> {
        let params = serde_json::from_value::<GenerateParams>(params)?;
        let token = self.fetch_access_token(&params.credential_id, None).await?;

        let info_result = self
            .csc_client
            .credential_info(
                &self.params.csc_base_url,
                &token.access_token,
                &params.credential_id,
            )
            .await;

        self.csc_client
            .revoke_access_token(
                &self.params.oauth_url,
                &token.access_token,
                &self.params.client_id,
                self.params.client_secret.expose_secret(),
            )
            .await;

        let info = info_result.error_while("getting credential info")?;
        let chain = x5c_into_pem_chain(
            &info
                .cert
                .ok_or_else(|| {
                    KeyStorageError::Failed(
                        "missing certificate in CSC credential info".to_string(),
                    )
                })?
                .certificates,
        )
        .error_while("parsing x5c")?;

        let ParsedCertificate { public_key, .. } = self
            .certificate_validator
            .parse_pem_chain(
                &chain,
                CertificateValidationOptions::signature_and_revocation(None)
                    .with_purpose(CertificatePurpose::Issuer),
            )
            .await
            .error_while("parsing PEM chain")?;

        Ok(StorageGeneratedKey {
            public_key: public_key.public_key_as_raw(),
            key_reference: Some(params.credential_id.as_bytes().to_vec()),
        })
    }

    async fn import(
        &self,
        _key_id: KeyId,
        _key_algorithm: KeyAlgorithmType,
        _jwk: PrivateJwk,
    ) -> Result<StorageGeneratedKey, KeyStorageError> {
        Err(KeyStorageError::NotSupported(
            "Not supported by Sign8 key storage".to_string(),
        ))
    }

    fn key_handle(&self, key: &Key) -> Result<KeyHandle, KeyStorageError> {
        let key_reference = key
            .key_reference
            .as_ref()
            .ok_or(KeyStorageError::MissingKeyReference)?;
        let credential_id = String::from_utf8_lossy(key_reference);
        Ok(KeyHandle::SignatureOnly(
            SignatureKeyHandle::WithPrivateKey {
                private: Arc::new(Sign8PrivateKeyHandle {
                    credential_id: credential_id.to_string(),
                    provider: self.clone(),
                }),
                public: Arc::new(EcdsaPublicKeyHandle::new(key.public_key.clone(), None)),
            },
        ))
    }

    async fn generate_attestation_key(
        &self,
        _key_id: KeyId,
        _nonce: Option<String>,
    ) -> Result<StorageGeneratedKey, KeyStorageError> {
        Err(KeyStorageError::NotSupported(
            "Not supported by Sign8 key storage".to_string(),
        ))
    }

    async fn generate_attestation(
        &self,
        _key: &Key,
        _nonce: Option<String>,
    ) -> Result<Vec<String>, KeyStorageError> {
        Err(KeyStorageError::NotSupported(
            "Not supported by Sign8 key storage".to_string(),
        ))
    }

    async fn sign_with_attestation_key(
        &self,
        _key: &Key,
        _data: &[u8],
    ) -> Result<Vec<u8>, KeyStorageError> {
        Err(KeyStorageError::NotSupported(
            "Not supported by Sign8 key storage".to_string(),
        ))
    }
}

#[derive(Clone)]
struct Sign8PrivateKeyHandle {
    credential_id: String,
    provider: Sign8KeyProvider,
}

#[async_trait]
impl SignaturePrivateKeyHandle for Sign8PrivateKeyHandle {
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, KeyHandleError> {
        self.provider
            .sign(&self.credential_id, message)
            .await
            .error_while("signing message")
            .map_err(Into::into)
    }
}
