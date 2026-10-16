//! Remote signing through a CSC (Cloud Signature Consortium) v2 service.

use std::sync::Arc;

use async_trait::async_trait;
use one_crypto::Hasher;
use one_crypto::hasher::sha256::SHA256;
use proc_macros::Provider;
use reqwest::Identity;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use shared_types::KeyId;
use standardized_types::csc::{CredentialInfoResponse, HashAlgorithm, SignatureAlgorithm};
use standardized_types::jwk::PrivateJwk;

use crate::config::core_config::KeyAlgorithmType;
use crate::error::ContextWithErrorCode;
use crate::mapper::x509::x5c_into_pem_chain;
use crate::model::key::Key;
use crate::proto::certificate_validator::{
    CertificatePurpose, CertificateValidationOptions, CertificateValidator, ParsedCertificate,
};
use crate::proto::csc::model::SignHashesRequest;
use crate::proto::csc::{CscClient, CscClientImpl};
use crate::proto::http_client::HttpClient;
use crate::provider::key_algorithm::ecdsa::EcdsaPublicKeyHandle;
use crate::provider::key_algorithm::key::{
    KeyHandle, KeyHandleError, SignatureKeyHandle, SignaturePrivateKeyHandle,
};
use crate::provider::key_storage::KeyStorage;
use crate::provider::key_storage::error::KeyStorageError;
use crate::provider::key_storage::model::{Features, KeyStorageCapabilities, StorageGeneratedKey};
use crate::provider::provider_directory::InitializationError;

mod oauth2_client;
mod sign8_tls;
#[cfg(test)]
mod test;

#[async_trait]
trait CredentialAuthorization: Send + Sync {
    fn features(&self) -> Vec<Features> {
        vec![]
    }

    async fn authorize_lookup(
        &self,
        csc_client: &dyn CscClient,
        generate_params: serde_json::Value,
    ) -> Result<(String, Option<String>), KeyStorageError>;

    async fn authorize_signing(
        &self,
        csc_client: &dyn CscClient,
        credential_id: &str,
        hash: &[u8],
    ) -> Result<String, KeyStorageError>;

    async fn release(&self, _csc_client: &dyn CscClient, _access_token: &str) {}
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Params {
    csc_base_url: String,
    sign_hash_base_url: Option<String>,
    certificate: String,
    private_key: SecretString,
    #[serde(flatten)]
    auth: AuthParams,
}

#[derive(Deserialize)]
#[serde(tag = "auth")]
enum AuthParams {
    #[serde(rename = "SIGN8_TLS")]
    Sign8Tls(sign8_tls::Sign8Tls),
    #[serde(rename = "OAUTH2_CLIENT")]
    Oauth2Client(oauth2_client::Params),
}

#[derive(Clone, Provider)]
pub(crate) struct CscKeyProvider {
    config_id: String,
    csc_base_url: String,
    sign_hash_base_url: String,
    certificate: String,
    private_key: SecretString,
    auth: Arc<dyn CredentialAuthorization>,
    client: Arc<dyn HttpClient>,
    certificate_validator: Arc<dyn CertificateValidator>,
}

impl CscKeyProvider {
    pub(crate) fn new(
        config_id: String,
        client: Arc<dyn HttpClient>,
        certificate_validator: Arc<dyn CertificateValidator>,
        params: serde_json::Value,
    ) -> Result<Self, InitializationError> {
        let Params {
            csc_base_url,
            sign_hash_base_url,
            certificate,
            private_key,
            auth,
        } = serde_json::from_value(params).map_err(|source| {
            InitializationError::InvalidParams {
                key: config_id.clone(),
                source,
            }
        })?;

        let auth: Arc<dyn CredentialAuthorization> = match auth {
            AuthParams::Sign8Tls(auth) => Arc::new(auth),
            AuthParams::Oauth2Client(params) => Arc::new(oauth2_client::Oauth2Client::new(
                params,
                private_key.clone(),
            )),
        };
        Ok(Self {
            config_id,
            sign_hash_base_url: sign_hash_base_url.unwrap_or_else(|| csc_base_url.clone()),
            csc_base_url,
            certificate,
            private_key,
            auth,
            client,
            certificate_validator,
        })
    }

    fn csc_client(&self) -> Result<CscClientImpl, KeyStorageError> {
        let pem: SecretString =
            format!("{}\n{}", self.private_key.expose_secret(), self.certificate).into();
        let identity = Identity::from_pem(pem.expose_secret().as_bytes())?;
        let client = self
            .client
            .with_identity(identity)
            .error_while("creating HTTP client with mTLS auth")?;
        Ok(CscClientImpl::new(client))
    }

    async fn credential(
        &self,
        csc_client: &dyn CscClient,
        access_token: &str,
        credential_id: Option<String>,
    ) -> Result<(String, CredentialInfoResponse), KeyStorageError> {
        let (credential_id, info) = match credential_id {
            Some(credential_id) => {
                let info = csc_client
                    .credential_info(&self.csc_base_url, access_token, &credential_id)
                    .await
                    .error_while("getting credential info")?;
                (credential_id, info)
            }
            None => {
                let credentials = csc_client
                    .credential_list(&self.csc_base_url, access_token)
                    .await
                    .error_while("listing credentials")?;
                let [credential] = <[_; 1]>::try_from(credentials).map_err(|credentials| {
                    KeyStorageError::Failed(format!(
                        "expected one CSC credential, found {}",
                        credentials.len()
                    ))
                })?;
                (credential.credential_id, credential.info)
            }
        };
        if info.signing_algorithm(HashAlgorithm::Sha256) != Some(SignatureAlgorithm::EcdsaSha256) {
            return Err(KeyStorageError::UnsupportedKeyType {
                key_type: info.key.algo.join(", "),
            });
        }
        Ok((credential_id, info))
    }

    async fn sign(&self, credential_id: &str, message: &[u8]) -> Result<Vec<u8>, KeyStorageError> {
        let hash = SHA256.hash(message)?;
        let csc_client = self.csc_client()?;
        let token = self
            .auth
            .authorize_signing(&csc_client, credential_id, &hash)
            .await?;

        let sign_result = csc_client
            .sign_hash(SignHashesRequest {
                api_url: self.sign_hash_base_url.as_str(),
                access_token: &token,
                credential_id,
                hashes: &[&hash],
                sign_algo: SignatureAlgorithm::EcdsaSha256,
                hash_algo: HashAlgorithm::Sha256,
            })
            .await
            .error_while("signing hash");

        self.auth.release(&csc_client, &token).await;

        let Some(first) = sign_result?.into_iter().next() else {
            return Err(KeyStorageError::Failed(
                "CSC API returned no signature".to_string(),
            ));
        };
        Ok(first)
    }
}

#[async_trait]
impl KeyStorage for CscKeyProvider {
    fn get_capabilities(&self) -> KeyStorageCapabilities {
        KeyStorageCapabilities {
            features: self.auth.features(),
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
        let csc_client = self.csc_client()?;
        let (token, credential_id) = self.auth.authorize_lookup(&csc_client, params).await?;

        let credential = self.credential(&csc_client, &token, credential_id).await;

        self.auth.release(&csc_client, &token).await;

        let (credential_id, info) = credential?;
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
            key_reference: Some(credential_id.into_bytes()),
        })
    }

    async fn import(
        &self,
        _key_id: KeyId,
        _key_algorithm: KeyAlgorithmType,
        _jwk: PrivateJwk,
    ) -> Result<StorageGeneratedKey, KeyStorageError> {
        Err(KeyStorageError::NotSupported(
            "Not supported by CSC key storage".to_string(),
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
                private: Arc::new(CscPrivateKeyHandle {
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
            "Not supported by CSC key storage".to_string(),
        ))
    }

    async fn generate_attestation(
        &self,
        _key: &Key,
        _nonce: Option<String>,
    ) -> Result<Vec<String>, KeyStorageError> {
        Err(KeyStorageError::NotSupported(
            "Not supported by CSC key storage".to_string(),
        ))
    }

    async fn sign_with_attestation_key(
        &self,
        _key: &Key,
        _data: &[u8],
    ) -> Result<Vec<u8>, KeyStorageError> {
        Err(KeyStorageError::NotSupported(
            "Not supported by CSC key storage".to_string(),
        ))
    }
}

#[derive(Clone)]
struct CscPrivateKeyHandle {
    credential_id: String,
    provider: CscKeyProvider,
}

#[async_trait]
impl SignaturePrivateKeyHandle for CscPrivateKeyHandle {
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, KeyHandleError> {
        self.provider
            .sign(&self.credential_id, message)
            .await
            .error_while("signing message")
            .map_err(Into::into)
    }
}
