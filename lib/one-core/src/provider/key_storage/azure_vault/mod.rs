//! Azure Key Vault implementation.

use std::ops::Add;
use std::sync::Arc;

use async_trait::async_trait;
use ct_codecs::{Base64UrlSafeNoPadding, Decoder};
use dto::{AzureHsmGetTokenResponse, AzureHsmKeyResponse, AzureHsmSignResponse};
use mapper::{
    create_generate_key_request, create_get_token_request, create_sign_request,
    public_key_from_components,
};
use one_crypto::signer::ecdsa::ECDSASigner;
use one_crypto::{CryptoProvider, Signer, SignerError};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use shared_types::KeyId;
use standardized_types::jwk::{PrivateJwk, PublicJwk};
use time::{Duration, OffsetDateTime};
use tokio::sync::Mutex;
use url::Url;
use uuid::Uuid;

use crate::config::core_config::KeyAlgorithmType;
use crate::error::ContextWithErrorCode;
use crate::model::key::{Key, PrivateJwkExt};
use crate::proto::http_client::HttpClient;
use crate::provider::key_algorithm::ecdsa::{
    ecdsa_public_key_as_jwk, ecdsa_public_key_as_multibase,
};
use crate::provider::key_algorithm::key::{
    KeyHandle, KeyHandleError, SignatureKeyHandle, SignaturePrivateKeyHandle,
    SignaturePublicKeyHandle,
};
use crate::provider::key_storage::KeyStorage;
use crate::provider::key_storage::azure_vault::dto::{
    AzureHsmGenerateKeyRequest, AzureHsmImportKeyRequest, AzureHsmSignRequest,
};
use crate::provider::key_storage::azure_vault::mapper::create_import_key_request;
use crate::provider::key_storage::error::KeyStorageError;
use crate::provider::key_storage::model::{Features, KeyStorageCapabilities, StorageGeneratedKey};

mod dto;
mod mapper;

#[cfg(test)]
mod test;

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Params {
    pub ad_tenant_id: Uuid,
    pub client_id: Uuid,
    pub client_secret: String,
    pub oauth_service_url: Url,
    pub vault_url: Url,
}

struct AzureAccessToken {
    pub token: SecretString,
    pub valid_until: OffsetDateTime,
}

pub struct AzureVaultKeyProvider {
    crypto: Arc<dyn CryptoProvider>,
    azure_client: Arc<AzureClient>,
}

#[async_trait]
impl KeyStorage for AzureVaultKeyProvider {
    fn get_capabilities(&self) -> KeyStorageCapabilities {
        KeyStorageCapabilities {
            features: vec![Features::Exportable, Features::Importable],
            algorithms: vec![KeyAlgorithmType::Ecdsa],
        }
    }

    async fn generate(
        &self,
        key_id: KeyId,
        key_type: KeyAlgorithmType,
    ) -> Result<StorageGeneratedKey, KeyStorageError> {
        if !self.get_capabilities().algorithms.contains(&key_type) {
            return Err(KeyStorageError::UnsupportedKeyType {
                key_type: key_type.to_string(),
            });
        }

        let response = self
            .azure_client
            .generate_key(key_id, create_generate_key_request())
            .await?;

        let public_key_bytes = public_key_from_components(&response.key)?;

        let public_key = ECDSASigner::parse_public_key(&public_key_bytes, true)?;

        Ok(StorageGeneratedKey {
            public_key,
            key_reference: Some(response.key.key_id.as_bytes().to_vec()),
        })
    }

    async fn import(
        &self,
        key_id: KeyId,
        key_type: KeyAlgorithmType,
        jwk: PrivateJwk,
    ) -> Result<StorageGeneratedKey, KeyStorageError> {
        if !self
            .get_capabilities()
            .features
            .contains(&Features::Importable)
        {
            return Err(KeyStorageError::UnsupportedFeature {
                feature: Features::Importable,
            });
        }
        if !self.get_capabilities().algorithms.contains(&key_type) {
            return Err(KeyStorageError::UnsupportedKeyType {
                key_type: key_type.to_string(),
            });
        };
        if jwk.supported_key_type() != key_type {
            return Err(KeyStorageError::InvalidKeyAlgorithm(key_type.to_string()));
        };

        let response = self
            .azure_client
            .import_key(key_id, create_import_key_request(jwk)?)
            .await?;

        let public_key_bytes = public_key_from_components(&response.key)?;

        let public_key = ECDSASigner::parse_public_key(&public_key_bytes, true)?;

        Ok(StorageGeneratedKey {
            public_key,
            key_reference: Some(response.key.key_id.as_bytes().to_vec()),
        })
    }

    fn key_handle(&self, key: &Key) -> Result<KeyHandle, KeyStorageError> {
        let handle =
            AzureVaultKeyHandle::new(key.clone(), self.crypto.clone(), self.azure_client.clone());

        Ok(KeyHandle::SignatureOnly(
            SignatureKeyHandle::WithPrivateKey {
                private: Arc::new(handle.clone()),
                public: Arc::new(handle),
            },
        ))
    }

    async fn generate_attestation_key(
        &self,
        _key_id: KeyId,
        _nonce: Option<String>,
    ) -> Result<StorageGeneratedKey, KeyStorageError> {
        return Err(KeyStorageError::UnsupportedFeature {
            feature: Features::Attestation,
        });
    }

    async fn generate_attestation(
        &self,
        _key: &Key,
        _nonce: Option<String>,
    ) -> Result<Vec<String>, KeyStorageError> {
        return Err(KeyStorageError::UnsupportedFeature {
            feature: Features::Attestation,
        });
    }

    async fn sign_with_attestation_key(
        &self,
        _key: &Key,
        _data: &[u8],
    ) -> Result<Vec<u8>, KeyStorageError> {
        return Err(KeyStorageError::UnsupportedFeature {
            feature: Features::Attestation,
        });
    }
}

impl AzureVaultKeyProvider {
    pub fn new(
        params: Params,
        crypto: Arc<dyn CryptoProvider>,
        client: Arc<dyn HttpClient>,
    ) -> Self {
        Self {
            crypto,
            azure_client: Arc::new(AzureClient {
                access_token: Arc::new(Mutex::new(None)),
                client,
                params,
            }),
        }
    }
}
#[derive(Clone)]
struct AzureVaultKeyHandle {
    key: Key,
    crypto: Arc<dyn CryptoProvider>,
    azure_client: Arc<AzureClient>,
}

impl AzureVaultKeyHandle {
    fn new(key: Key, crypto: Arc<dyn CryptoProvider>, azure_client: Arc<AzureClient>) -> Self {
        Self {
            key,
            crypto,
            azure_client,
        }
    }
}

impl SignaturePublicKeyHandle for AzureVaultKeyHandle {
    fn as_jwk(&self) -> Result<PublicJwk, KeyHandleError> {
        ecdsa_public_key_as_jwk(&self.key.public_key, None)
    }

    fn as_multibase(&self) -> Result<String, KeyHandleError> {
        ecdsa_public_key_as_multibase(&self.key.public_key)
    }

    fn as_raw(&self) -> Vec<u8> {
        self.key.public_key.clone()
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), KeyHandleError> {
        Ok(ECDSASigner.verify(message, signature, &self.key.public_key)?)
    }
}

#[async_trait]
impl SignaturePrivateKeyHandle for AzureVaultKeyHandle {
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, KeyHandleError> {
        let key_reference = self
            .key
            .key_reference
            .as_ref()
            .ok_or(SignerError::MissingKey)
            .map(ToOwned::to_owned)
            .map(String::from_utf8)?
            .map_err(|e| SignerError::CouldNotSign(e.to_string()))?;

        let sign_request = create_sign_request(message, self.crypto.clone())?;

        let response = self.azure_client.sign(key_reference, sign_request).await?;

        let decoded = Base64UrlSafeNoPadding::decode_to_vec(response.value, None)
            .map_err(|e| SignerError::CouldNotSign(e.to_string()))?;

        Ok(decoded)
    }
}

struct AzureClient {
    access_token: Arc<Mutex<Option<AzureAccessToken>>>,
    client: Arc<dyn HttpClient>,
    params: Params,
}

impl AzureClient {
    async fn acquire_new_token(&self) -> Result<AzureHsmGetTokenResponse, KeyStorageError> {
        let request = create_get_token_request(
            &self.params.client_id.to_string(),
            &self.params.client_secret,
        );

        let mut url = self.params.oauth_service_url.clone();
        url.set_path(&format!("{}/oauth2/v2.0/token", self.params.ad_tenant_id));

        let response: AzureHsmGetTokenResponse = async {
            self.client
                .post(url.as_str())
                .form(&request)?
                .send()
                .await?
                .error_for_status()?
                .json()
        }
        .await
        .error_while("fetching azure token")?;

        if response.token_type != "Bearer" {
            return Err(KeyStorageError::Failed(format!(
                "Unknown AzureHSM token type: '{}'",
                response.token_type
            )));
        }

        Ok(response)
    }

    async fn get_access_token(&self) -> Result<SecretString, KeyStorageError> {
        if self.is_token_valid().await {
            Ok(self
                .access_token
                .lock()
                .await
                .as_ref()
                .ok_or(KeyStorageError::Failed("token is None".to_string()))?
                .token
                .to_owned())
        } else {
            // todo: should this be atomic? (here multiple requests are all going to acquire a new token and set the new token)
            let response = self.acquire_new_token().await?;
            let valid_until = OffsetDateTime::now_utc().add(Duration::seconds(response.expires_in));
            let mut storage = self.access_token.lock().await;
            *storage = Some(AzureAccessToken {
                token: response.access_token.clone(),
                valid_until,
            });
            Ok(response.access_token)
        }
    }

    pub async fn is_token_valid(&self) -> bool {
        let azure_access_token = self.access_token.lock().await;

        match azure_access_token.as_ref() {
            None => false,
            Some(token) => {
                // Adding 5 seconds tolerance for network requests delay
                token.valid_until > OffsetDateTime::now_utc().add(Duration::seconds(5))
            }
        }
    }

    async fn generate_key(
        &self,
        key_id: KeyId,
        request: AzureHsmGenerateKeyRequest,
    ) -> Result<AzureHsmKeyResponse, KeyStorageError> {
        let access_token = self.get_access_token().await?;

        let mut url = self.params.vault_url.clone();
        url.set_path(&format!("keys/{key_id}/create"));
        url.set_query(Some("api-version=7.4"));

        let response = async {
            self.client
                .post(url.as_str())
                .bearer_auth(access_token.expose_secret())
                .json(request)?
                .send()
                .await?
                .error_for_status()?
                .json()
        }
        .await
        .error_while("requesting azure key")?;
        Ok(response)
    }

    async fn import_key(
        &self,
        key_id: KeyId,
        request: AzureHsmImportKeyRequest,
    ) -> Result<AzureHsmKeyResponse, KeyStorageError> {
        let access_token = self.get_access_token().await?;

        let mut url = self.params.vault_url.clone();
        url.set_path(&format!("keys/{key_id}"));
        url.set_query(Some("api-version=7.4"));

        let response = async {
            self.client
                .put(url.as_str())
                .bearer_auth(access_token.expose_secret())
                .json(request)?
                .send()
                .await?
                .error_for_status()?
                .json()
        }
        .await
        .error_while("importing azure key")?;
        Ok(response)
    }

    // key_reference is on format of URL e.g. https://one-dev.vault.azure.net/keys/df7d293c-3480-4e85-b176-851fb79b4564/808094a3790b4032ad4d01968a510cbd
    async fn sign(
        &self,
        key_reference: String,
        request: AzureHsmSignRequest,
    ) -> Result<AzureHsmSignResponse, SignerError> {
        let access_token = self
            .get_access_token()
            .await
            .map_err(|e| SignerError::CouldNotSign(e.to_string()))?;

        let mut url = Url::parse(format!("{key_reference}/sign").as_str())
            .map_err(|e| SignerError::CouldNotSign(e.to_string()))?;
        url.set_query(Some("api-version=7.4"));
        let response: AzureHsmSignResponse = self
            .client
            .post(url.as_str())
            .bearer_auth(access_token.expose_secret())
            .json(request)
            .map_err(|e| SignerError::CouldNotSign(e.to_string()))?
            .send()
            .await
            .map_err(|e| SignerError::CouldNotSign(e.to_string()))?
            .error_for_status()
            .map_err(|e| SignerError::CouldNotSign(e.to_string()))?
            .json()
            .map_err(|e| SignerError::CouldNotSign(e.to_string()))?;
        Ok(response)
    }
}
