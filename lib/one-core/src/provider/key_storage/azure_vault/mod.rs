//! Azure Key Vault implementation.

use std::ops::Add;
use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use ct_codecs::{Base64UrlSafeNoPadding, Decoder};
use dto::{AzureHsmGenerateKeyResponse, AzureHsmGetTokenResponse, AzureHsmSignResponse};
use mapper::{
    create_generate_key_request, create_get_token_request, create_sign_request,
    public_key_from_components,
};
use one_crypto::signer::es256::ES256Signer;
use one_crypto::{CryptoProvider, Signer, SignerError};
use serde::Deserialize;
use shared_types::KeyId;
use time::{Duration, OffsetDateTime};
use tokio::sync::Mutex;
use url::Url;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::model::key::{Key, PublicKeyJwk};
use crate::provider::http_client::HttpClient;
use crate::provider::key_algorithm::key::{
    KeyHandle, KeyHandleError, SignatureKeyHandle, SignaturePrivateKeyHandle,
    SignaturePublicKeyHandle,
};
use crate::provider::key_storage::error::KeyStorageError;
use crate::provider::key_storage::model::{
    Features, KeySecurity, KeyStorageCapabilities, StorageGeneratedKey,
};
use crate::provider::key_storage::KeyStorage;
use crate::provider::key_utils::{es256_public_key_as_jwk, es256_public_key_as_multibase};

mod dto;
mod mapper;

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
    pub token: String,
    pub valid_until: OffsetDateTime,
}

pub struct AzureVaultKeyProvider {
    client: Arc<dyn HttpClient>,
    crypto: Arc<dyn CryptoProvider>,
    fetcher: Arc<AzureTokenFetcher>,
    params: Params,
}

#[async_trait]
impl KeyStorage for AzureVaultKeyProvider {
    fn get_capabilities(&self) -> KeyStorageCapabilities {
        KeyStorageCapabilities {
            features: vec![Features::Exportable],
            algorithms: vec!["ES256".to_string()],
            security: vec![KeySecurity::RemoteSecureElement],
        }
    }

    async fn generate(
        &self,
        key_id: KeyId,
        key_type: &str,
    ) -> Result<StorageGeneratedKey, KeyStorageError> {
        if !self
            .get_capabilities()
            .algorithms
            .contains(&key_type.to_string())
        {
            return Err(KeyStorageError::UnsupportedKeyType {
                key_type: key_type.to_owned(),
            });
        }

        let access_token = self.fetcher.get_access_token().await?;

        let mut url = self.params.vault_url.clone();
        url.set_path(&format!("keys/{}/create", key_id));
        url.set_query(Some("api-version=7.4"));

        let response: AzureHsmGenerateKeyResponse = self
            .client
            .post(url.as_str())
            .bearer_auth(&access_token)
            .json(create_generate_key_request())
            .context("json error")
            .map_err(KeyStorageError::Transport)?
            .send()
            .await
            .context("send error")
            .map_err(KeyStorageError::Transport)?
            .error_for_status()
            .context("status error")
            .map_err(KeyStorageError::Transport)?
            .json()
            .context("parsing error")
            .map_err(KeyStorageError::Transport)?;

        let public_key_bytes = public_key_from_components(&response.key)?;

        let public_key = ES256Signer::parse_public_key(&public_key_bytes, true)
            .map_err(|err| KeyStorageError::Failed(format!("failed to build public key: {err}")))?;

        Ok(StorageGeneratedKey {
            public_key,
            key_reference: response.key.key_id.as_bytes().to_vec(),
        })
    }

    fn key_handle(&self, key: &Key) -> Result<KeyHandle, SignerError> {
        let handle = AzureVaultKeyHandle::new(
            key.clone(),
            self.client.clone(),
            self.crypto.clone(),
            self.fetcher.clone(),
        );

        Ok(KeyHandle::SignatureOnly(
            SignatureKeyHandle::WithPrivateKey {
                private: Arc::new(handle.clone()),
                public: Arc::new(handle),
            },
        ))
    }
}

impl AzureVaultKeyProvider {
    pub fn new(
        params: Params,
        crypto: Arc<dyn CryptoProvider>,
        client: Arc<dyn HttpClient>,
    ) -> Self {
        Self {
            client: client.clone(),
            crypto,
            fetcher: Arc::new(AzureTokenFetcher {
                access_token: Arc::new(Mutex::new(None)),
                client,
                params: params.clone(),
            }),
            params,
        }
    }
}

struct AzureTokenFetcher {
    access_token: Arc<Mutex<Option<AzureAccessToken>>>,
    client: Arc<dyn HttpClient>,
    params: Params,
}

impl AzureTokenFetcher {
    async fn acquire_new_token(&self) -> Result<AzureHsmGetTokenResponse, KeyStorageError> {
        let request = create_get_token_request(
            &self.params.client_id.to_string(),
            &self.params.client_secret,
        );

        let mut url = self.params.oauth_service_url.clone();
        url.set_path(&format!("{}/oauth2/v2.0/token", self.params.ad_tenant_id));

        let response: AzureHsmGetTokenResponse = self
            .client
            .post(url.as_str())
            .form(&request)
            .context("form error")
            .map_err(KeyStorageError::Transport)?
            .send()
            .await
            .context("send error")
            .map_err(KeyStorageError::Transport)?
            .error_for_status()
            .context("status error")
            .map_err(KeyStorageError::Transport)?
            .json()
            .context("parsing error")
            .map_err(KeyStorageError::Transport)?;

        if response.token_type != "Bearer" {
            return Err(KeyStorageError::Failed(format!(
                "Unknown AzureHSM token type: '{}'",
                response.token_type
            )));
        }

        Ok(response)
    }

    async fn get_access_token(&self) -> Result<String, KeyStorageError> {
        if self.is_token_valid().await {
            Ok(self
                .access_token
                .lock()
                .await
                .as_ref()
                .ok_or(KeyStorageError::MappingError("token is None".to_string()))?
                .token
                .to_owned())
        } else {
            // todo: should this be atomic? (here multiple requests are all going to acquire a new token and set the new token)
            let response = self.acquire_new_token().await?;
            let valid_until = OffsetDateTime::now_utc().add(Duration::seconds(response.expires_in));
            let mut storage = self.access_token.lock().await;
            *storage = Some(AzureAccessToken {
                token: response.access_token.to_owned(),
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
}

#[cfg(test)]
mod test;

#[derive(Clone)]
struct AzureVaultKeyHandle {
    key: Key,
    client: Arc<dyn HttpClient>,
    crypto: Arc<dyn CryptoProvider>,
    fetcher: Arc<AzureTokenFetcher>,
}

impl AzureVaultKeyHandle {
    fn new(
        key: Key,
        client: Arc<dyn HttpClient>,
        crypto: Arc<dyn CryptoProvider>,
        fetcher: Arc<AzureTokenFetcher>,
    ) -> Self {
        Self {
            key,
            client,
            crypto,
            fetcher,
        }
    }
}

impl SignaturePublicKeyHandle for AzureVaultKeyHandle {
    fn as_jwk(&self) -> Result<PublicKeyJwk, KeyHandleError> {
        es256_public_key_as_jwk(&self.key.public_key, None)
    }

    fn as_multibase(&self) -> Result<String, KeyHandleError> {
        es256_public_key_as_multibase(&self.key.public_key)
    }

    fn as_raw(&self) -> Vec<u8> {
        self.key.public_key.clone()
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), SignerError> {
        ES256Signer {}.verify(message, signature, &self.key.public_key)
    }
}

#[async_trait]
impl SignaturePrivateKeyHandle for AzureVaultKeyHandle {
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignerError> {
        let key_reference = String::from_utf8(self.key.key_reference.to_owned())
            .map_err(|e| SignerError::CouldNotSign(e.to_string()))?;
        let url = Url::parse(&format!("{key_reference}/sign?api-version=7.4"))
            .map_err(|e| SignerError::CouldNotSign(e.to_string()))?;
        let sign_request = create_sign_request(message, self.crypto.clone())?;

        let access_token = self
            .fetcher
            .get_access_token()
            .await
            .map_err(|e| SignerError::CouldNotSign(e.to_string()))?;

        let parsed: AzureHsmSignResponse = self
            .client
            .post(url.as_str())
            .bearer_auth(&access_token)
            .json(&sign_request)
            .map_err(|e| SignerError::CouldNotSign(e.to_string()))?
            .send()
            .await
            .map_err(|e| SignerError::CouldNotSign(e.to_string()))?
            .error_for_status()
            .map_err(|e| SignerError::CouldNotSign(e.to_string()))?
            .json()
            .map_err(|e| SignerError::CouldNotSign(e.to_string()))?;

        let decoded = Base64UrlSafeNoPadding::decode_to_vec(parsed.value, None)
            .map_err(|e| SignerError::CouldNotSign(e.to_string()))?;

        Ok(decoded)
    }

    fn as_jwk(&self) -> Result<Zeroizing<String>, KeyHandleError> {
        Err(KeyHandleError::EncodingPrivateJwk(
            "unsupported storage type".to_string(),
        ))
    }
}
