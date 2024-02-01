use std::ops::Add;
use std::sync::Arc;

use ct_codecs::{Base64UrlSafeNoPadding, Decoder};
use serde::Deserialize;
use time::{Duration, OffsetDateTime};
use tokio::sync::Mutex;
use url::Url;
use uuid::Uuid;

use dto::{AzureHsmGenerateKeyResponse, AzureHsmSignResponse};
use mapper::{
    create_generate_key_request, create_get_token_request, create_sign_request,
    public_key_from_components,
};

use crate::{
    crypto::{
        signer::{error::SignerError, es256::ES256Signer},
        CryptoProvider,
    },
    model::key::{Key, KeyId},
    provider::{
        key_storage::{
            azure_vault::dto::AzureHsmGetTokenResponse, GeneratedKey, KeyStorage,
            KeyStorageCapabilities,
        },
        transport_protocol::TransportProtocolError,
    },
    service::error::{ServiceError, ValidationError},
};

mod dto;
mod mapper;

#[derive(Deserialize)]
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
    access_token: Arc<Mutex<Option<AzureAccessToken>>>,
    client: reqwest::Client,
    crypto: Arc<dyn CryptoProvider>,
    params: Params,
}

#[async_trait::async_trait]
impl KeyStorage for AzureVaultKeyProvider {
    async fn generate(&self, key_id: &KeyId, key_type: &str) -> Result<GeneratedKey, ServiceError> {
        if key_type != "ES256" {
            return Err(ValidationError::UnsupportedKeyType {
                key_type: key_type.to_owned(),
            }
            .into());
        }

        let access_token = self.get_access_token().await?;

        let mut url = self.params.vault_url.clone();
        url.set_path(&format!("keys/{}/create", key_id));
        url.set_query(Some("api-version=7.4"));

        let response: AzureHsmGenerateKeyResponse = self
            .client
            .post(url)
            .json(&create_generate_key_request())
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(TransportProtocolError::HttpRequestError)?
            .error_for_status()
            .map_err(TransportProtocolError::HttpRequestError)?
            .json()
            .await
            .map_err(TransportProtocolError::HttpRequestError)?;

        let public_key_bytes = public_key_from_components(&response.key)?;

        let public_key = ES256Signer::to_bytes(&public_key_bytes)
            .map_err(|err| ServiceError::Other(format!("failed to build public key: {err}")))?;

        Ok(GeneratedKey {
            public_key,
            key_reference: response.key.key_id.as_bytes().to_vec(),
        })
    }

    async fn sign(&self, key: &Key, message: &[u8]) -> Result<Vec<u8>, SignerError> {
        let key_reference = String::from_utf8(key.key_reference.to_owned())
            .map_err(|e| SignerError::CouldNotSign(e.to_string()))?;
        let url = Url::parse(&format!("{key_reference}/sign?api-version=7.4"))
            .map_err(|e| SignerError::CouldNotSign(e.to_string()))?;
        let sign_request = create_sign_request(message, self.crypto.clone())?;

        let access_token = self
            .get_access_token()
            .await
            .map_err(|e| SignerError::CouldNotSign(e.to_string()))?;

        let parsed: AzureHsmSignResponse = self
            .client
            .post(url)
            .json(&sign_request)
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| SignerError::CouldNotSign(e.to_string()))?
            .error_for_status()
            .map_err(|e| SignerError::CouldNotSign(e.to_string()))?
            .json()
            .await
            .map_err(|e| SignerError::CouldNotSign(e.to_string()))?;

        let decoded = Base64UrlSafeNoPadding::decode_to_vec(parsed.value, None)
            .map_err(|e| SignerError::CouldNotSign(e.to_string()))?;

        Ok(decoded)
    }

    fn get_capabilities(&self) -> KeyStorageCapabilities {
        KeyStorageCapabilities {
            algorithms: vec!["ES256".to_string()],
            security: vec!["HARDWARE".to_string()],
        }
    }
}

impl AzureVaultKeyProvider {
    pub fn new(params: Params, crypto: Arc<dyn CryptoProvider>) -> Self {
        Self {
            access_token: Arc::new(Mutex::new(None)),
            client: reqwest::Client::new(),
            crypto,
            params,
        }
    }

    async fn acquire_new_token(&self) -> Result<AzureHsmGetTokenResponse, ServiceError> {
        let request = create_get_token_request(
            &self.params.client_id.to_string(),
            &self.params.client_secret,
        );

        let mut url = self.params.oauth_service_url.clone();
        url.set_path(&format!("{}/oauth2/v2.0/token", self.params.ad_tenant_id));

        let response: AzureHsmGetTokenResponse = self
            .client
            .post(url)
            .form(&request)
            .send()
            .await
            .map_err(TransportProtocolError::HttpRequestError)?
            .error_for_status()
            .map_err(TransportProtocolError::HttpRequestError)?
            .json()
            .await
            .map_err(TransportProtocolError::HttpResponse)?;

        if response.token_type != "Bearer" {
            return Err(ServiceError::Other(format!(
                "Unknown AzureHSM token type: '{}'",
                response.token_type
            )));
        }

        Ok(response)
    }

    async fn get_access_token(&self) -> Result<String, ServiceError> {
        if self.is_token_valid().await {
            Ok(self
                .access_token
                .lock()
                .await
                .as_ref()
                .ok_or(ServiceError::MappingError("token is None".to_string()))?
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

    async fn is_token_valid(&self) -> bool {
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
