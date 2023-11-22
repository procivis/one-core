use age::secrecy::Secret;
use serde::Deserialize;
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tokio_util::compat::FuturesAsyncWriteCompatExt;

use crate::crypto::signer::error::SignerError;
use crate::model::key::Key;
use crate::{
    provider::{
        key_algorithm::{provider::KeyAlgorithmProvider, GeneratedKey},
        key_storage::KeyStorage,
    },
    service::error::ServiceError,
};

pub struct InternalKeyProvider {
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider + Send + Sync>,
    params: Params,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Params {
    encryption: Option<String>,
}

impl InternalKeyProvider {
    pub fn new(
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider + Send + Sync>,
        params: Params,
    ) -> Self {
        Self {
            key_algorithm_provider,
            params,
        }
    }
}

#[async_trait::async_trait]
impl KeyStorage for InternalKeyProvider {
    async fn sign(&self, key: &Key, message: &str) -> Result<Vec<u8>, SignerError> {
        let signer = self
            .key_algorithm_provider
            .get_signer(&key.key_type)
            .map_err(|e| SignerError::MissingAlgorithm(e.to_string()))?;

        let passphrase = self.params.encryption.as_ref();
        let private_key = decrypt_if_password_is_provided(&key.private_key, passphrase)
            .await
            .map_err(|_| SignerError::CouldNotExtractKeyPair)?;

        signer.sign(message, &key.public_key, &private_key)
    }

    async fn generate(&self, key_type: &str) -> Result<GeneratedKey, ServiceError> {
        let key_pair = self
            .key_algorithm_provider
            .get_key_algorithm(key_type)
            .map_err(|_| ServiceError::IncorrectParameters)?
            .generate_key_pair();
        let passphrase = self.params.encryption.as_ref();

        Ok(GeneratedKey {
            public: key_pair.public,
            private: encrypt_if_password_is_provided(&key_pair.private, passphrase).await?,
        })
    }
}

async fn decrypt_if_password_is_provided(
    data: &[u8],
    passphrase: Option<&String>,
) -> Result<Vec<u8>, ServiceError> {
    match passphrase {
        None => Ok(data.to_vec()),
        Some(passphrase) => {
            let decryptor =
            //TODO: use the async version of new
                match age::Decryptor::new(data).map_err(|e| ServiceError::Other(e.to_string()))? {
                    age::Decryptor::Passphrase(d) => Ok(d),
                    _ => Err(ServiceError::Other(
                        "Failed to create decryptor".to_string(),
                    )),
                }?;

            let mut decrypted = vec![];
            let reader = decryptor
                .decrypt_async(&Secret::new(passphrase.to_owned()), None)
                .map_err(|e| ServiceError::Other(e.to_string()))?;

            let mut reader = reader.compat();

            reader
                .read_to_end(&mut decrypted)
                .await
                .map_err(|e| ServiceError::Other(e.to_string()))?;

            Ok(decrypted)
        }
    }
}

async fn encrypt_if_password_is_provided(
    buffer: &[u8],
    passphrase: Option<&String>,
) -> Result<Vec<u8>, ServiceError> {
    match passphrase {
        None => Ok(buffer.to_vec()),
        Some(passphrase) => {
            let encryptor =
                age::Encryptor::with_user_passphrase(Secret::new(passphrase.to_string()));

            let mut encrypted = vec![];
            let writer = encryptor
                .wrap_async_output(&mut encrypted)
                .await
                .map_err(|e| ServiceError::Other(e.to_string()))?;

            let mut writer = writer.compat_write();

            writer
                .write_all(buffer.as_ref())
                .await
                .map_err(|e| ServiceError::Other(e.to_string()))?;

            writer
                .shutdown()
                .await
                .map_err(|e| ServiceError::Other(e.to_string()))?;

            Ok(encrypted)
        }
    }
}
