use age::secrecy::Secret;
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tokio_util::compat::FuturesAsyncWriteCompatExt;

use crate::{
    config::data_structure::KeyStorageInternalParams,
    provider::{
        key_algorithm::{provider::KeyAlgorithmProvider, GeneratedKey},
        key_storage::KeyStorage,
    },
    service::error::ServiceError,
};

pub struct InternalKeyProvider {
    pub key_algorithm_provider: Arc<dyn KeyAlgorithmProvider + Send + Sync>,
    pub params: KeyStorageInternalParams,
}

#[async_trait::async_trait]
impl KeyStorage for InternalKeyProvider {
    async fn decrypt_private_key(&self, private_key: &[u8]) -> Result<Vec<u8>, ServiceError> {
        let passphrase = self.params.encryption.as_ref().map(|value| &value.value);
        decrypt_if_password_is_provided(private_key, passphrase).await
    }

    fn fingerprint(&self, public_key: &[u8], key_type: &str) -> Result<String, ServiceError> {
        Ok(self
            .key_algorithm_provider
            .get_key_algorithm(key_type)
            .map_err(|_| ServiceError::IncorrectParameters)?
            .fingerprint(public_key))
    }

    async fn generate(&self, key_type: &str) -> Result<GeneratedKey, ServiceError> {
        let key_pair = self
            .key_algorithm_provider
            .get_key_algorithm(key_type)
            .map_err(|_| ServiceError::IncorrectParameters)?
            .generate_key_pair();
        let passphrase = self.params.encryption.as_ref().map(|value| &value.value);

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
