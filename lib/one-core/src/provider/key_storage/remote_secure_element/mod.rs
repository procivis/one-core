use std::sync::Arc;

use one_crypto::signer::eddsa::EDDSASigner;
use one_crypto::{Signer, SignerError};
use shared_types::KeyId;

use super::secure_element::NativeKeyStorage;
use crate::config::core_config::KeyAlgorithmType;
use crate::model::key::{Key, PublicKeyJwk};
use crate::provider::key_algorithm::key::{
    KeyHandle, KeyHandleError, SignatureKeyHandle, SignaturePrivateKeyHandle,
    SignaturePublicKeyHandle,
};
use crate::provider::key_storage::error::KeyStorageError;
use crate::provider::key_storage::model::{
    KeySecurity, KeyStorageCapabilities, StorageGeneratedKey,
};
use crate::provider::key_storage::KeyStorage;
use crate::provider::key_utils::{eddsa_public_key_as_jwk, eddsa_public_key_as_multibase};

pub struct RemoteSecureElementKeyProvider {
    native_storage: Arc<dyn NativeKeyStorage>,
}

#[async_trait::async_trait]
impl KeyStorage for RemoteSecureElementKeyProvider {
    fn get_capabilities(&self) -> KeyStorageCapabilities {
        KeyStorageCapabilities {
            algorithms: vec![KeyAlgorithmType::Eddsa],
            security: vec![KeySecurity::RemoteSecureElement],
            features: vec![],
        }
    }

    async fn generate(
        &self,
        key_id: KeyId,
        key_type: &str,
    ) -> Result<StorageGeneratedKey, KeyStorageError> {
        if key_type != "EDDSA" {
            return Err(KeyStorageError::UnsupportedKeyType {
                key_type: key_type.to_owned(),
            });
        }

        self.native_storage.generate_key(key_id.to_string()).await
    }

    fn key_handle(&self, key: &Key) -> Result<KeyHandle, SignerError> {
        let handle = RemoteSecureElementKeyHandle {
            key: key.clone(),
            native_storage: self.native_storage.clone(),
        };

        Ok(KeyHandle::SignatureOnly(
            SignatureKeyHandle::WithPrivateKey {
                private: Arc::new(handle.clone()),
                public: Arc::new(handle),
            },
        ))
    }
}

impl RemoteSecureElementKeyProvider {
    pub fn new(native_storage: Arc<dyn NativeKeyStorage>) -> Self {
        Self { native_storage }
    }
}

#[derive(Clone)]
struct RemoteSecureElementKeyHandle {
    key: Key,
    native_storage: Arc<dyn NativeKeyStorage>,
}

impl SignaturePublicKeyHandle for RemoteSecureElementKeyHandle {
    fn as_jwk(&self) -> Result<PublicKeyJwk, KeyHandleError> {
        eddsa_public_key_as_jwk(&self.key.public_key, "Ed25519", None)
    }

    fn as_multibase(&self) -> Result<String, KeyHandleError> {
        eddsa_public_key_as_multibase(&self.key.public_key)
    }

    fn as_raw(&self) -> Vec<u8> {
        self.key.public_key.clone()
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), SignerError> {
        EDDSASigner {}.verify(message, signature, &self.key.public_key)
    }
}

#[async_trait::async_trait]
impl SignaturePrivateKeyHandle for RemoteSecureElementKeyHandle {
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignerError> {
        self.native_storage
            .sign(&self.key.key_reference, message)
            .await
    }
}

#[cfg(test)]
mod test;
