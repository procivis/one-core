use std::sync::Arc;

use coset::iana::EnumI64;
use coset::{CoseKey, CoseKeyBuilder, iana};
use one_crypto::Signer;
use one_crypto::signer::eddsa::EDDSASigner;
use proc_macros::Provider;
use shared_types::{KeyId, KeyStorageId};
use standardized_types::jwk::{PrivateJwk, PublicJwk};

use super::secure_element::NativeKeyStorage;
use crate::config::core_config::KeyAlgorithmType;
use crate::error::ContextWithErrorCode;
use crate::model::key::Key;
use crate::provider::key_algorithm::eddsa::{
    eddsa_public_key_as_jwk, eddsa_public_key_as_multibase,
};
use crate::provider::key_algorithm::key::{
    KeyHandle, KeyHandleError, SignatureKeyHandle, SignaturePrivateKeyHandle,
    SignaturePublicKeyHandle,
};
use crate::provider::key_storage::KeyStorage;
use crate::provider::key_storage::error::KeyStorageError;
use crate::provider::key_storage::model::{Features, KeyStorageCapabilities, StorageGeneratedKey};

#[derive(Provider)]
pub struct RemoteSecureElementKeyProvider {
    native_storage: Arc<dyn NativeKeyStorage>,
    name: KeyStorageId,
}

#[async_trait::async_trait]
impl KeyStorage for RemoteSecureElementKeyProvider {
    fn get_capabilities(&self) -> KeyStorageCapabilities {
        KeyStorageCapabilities {
            algorithms: vec![KeyAlgorithmType::Eddsa],
            features: vec![],
        }
    }

    fn config_name(&self) -> KeyStorageId {
        self.name.clone()
    }
    async fn generate(
        &self,
        key_id: KeyId,
        _key_type: KeyAlgorithmType,
        _params: serde_json::Value,
    ) -> Result<StorageGeneratedKey, KeyStorageError> {
        self.native_storage.generate_key(key_id.to_string()).await
    }

    async fn import(
        &self,
        _key_id: KeyId,
        _key_algorithm: KeyAlgorithmType,
        _jwk: PrivateJwk,
    ) -> Result<StorageGeneratedKey, KeyStorageError> {
        Err(KeyStorageError::UnsupportedFeature {
            feature: Features::Importable,
        })
    }

    fn key_handle(&self, key: &Key) -> Result<KeyHandle, KeyStorageError> {
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

impl RemoteSecureElementKeyProvider {
    pub fn new(name: &KeyStorageId, native_storage: Arc<dyn NativeKeyStorage>) -> Self {
        Self {
            native_storage,
            name: name.to_owned(),
        }
    }
}

#[derive(Clone)]
struct RemoteSecureElementKeyHandle {
    key: Key,
    native_storage: Arc<dyn NativeKeyStorage>,
}

impl SignaturePublicKeyHandle for RemoteSecureElementKeyHandle {
    fn as_jwk(&self) -> Result<PublicJwk, KeyHandleError> {
        eddsa_public_key_as_jwk(&self.key.public_key, None)
    }

    fn as_multibase(&self) -> Result<String, KeyHandleError> {
        eddsa_public_key_as_multibase(&self.key.public_key)
    }

    fn as_raw(&self) -> Vec<u8> {
        self.key.public_key.clone()
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), KeyHandleError> {
        Ok(EDDSASigner.verify(message, signature, &self.key.public_key)?)
    }

    fn as_der(&self) -> Result<Vec<u8>, KeyHandleError> {
        Ok(EDDSASigner::public_key_to_der(&self.key.public_key)?)
    }

    fn as_cose(&self) -> Result<CoseKey, KeyHandleError> {
        Ok(CoseKeyBuilder::new_okp_key()
            .param(
                iana::Ec2KeyParameter::Crv.to_i64(),
                ciborium::Value::from(iana::EllipticCurve::Ed25519.to_i64()),
            )
            .param(
                iana::Ec2KeyParameter::X as i64,
                ciborium::Value::from(self.key.public_key.to_owned()),
            )
            .build())
    }
}

#[async_trait::async_trait]
impl SignaturePrivateKeyHandle for RemoteSecureElementKeyHandle {
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, KeyHandleError> {
        let key_reference = self
            .key
            .key_reference
            .as_ref()
            .ok_or(KeyStorageError::MissingKeyReference)
            .error_while("signing")?;
        Ok(self.native_storage.sign(key_reference, message).await?)
    }
}

#[cfg(test)]
mod test;
