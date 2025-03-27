//! https://datatracker.ietf.org/doc/html/rfc7518

use std::sync::Arc;

use async_trait::async_trait;
use ct_codecs::{Base64UrlSafeNoPadding, Decoder};
use one_crypto::encryption::EncryptionError;
use one_crypto::jwe::{PrivateKeyAgreementHandle, RemoteJwk};
use one_crypto::signer::ecdsa::ECDSASigner;
use one_crypto::{Signer, SignerError};
use secrecy::SecretSlice;

use crate::config::core_config::KeyAlgorithmType;
use crate::model::key::PublicKeyJwk;
use crate::provider::key_algorithm::error::KeyAlgorithmError;
use crate::provider::key_algorithm::key::{
    KeyAgreementHandle, KeyHandle, KeyHandleError, PublicKeyAgreementHandle, SignatureKeyHandle,
    SignaturePrivateKeyHandle, SignaturePublicKeyHandle,
};
use crate::provider::key_algorithm::model::{Features, GeneratedKey, KeyAlgorithmCapabilities};
use crate::provider::key_algorithm::KeyAlgorithm;
use crate::provider::key_utils::{ecdsa_public_key_as_jwk, ecdsa_public_key_as_multibase};

pub struct Ecdsa;

#[cfg(test)]
mod test;

impl KeyAlgorithm for Ecdsa {
    fn algorithm_id(&self) -> String {
        "ECDSA".to_string()
    }

    fn algorithm_type(&self) -> KeyAlgorithmType {
        KeyAlgorithmType::Ecdsa
    }

    fn get_capabilities(&self) -> KeyAlgorithmCapabilities {
        KeyAlgorithmCapabilities {
            features: vec![Features::GenerateCSR],
        }
    }

    fn generate_key(&self) -> Result<GeneratedKey, KeyAlgorithmError> {
        let (private, public) = ECDSASigner::generate_key_pair();

        let private_handle = Arc::new(EcdsaPrivateKeyHandle::new(private.clone(), public.clone()));
        let public_handle = Arc::new(EcdsaPublicKeyHandle::new(public.clone(), None));

        Ok(GeneratedKey {
            key: KeyHandle::SignatureAndKeyAgreement {
                signature: SignatureKeyHandle::WithPrivateKey {
                    private: private_handle.clone(),
                    public: public_handle.clone(),
                },
                key_agreement: KeyAgreementHandle::WithPrivateKey {
                    private: private_handle,
                    public: public_handle,
                },
            },
            public,
            private,
        })
    }

    fn reconstruct_key(
        &self,
        public_key: &[u8],
        private_key: Option<SecretSlice<u8>>,
        r#use: Option<String>,
    ) -> Result<KeyHandle, KeyAlgorithmError> {
        if let Some(private_key) = private_key {
            let private_handle =
                Arc::new(EcdsaPrivateKeyHandle::new(private_key, public_key.to_vec()));
            let public_handle = Arc::new(EcdsaPublicKeyHandle::new(public_key.to_vec(), r#use));

            Ok(KeyHandle::SignatureAndKeyAgreement {
                signature: SignatureKeyHandle::WithPrivateKey {
                    private: private_handle.clone(),
                    public: public_handle.clone(),
                },
                key_agreement: KeyAgreementHandle::WithPrivateKey {
                    private: private_handle,
                    public: public_handle,
                },
            })
        } else {
            let public_handle = Arc::new(EcdsaPublicKeyHandle::new(public_key.to_vec(), r#use));

            Ok(KeyHandle::SignatureAndKeyAgreement {
                signature: SignatureKeyHandle::PublicKeyOnly(public_handle.clone()),
                key_agreement: KeyAgreementHandle::PublicKeyOnly(public_handle),
            })
        }
    }

    fn issuance_jose_alg_id(&self) -> Option<String> {
        Some("ES256".to_string())
    }

    fn verification_jose_alg_ids(&self) -> Vec<String> {
        vec!["ES256".to_string()]
    }

    fn cose_alg_id(&self) -> Option<i32> {
        todo!()
    }

    fn parse_jwk(&self, key: &PublicKeyJwk) -> Result<KeyHandle, KeyAlgorithmError> {
        if let PublicKeyJwk::Ec(data) = key {
            let x = Base64UrlSafeNoPadding::decode_to_vec(&data.x, None)
                .map_err(|e| KeyAlgorithmError::Failed(e.to_string()))?;
            let y = Base64UrlSafeNoPadding::decode_to_vec(
                data.y
                    .as_ref()
                    .ok_or(KeyAlgorithmError::Failed("Y is missing".to_string()))?,
                None,
            )
            .map_err(|e| KeyAlgorithmError::Failed(e.to_string()))?;

            let public_key = ECDSASigner::parse_public_key_coordinates(&x, &y, true)?;
            let handle = Arc::new(EcdsaPublicKeyHandle::new(public_key, data.r#use.clone()));

            Ok(KeyHandle::SignatureAndKeyAgreement {
                signature: SignatureKeyHandle::PublicKeyOnly(handle.clone()),
                key_agreement: KeyAgreementHandle::PublicKeyOnly(handle),
            })
        } else {
            Err(KeyAlgorithmError::Failed("invalid kty".to_string()))
        }
    }

    fn parse_multibase(&self, _multibase: &str) -> Result<KeyHandle, KeyAlgorithmError> {
        todo!()
    }

    fn parse_raw(&self, public_key_der: &[u8]) -> Result<KeyHandle, KeyAlgorithmError> {
        let public_key = ECDSASigner::parse_public_key_from_der(public_key_der, true)?;
        let handle = Arc::new(EcdsaPublicKeyHandle::new(public_key, None));
        Ok(KeyHandle::SignatureAndKeyAgreement {
            signature: SignatureKeyHandle::PublicKeyOnly(handle.clone()),
            key_agreement: KeyAgreementHandle::PublicKeyOnly(handle),
        })
    }
}

struct EcdsaPublicKeyHandle {
    public_key: Vec<u8>,
    r#use: Option<String>,
}

impl EcdsaPublicKeyHandle {
    fn new(public_key: Vec<u8>, r#use: Option<String>) -> Self {
        Self { public_key, r#use }
    }
}

struct EcdsaPrivateKeyHandle {
    private_key: SecretSlice<u8>,
    public_key: Vec<u8>,
}

impl EcdsaPrivateKeyHandle {
    fn new(private_key: SecretSlice<u8>, public_key: Vec<u8>) -> Self {
        Self {
            private_key,
            public_key,
        }
    }
}

impl SignaturePublicKeyHandle for EcdsaPublicKeyHandle {
    fn as_jwk(&self) -> Result<PublicKeyJwk, KeyHandleError> {
        ecdsa_public_key_as_jwk(&self.public_key, self.r#use.clone())
    }

    fn as_multibase(&self) -> Result<String, KeyHandleError> {
        ecdsa_public_key_as_multibase(&self.public_key)
    }

    fn as_raw(&self) -> Vec<u8> {
        self.public_key.clone()
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), SignerError> {
        ECDSASigner {}.verify(message, signature, &self.public_key)
    }
}

#[async_trait::async_trait]
impl SignaturePrivateKeyHandle for EcdsaPrivateKeyHandle {
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignerError> {
        ECDSASigner {}.sign(message, &self.public_key, &self.private_key)
    }
}

impl PublicKeyAgreementHandle for EcdsaPublicKeyHandle {
    fn as_jwk(&self) -> Result<RemoteJwk, KeyHandleError> {
        ECDSASigner::bytes_as_jwk(&self.public_key).map_err(KeyHandleError::Encryption)
    }

    fn as_multibase(&self) -> Result<String, KeyHandleError> {
        ecdsa_public_key_as_multibase(&self.public_key)
    }

    fn as_raw(&self) -> Vec<u8> {
        self.public_key.clone()
    }
}

#[async_trait]
impl PrivateKeyAgreementHandle for EcdsaPrivateKeyHandle {
    async fn shared_secret(
        &self,
        remote_jwk: &RemoteJwk,
    ) -> Result<SecretSlice<u8>, EncryptionError> {
        ECDSASigner::shared_secret_p256(&self.private_key, remote_jwk)
    }
}
