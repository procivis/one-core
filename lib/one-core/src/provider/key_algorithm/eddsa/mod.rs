//! https://datatracker.ietf.org/doc/html/rfc8037

use std::sync::Arc;

use async_trait::async_trait;
use ct_codecs::{Base64UrlSafeNoPadding, Decoder};
use one_crypto::encryption::EncryptionError;
use one_crypto::jwe::{PrivateKeyAgreementHandle, RemoteJwk};
use one_crypto::signer::eddsa::EDDSASigner;
use one_crypto::{Signer, SignerError};
use secrecy::SecretSlice;
use serde::Deserialize;

use crate::config::core_config::KeyAlgorithmType;
use crate::model::key::PublicKeyJwk;
use crate::provider::key_algorithm::error::KeyAlgorithmError;
use crate::provider::key_algorithm::key::{
    KeyAgreementHandle, KeyHandle, KeyHandleError, PublicKeyAgreementHandle, SignatureKeyHandle,
    SignaturePrivateKeyHandle, SignaturePublicKeyHandle,
};
use crate::provider::key_algorithm::model::{Features, GeneratedKey, KeyAlgorithmCapabilities};
use crate::provider::key_algorithm::KeyAlgorithm;
use crate::provider::key_utils::{eddsa_public_key_as_jwk, eddsa_public_key_as_multibase};

pub struct Eddsa;

#[cfg(test)]
mod test;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EddsaParams {
    pub algorithm: Algorithm,
}

#[derive(Deserialize)]
pub enum Algorithm {
    #[serde(rename = "Ed25519")]
    Ed25519,
}

impl Eddsa {
    pub fn new(params: EddsaParams) -> Self {
        _ = params.algorithm;
        Self
    }
}

impl KeyAlgorithm for Eddsa {
    fn algorithm_id(&self) -> String {
        "Ed25519".to_string()
    }

    fn algorithm_type(&self) -> KeyAlgorithmType {
        KeyAlgorithmType::Eddsa
    }

    fn get_capabilities(&self) -> KeyAlgorithmCapabilities {
        KeyAlgorithmCapabilities {
            features: vec![Features::GenerateCSR],
        }
    }

    fn generate_key(&self) -> Result<GeneratedKey, KeyAlgorithmError> {
        let key_pair = EDDSASigner::generate_key_pair();

        let private_handle = Arc::new(EddsaPrivateKeyHandle::new(
            key_pair.private.clone(),
            key_pair.public.clone(),
        ));
        let public_handle = Arc::new(EddsaPublicKeyHandle::new(key_pair.public.clone(), None));

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
            public: key_pair.public,
            private: key_pair.private,
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
                Arc::new(EddsaPrivateKeyHandle::new(private_key, public_key.to_vec()));
            let public_handle = Arc::new(EddsaPublicKeyHandle::new(public_key.to_vec(), r#use));

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
            let public_handle = Arc::new(EddsaPublicKeyHandle::new(public_key.to_vec(), r#use));

            Ok(KeyHandle::SignatureAndKeyAgreement {
                signature: SignatureKeyHandle::PublicKeyOnly(public_handle.clone()),
                key_agreement: KeyAgreementHandle::PublicKeyOnly(public_handle),
            })
        }
    }

    fn issuance_jose_alg_id(&self) -> Option<String> {
        Some("EdDSA".to_string())
    }

    fn verification_jose_alg_ids(&self) -> Vec<String> {
        vec!["EdDSA".to_string(), "EDDSA".to_string()]
    }

    fn cose_alg_id(&self) -> Option<i32> {
        todo!()
    }

    fn parse_jwk(&self, key: &PublicKeyJwk) -> Result<KeyHandle, KeyAlgorithmError> {
        if let PublicKeyJwk::Okp(data) = key {
            let x = Base64UrlSafeNoPadding::decode_to_vec(&data.x, None)
                .map_err(|e| KeyAlgorithmError::Failed(e.to_string()))?;
            let handle = Arc::new(EddsaPublicKeyHandle::new(x, data.r#use.clone()));
            Ok(KeyHandle::SignatureAndKeyAgreement {
                signature: SignatureKeyHandle::PublicKeyOnly(handle.clone()),
                key_agreement: KeyAgreementHandle::PublicKeyOnly(handle),
            })
        } else {
            Err(KeyAlgorithmError::Failed("invalid kty".to_string()))
        }
    }

    fn parse_multibase(&self, multibase: &str) -> Result<KeyHandle, KeyAlgorithmError> {
        let x = Base64UrlSafeNoPadding::decode_to_vec(multibase, None)
            .map_err(|e| KeyAlgorithmError::Failed(e.to_string()))?;
        let handle = Arc::new(EddsaPublicKeyHandle::new(x, None));
        Ok(KeyHandle::SignatureAndKeyAgreement {
            signature: SignatureKeyHandle::PublicKeyOnly(handle.clone()),
            key_agreement: KeyAgreementHandle::PublicKeyOnly(handle),
        })
    }

    fn parse_raw(&self, public_key_der: &[u8]) -> Result<KeyHandle, KeyAlgorithmError> {
        let key = EDDSASigner::public_key_from_der(public_key_der)?;
        let handle = Arc::new(EddsaPublicKeyHandle::new(key, None));
        Ok(KeyHandle::SignatureAndKeyAgreement {
            signature: SignatureKeyHandle::PublicKeyOnly(handle.clone()),
            key_agreement: KeyAgreementHandle::PublicKeyOnly(handle),
        })
    }
}

struct EddsaPublicKeyHandle {
    public_key: Vec<u8>,
    r#use: Option<String>,
}

impl EddsaPublicKeyHandle {
    fn new(public_key: Vec<u8>, r#use: Option<String>) -> Self {
        Self { public_key, r#use }
    }

    fn as_jwk(&self) -> Result<PublicKeyJwk, KeyHandleError> {
        eddsa_public_key_as_jwk(&self.public_key, "Ed25519", self.r#use.clone())
    }

    fn as_multibase(&self) -> Result<String, KeyHandleError> {
        eddsa_public_key_as_multibase(&self.public_key)
    }

    fn as_raw(&self) -> Vec<u8> {
        self.public_key.clone()
    }
}

struct EddsaPrivateKeyHandle {
    private_key: SecretSlice<u8>,
    public_key: Vec<u8>,
}

impl EddsaPrivateKeyHandle {
    fn new(private_key: SecretSlice<u8>, public_key: Vec<u8>) -> Self {
        Self {
            private_key,
            public_key,
        }
    }
}

impl SignaturePublicKeyHandle for EddsaPublicKeyHandle {
    fn as_jwk(&self) -> Result<PublicKeyJwk, KeyHandleError> {
        self.as_jwk()
    }

    fn as_multibase(&self) -> Result<String, KeyHandleError> {
        self.as_multibase()
    }

    fn as_raw(&self) -> Vec<u8> {
        self.as_raw()
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), SignerError> {
        EDDSASigner {}.verify(message, signature, &self.public_key)
    }
}

#[async_trait]
impl SignaturePrivateKeyHandle for EddsaPrivateKeyHandle {
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignerError> {
        EDDSASigner {}.sign(message, &self.public_key, &self.private_key)
    }
}

#[async_trait]
impl PrivateKeyAgreementHandle for EddsaPrivateKeyHandle {
    async fn shared_secret(
        &self,
        remote_jwk: &RemoteJwk,
    ) -> Result<SecretSlice<u8>, EncryptionError> {
        EDDSASigner::shared_secret_x25519(&self.private_key, remote_jwk)
    }
}

impl PublicKeyAgreementHandle for EddsaPublicKeyHandle {
    fn as_jwk(&self) -> Result<RemoteJwk, KeyHandleError> {
        EDDSASigner::ed25519_to_x25519_jwk(&self.public_key).map_err(KeyHandleError::Encryption)
    }

    fn as_multibase(&self) -> Result<String, KeyHandleError> {
        self.as_multibase()
    }

    fn as_raw(&self) -> Vec<u8> {
        self.as_raw()
    }
}
