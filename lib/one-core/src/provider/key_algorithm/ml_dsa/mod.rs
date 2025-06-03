//! https://datatracker.ietf.org/doc/html/draft-ietf-cose-dilithium-01

use std::sync::Arc;

use async_trait::async_trait;
use ct_codecs::{Base64UrlSafeNoPadding, Decoder, Encoder};
use one_crypto::signer::crydi3::CRYDI3Signer;
use one_crypto::{Signer, SignerError};
use secrecy::{ExposeSecret, SecretSlice};

use crate::config::core_config::KeyAlgorithmType;
use crate::model::key::{PrivateKeyJwk, PublicKeyJwk, PublicKeyJwkMlweData};
use crate::provider::key_algorithm::KeyAlgorithm;
use crate::provider::key_algorithm::error::KeyAlgorithmError;
use crate::provider::key_algorithm::key::{
    KeyHandle, KeyHandleError, SignatureKeyHandle, SignaturePrivateKeyHandle,
    SignaturePublicKeyHandle,
};
use crate::provider::key_algorithm::model::{GeneratedKey, KeyAlgorithmCapabilities};

pub struct MlDsa;

#[cfg(test)]
mod test;

impl KeyAlgorithm for MlDsa {
    fn algorithm_id(&self) -> String {
        "DILITHIUM".to_string()
    }

    fn algorithm_type(&self) -> KeyAlgorithmType {
        KeyAlgorithmType::Dilithium
    }

    fn get_capabilities(&self) -> KeyAlgorithmCapabilities {
        KeyAlgorithmCapabilities { features: vec![] }
    }

    fn generate_key(&self) -> Result<GeneratedKey, KeyAlgorithmError> {
        let keys = CRYDI3Signer::generate_key_pair();
        Ok(GeneratedKey {
            key: KeyHandle::SignatureOnly(SignatureKeyHandle::WithPrivateKey {
                private: Arc::new(MlDsaPrivateKeyHandle::new(
                    keys.private.clone(),
                    keys.public.clone(),
                )),
                public: Arc::new(MlDsaPublicKeyHandle::new(keys.public.clone(), None)),
            }),
            private: keys.private,
            public: keys.public,
        })
    }

    fn reconstruct_key(
        &self,
        public_key: &[u8],
        private_key: Option<SecretSlice<u8>>,
        r#use: Option<String>,
    ) -> Result<KeyHandle, KeyAlgorithmError> {
        if let Some(private_key) = private_key {
            Ok(KeyHandle::SignatureOnly(
                SignatureKeyHandle::WithPrivateKey {
                    private: Arc::new(MlDsaPrivateKeyHandle::new(private_key, public_key.to_vec())),
                    public: Arc::new(MlDsaPublicKeyHandle::new(public_key.to_vec(), r#use)),
                },
            ))
        } else {
            Ok(KeyHandle::SignatureOnly(SignatureKeyHandle::PublicKeyOnly(
                Arc::new(MlDsaPublicKeyHandle::new(public_key.to_vec(), r#use)),
            )))
        }
    }

    fn issuance_jose_alg_id(&self) -> Option<String> {
        Some("CRYDI3".to_string())
    }

    fn verification_jose_alg_ids(&self) -> Vec<String> {
        // invalid values for backward compatibility
        vec!["CRYDI3".to_string(), "DILITHIUM".to_string()]
    }

    fn cose_alg_id(&self) -> Option<i32> {
        todo!()
    }

    fn parse_jwk(&self, key: &PublicKeyJwk) -> Result<KeyHandle, KeyAlgorithmError> {
        if let PublicKeyJwk::Mlwe(data) = key {
            if !self.verification_jose_alg_ids().contains(&data.alg) {
                return Err(KeyAlgorithmError::Failed(format!(
                    "unsupported key algorithm variant: {}",
                    data.alg
                )));
            }
            let x = Base64UrlSafeNoPadding::decode_to_vec(&data.x, None)
                .map_err(|e| KeyAlgorithmError::Failed(e.to_string()))?;

            Ok(KeyHandle::SignatureOnly(SignatureKeyHandle::PublicKeyOnly(
                Arc::new(MlDsaPublicKeyHandle::new(x, data.r#use.clone())),
            )))
        } else {
            Err(KeyAlgorithmError::Failed("invalid kty".to_string()))
        }
    }

    fn parse_private_jwk(&self, jwk: PrivateKeyJwk) -> Result<GeneratedKey, KeyAlgorithmError> {
        if let PrivateKeyJwk::Mlwe(data) = jwk {
            if data.alg != "CRYDI3" {
                return Err(KeyAlgorithmError::Failed(format!(
                    "unsupported alg {}",
                    data.alg
                )));
            }
            let x = Base64UrlSafeNoPadding::decode_to_vec(&data.x, None)
                .map_err(|e| KeyAlgorithmError::Failed(e.to_string()))?;
            let d = Base64UrlSafeNoPadding::decode_to_vec(data.d.expose_secret(), None)
                .map_err(|e| KeyAlgorithmError::Failed(e.to_string()))?
                .into();

            let keys = CRYDI3Signer::parse_key_pair(&x, &d)?;
            let key_handle =
                self.reconstruct_key(&keys.public, Some(keys.private.clone()), data.r#use)?;
            Ok(GeneratedKey {
                key: key_handle,
                public: keys.public,
                private: keys.private,
            })
        } else {
            Err(KeyAlgorithmError::Failed("invalid kty".to_string()))
        }
    }

    fn parse_multibase(&self, _multibase: &str) -> Result<KeyHandle, KeyAlgorithmError> {
        todo!()
    }

    fn parse_raw(&self, _public_key_der: &[u8]) -> Result<KeyHandle, KeyAlgorithmError> {
        todo!()
    }
}

struct MlDsaPublicKeyHandle {
    public_key: Vec<u8>,
    r#use: Option<String>,
}

impl MlDsaPublicKeyHandle {
    fn new(public_key: Vec<u8>, r#use: Option<String>) -> Self {
        Self { public_key, r#use }
    }
}

struct MlDsaPrivateKeyHandle {
    private_key: SecretSlice<u8>,
    public_key: Vec<u8>,
}

impl MlDsaPrivateKeyHandle {
    fn new(private_key: SecretSlice<u8>, public_key: Vec<u8>) -> Self {
        Self {
            private_key,
            public_key,
        }
    }
}

impl SignaturePublicKeyHandle for MlDsaPublicKeyHandle {
    fn as_jwk(&self) -> Result<PublicKeyJwk, KeyHandleError> {
        Ok(PublicKeyJwk::Mlwe(PublicKeyJwkMlweData {
            r#use: self.r#use.clone(),
            kid: None,
            alg: "CRYDI3".to_string(),
            x: Base64UrlSafeNoPadding::encode_to_string(&self.public_key)
                .map_err(|e| KeyHandleError::EncodingJwk(e.to_string()))?,
        }))
    }

    fn as_multibase(&self) -> Result<String, KeyHandleError> {
        todo!()
    }

    fn as_raw(&self) -> Vec<u8> {
        self.public_key.clone()
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), SignerError> {
        CRYDI3Signer {}
            .verify(message, signature, &self.public_key)
            .map_err(|_| SignerError::InvalidSignature)
    }
}

#[async_trait]
impl SignaturePrivateKeyHandle for MlDsaPrivateKeyHandle {
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignerError> {
        CRYDI3Signer {}.sign(message, &self.public_key, &self.private_key)
    }
}
