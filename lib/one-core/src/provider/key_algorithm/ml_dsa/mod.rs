//! https://datatracker.ietf.org/doc/html/draft-ietf-cose-dilithium-01

use std::sync::Arc;

use async_trait::async_trait;
use ct_codecs::{Base64UrlSafeNoPadding, Decoder, Encoder};
use one_crypto::signer::ml_dsa::MlDsaSigner;
use one_crypto::{Signer, SignerError};
use secrecy::{ExposeSecret, SecretSlice};
use standardized_types::jwk::{JwkUse, PrivateJwk, PublicJwk, PublicJwkAkp};

use crate::config::core_config::KeyAlgorithmType;
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
        "ML-DSA-65".to_string()
    }

    fn algorithm_type(&self) -> KeyAlgorithmType {
        KeyAlgorithmType::MlDsa
    }

    fn get_capabilities(&self) -> KeyAlgorithmCapabilities {
        KeyAlgorithmCapabilities { features: vec![] }
    }

    fn generate_key(&self) -> Result<GeneratedKey, KeyAlgorithmError> {
        let keys = MlDsaSigner::generate_key_pair()?;
        Ok(GeneratedKey {
            key: KeyHandle::SignatureOnly(SignatureKeyHandle::WithPrivateKey {
                private: Arc::new(MlDsaPrivateKeyHandle::new(
                    keys.seed.clone(),
                    keys.public.clone(),
                )),
                public: Arc::new(MlDsaPublicKeyHandle::new(keys.public.clone(), None)),
            }),
            private: keys.seed,
            public: keys.public,
        })
    }

    fn reconstruct_key(
        &self,
        public_key: &[u8],
        private_key: Option<SecretSlice<u8>>,
        r#use: Option<JwkUse>,
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
        Some("ML-DSA-65".to_string())
    }

    fn verification_jose_alg_ids(&self) -> Vec<String> {
        // invalid values for backward compatibility
        vec!["ML-DSA-65".to_string()]
    }

    fn cose_alg_id(&self) -> Option<i32> {
        // https://www.ietf.org/archive/id/draft-ietf-cose-dilithium-11.html#name-ml-dsa-65
        Some(-49)
    }

    fn parse_jwk(&self, key: &PublicJwk) -> Result<KeyHandle, KeyAlgorithmError> {
        if let PublicJwk::Akp(data) = key {
            if !self.verification_jose_alg_ids().contains(&data.alg) {
                return Err(KeyAlgorithmError::NotSupported(format!(
                    "key algorithm variant: {}",
                    data.alg
                )));
            }
            let r#pub = Base64UrlSafeNoPadding::decode_to_vec(&data.r#pub, None)?;

            Ok(KeyHandle::SignatureOnly(SignatureKeyHandle::PublicKeyOnly(
                Arc::new(MlDsaPublicKeyHandle::new(r#pub, data.r#use.clone())),
            )))
        } else {
            Err(KeyAlgorithmError::InvalidKeyType)
        }
    }

    fn parse_private_jwk(&self, jwk: PrivateJwk) -> Result<GeneratedKey, KeyAlgorithmError> {
        if let PrivateJwk::Akp(data) = jwk {
            if data.alg != "ML-DSA-65" {
                return Err(KeyAlgorithmError::NotSupported(format!(
                    "alg: `{}`",
                    data.alg
                )));
            }
            let r#pub = Base64UrlSafeNoPadding::decode_to_vec(&data.r#pub, None)?;
            let r#priv =
                Base64UrlSafeNoPadding::decode_to_vec(data.r#priv.expose_secret(), None)?.into();

            let keys = MlDsaSigner::parse_key_pair(&r#pub, &r#priv)?;
            let key_handle =
                self.reconstruct_key(&keys.public, Some(keys.seed.clone()), data.r#use)?;
            Ok(GeneratedKey {
                key: key_handle,
                public: keys.public,
                private: keys.seed,
            })
        } else {
            Err(KeyAlgorithmError::InvalidKeyType)
        }
    }

    fn parse_multibase(&self, _multibase: &str) -> Result<KeyHandle, KeyAlgorithmError> {
        Err(KeyAlgorithmError::NotSupported(
            "parse multibase not supported for ML-DSA".to_string(),
        ))
    }

    fn parse_raw(&self, _public_key_der: &[u8]) -> Result<KeyHandle, KeyAlgorithmError> {
        Err(KeyAlgorithmError::NotSupported(
            "parse raw not supported for ML-DSA".to_string(),
        ))
    }
}

struct MlDsaPublicKeyHandle {
    public_key: Vec<u8>,
    r#use: Option<JwkUse>,
}

impl MlDsaPublicKeyHandle {
    fn new(public_key: Vec<u8>, r#use: Option<JwkUse>) -> Self {
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
    fn as_jwk(&self) -> Result<PublicJwk, KeyHandleError> {
        Ok(PublicJwk::Akp(PublicJwkAkp {
            r#use: self.r#use.clone(),
            kid: None,
            alg: "ML-DSA-65".to_string(),
            r#pub: Base64UrlSafeNoPadding::encode_to_string(&self.public_key)?,
        }))
    }

    fn as_multibase(&self) -> Result<String, KeyHandleError> {
        unimplemented!("unsupported")
    }

    fn as_raw(&self) -> Vec<u8> {
        self.public_key.clone()
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), SignerError> {
        MlDsaSigner
            .verify(message, signature, &self.public_key)
            .map_err(|_| SignerError::InvalidSignature)
    }
}

#[async_trait]
impl SignaturePrivateKeyHandle for MlDsaPrivateKeyHandle {
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignerError> {
        MlDsaSigner.sign(message, &self.public_key, &self.private_key)
    }
}
