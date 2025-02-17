//! https://datatracker.ietf.org/doc/html/draft-ietf-cose-dilithium-01

use std::sync::Arc;

use async_trait::async_trait;
use ct_codecs::{Base64UrlSafeNoPadding, Decoder, Encoder};
use one_crypto::signer::crydi3::CRYDI3Signer;
use one_crypto::{Signer, SignerError};
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::model::key::{PublicKeyJwk, PublicKeyJwkMlweData};
use crate::provider::key_algorithm::error::KeyAlgorithmError;
use crate::provider::key_algorithm::key::{
    KeyHandle, KeyHandleError, SignatureKeyHandle, SignaturePrivateKeyHandle,
    SignaturePublicKeyHandle,
};
use crate::provider::key_algorithm::model::{GeneratedKey, KeyAlgorithmCapabilities};
use crate::provider::key_algorithm::KeyAlgorithm;

pub struct MlDsa;

#[cfg(test)]
mod test;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MlDsaParams {
    algorithm: Algorithm,
}

#[derive(Deserialize)]
enum Algorithm {
    #[serde(rename = "CRYDI3")]
    Crydi3,
}

impl MlDsa {
    pub fn new(params: MlDsaParams) -> Self {
        _ = params.algorithm;
        Self
    }
}

impl KeyAlgorithm for MlDsa {
    fn algorithm_id(&self) -> String {
        "DILITHIUM".to_string()
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
        private_key: Option<Zeroizing<Vec<u8>>>,
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
            if !self
                .verification_jose_alg_ids()
                .iter()
                .any(|value| *value == data.alg)
            {
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
    private_key: Zeroizing<Vec<u8>>,
    public_key: Vec<u8>,
}

impl MlDsaPrivateKeyHandle {
    fn new(private_key: Zeroizing<Vec<u8>>, public_key: Vec<u8>) -> Self {
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

    fn as_jwk(&self) -> Result<Zeroizing<String>, KeyHandleError> {
        todo!()
    }
}
