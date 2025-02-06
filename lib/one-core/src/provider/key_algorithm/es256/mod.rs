use std::sync::Arc;

use ct_codecs::{Base64UrlSafeNoPadding, Decoder, Encoder};
use one_crypto::signer::es256::ES256Signer;
use one_crypto::{Signer, SignerError};
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::model::key::{PublicKeyJwk, PublicKeyJwkEllipticData};
use crate::provider::key_algorithm::error::KeyAlgorithmError;
use crate::provider::key_algorithm::key::{
    KeyHandle, KeyHandleError, SignatureKeyHandle, SignaturePrivateKeyHandle,
    SignaturePublicKeyHandle,
};
use crate::provider::key_algorithm::model::{Features, GeneratedKey, KeyAlgorithmCapabilities};
use crate::provider::key_algorithm::KeyAlgorithm;

pub struct Es256;

#[cfg(test)]
mod test;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Es256Params {
    pub algorithm: Algorithm,
}

#[derive(Deserialize)]
pub enum Algorithm {
    #[serde(rename = "ES256")]
    Es256,
}

impl Es256 {
    pub fn new(params: Es256Params) -> Self {
        _ = params.algorithm;
        Self
    }
}

impl KeyAlgorithm for Es256 {
    fn algorithm_id(&self) -> String {
        "ES256".to_string()
    }

    fn get_capabilities(&self) -> KeyAlgorithmCapabilities {
        KeyAlgorithmCapabilities {
            features: vec![Features::GenerateCSR],
        }
    }

    fn generate_key(&self) -> Result<GeneratedKey, KeyAlgorithmError> {
        let (private, public) = ES256Signer::generate_key_pair();

        Ok(GeneratedKey {
            key: KeyHandle::SignatureOnly(SignatureKeyHandle::WithPrivateKey {
                private: Arc::new(Es256PrivateKeyHandle::new(private.clone(), public.clone())),
                public: Arc::new(Es256PublicKeyHandle::new(public.clone(), None)),
            }),
            public,
            private,
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
                    private: Arc::new(Es256PrivateKeyHandle::new(private_key, public_key.to_vec())),
                    public: Arc::new(Es256PublicKeyHandle::new(public_key.to_vec(), r#use)),
                },
            ))
        } else {
            Ok(KeyHandle::SignatureOnly(SignatureKeyHandle::PublicKeyOnly(
                Arc::new(Es256PublicKeyHandle::new(public_key.to_vec(), r#use)),
            )))
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

            let public_key = ES256Signer::parse_public_key_coordinates(&x, &y, true)?;
            Ok(KeyHandle::SignatureOnly(SignatureKeyHandle::PublicKeyOnly(
                Arc::new(Es256PublicKeyHandle::new(public_key, data.r#use.clone())),
            )))
        } else {
            Err(KeyAlgorithmError::Failed("invalid kty".to_string()))
        }
    }

    fn parse_multibase(&self, _multibase: &str) -> Result<KeyHandle, KeyAlgorithmError> {
        todo!()
    }

    fn parse_raw(&self, public_key_der: &[u8]) -> Result<KeyHandle, KeyAlgorithmError> {
        let public_key = ES256Signer::parse_public_key_from_der(public_key_der, true)?;
        Ok(KeyHandle::SignatureOnly(SignatureKeyHandle::PublicKeyOnly(
            Arc::new(Es256PublicKeyHandle::new(public_key, None)),
        )))
    }
}

struct Es256PublicKeyHandle {
    public_key: Vec<u8>,
    r#use: Option<String>,
}

impl Es256PublicKeyHandle {
    fn new(public_key: Vec<u8>, r#use: Option<String>) -> Self {
        Self { public_key, r#use }
    }
}

struct Es256PrivateKeyHandle {
    private_key: Zeroizing<Vec<u8>>,
    public_key: Vec<u8>,
}

impl Es256PrivateKeyHandle {
    fn new(private_key: Zeroizing<Vec<u8>>, public_key: Vec<u8>) -> Self {
        Self {
            private_key,
            public_key,
        }
    }
}

impl SignaturePublicKeyHandle for Es256PublicKeyHandle {
    fn as_jwk(&self) -> Result<PublicKeyJwk, KeyHandleError> {
        let (x, y) = ES256Signer::get_public_key_coordinates(&self.public_key)
            .map_err(KeyHandleError::Signer)?;
        Ok(PublicKeyJwk::Ec(PublicKeyJwkEllipticData {
            r#use: self.r#use.clone(),
            kid: None,
            crv: "P-256".to_string(),
            x: Base64UrlSafeNoPadding::encode_to_string(x)
                .map_err(|e| KeyHandleError::EncodingJwk(e.to_string()))?,
            y: Some(
                Base64UrlSafeNoPadding::encode_to_string(y)
                    .map_err(|e| KeyHandleError::EncodingJwk(e.to_string()))?,
            ),
        }))
    }

    fn as_multibase(&self) -> Result<String, KeyHandleError> {
        let codec = &[0x80, 0x24];
        let key = ES256Signer::parse_public_key(&self.public_key, true)
            .map_err(|e| KeyHandleError::EncodingMultibase(e.to_string()))?;
        let data = [codec, key.as_slice()].concat();
        Ok(format!("z{}", bs58::encode(data).into_string()))
    }

    fn as_raw(&self) -> Vec<u8> {
        self.public_key.clone()
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), SignerError> {
        ES256Signer {}.verify(message, signature, &self.public_key)
    }
}

#[async_trait::async_trait]
impl SignaturePrivateKeyHandle for Es256PrivateKeyHandle {
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignerError> {
        ES256Signer {}.sign(message, &self.public_key, &self.private_key)
    }

    fn as_jwk(&self) -> Result<Zeroizing<String>, KeyHandleError> {
        ES256Signer::private_key_as_jwk(&self.private_key)
            .map_err(|e| KeyHandleError::EncodingPrivateJwk(e.to_string()))
    }
}
