//! https://www.w3.org/TR/vc-di-bbs/#bbs-2023

use std::sync::Arc;

use ct_codecs::{Base64UrlSafeNoPadding, Decoder, Encoder};
use one_crypto::signer::bbs::{BBSSigner, BbsDeriveInput, BbsProofInput};
use one_crypto::SignerError;
use secrecy::{ExposeSecret, SecretSlice, SecretString};

use crate::model::key::{PublicKeyJwk, PublicKeyJwkEllipticData};
use crate::provider::key_algorithm::error::KeyAlgorithmError;
use crate::provider::key_algorithm::key::{
    KeyHandle, KeyHandleError, MultiMessageSignatureKeyHandle,
    MultiMessageSignaturePrivateKeyHandle, MultiMessageSignaturePublicKeyHandle,
};
use crate::provider::key_algorithm::model::{GeneratedKey, KeyAlgorithmCapabilities};
use crate::provider::key_algorithm::KeyAlgorithm;

pub struct BBS;

#[cfg(test)]
mod test;

impl KeyAlgorithm for BBS {
    fn algorithm_id(&self) -> String {
        "BBS".to_string()
    }

    fn get_capabilities(&self) -> KeyAlgorithmCapabilities {
        KeyAlgorithmCapabilities { features: vec![] }
    }

    fn generate_key(&self) -> Result<GeneratedKey, KeyAlgorithmError> {
        let key_pair = BBSSigner::generate_key_pair();
        Ok(GeneratedKey {
            key: KeyHandle::MultiMessageSignature(MultiMessageSignatureKeyHandle::WithPrivateKey {
                private: Arc::new(BBSPrivateKeyHandle::new(
                    key_pair.private.clone(),
                    key_pair.public.clone(),
                )),
                public: Arc::new(BBSPublicKeyHandle::new(key_pair.public.clone(), None)),
            }),
            public: key_pair.public,
            private: SecretSlice::from(key_pair.private.expose_secret().to_vec()),
        })
    }

    fn reconstruct_key(
        &self,
        public_key: &[u8],
        private_key: Option<SecretSlice<u8>>,
        r#use: Option<String>,
    ) -> Result<KeyHandle, KeyAlgorithmError> {
        if let Some(private_key) = private_key {
            Ok(KeyHandle::MultiMessageSignature(
                MultiMessageSignatureKeyHandle::WithPrivateKey {
                    private: Arc::new(BBSPrivateKeyHandle::new(private_key, public_key.to_vec())),
                    public: Arc::new(BBSPublicKeyHandle::new(public_key.to_vec(), r#use)),
                },
            ))
        } else {
            Ok(KeyHandle::MultiMessageSignature(
                MultiMessageSignatureKeyHandle::PublicKeyOnly(Arc::new(BBSPublicKeyHandle::new(
                    public_key.to_vec(),
                    r#use,
                ))),
            ))
        }
    }

    fn issuance_jose_alg_id(&self) -> Option<String> {
        // invalid value for backward compatibility
        Some("BBS_PLUS".to_string())
    }

    fn verification_jose_alg_ids(&self) -> Vec<String> {
        // invalid value for backward compatibility
        vec!["BBS_PLUS".to_string()]
    }

    fn cose_alg_id(&self) -> Option<i32> {
        todo!()
    }

    fn parse_jwk(&self, key: &PublicKeyJwk) -> Result<KeyHandle, KeyAlgorithmError> {
        if let PublicKeyJwk::Okp(data) = key {
            let x = Base64UrlSafeNoPadding::decode_to_vec(&data.x, None)
                .map_err(|e| KeyAlgorithmError::Failed(e.to_string()))?;
            let y = Base64UrlSafeNoPadding::decode_to_vec(
                data.y
                    .as_ref()
                    .ok_or(KeyAlgorithmError::Failed("Y is missing".to_string()))?,
                None,
            )
            .map_err(|e| KeyAlgorithmError::Failed(e.to_string()))?;

            let public_key = BBSSigner::parse_public_key(&x, &y, true)?;

            Ok(KeyHandle::MultiMessageSignature(
                MultiMessageSignatureKeyHandle::PublicKeyOnly(Arc::new(BBSPublicKeyHandle::new(
                    public_key,
                    data.r#use.clone(),
                ))),
            ))
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

struct BBSPrivateKeyHandle {
    private_key: SecretSlice<u8>,
    public_key: Vec<u8>,
}

impl BBSPrivateKeyHandle {
    fn new(private_key: SecretSlice<u8>, public_key: Vec<u8>) -> Self {
        Self {
            private_key,
            public_key,
        }
    }
}

struct BBSPublicKeyHandle {
    public_key: Vec<u8>,
    r#use: Option<String>,
}

impl BBSPublicKeyHandle {
    fn new(public_key: Vec<u8>, r#use: Option<String>) -> Self {
        Self { public_key, r#use }
    }
}

impl MultiMessageSignaturePublicKeyHandle for BBSPublicKeyHandle {
    fn as_jwk(&self) -> Result<PublicKeyJwk, KeyHandleError> {
        let (x, y) = BBSSigner::get_public_key_coordinates(&self.public_key)
            .map_err(KeyHandleError::Signer)?;
        Ok(PublicKeyJwk::Okp(PublicKeyJwkEllipticData {
            r#use: self.r#use.clone(),
            kid: None,
            crv: "Bls12381G2".to_string(),
            x: Base64UrlSafeNoPadding::encode_to_string(x)
                .map_err(|e| KeyHandleError::EncodingJwk(e.to_string()))?,
            y: Some(
                Base64UrlSafeNoPadding::encode_to_string(y)
                    .map_err(|e| KeyHandleError::EncodingJwk(e.to_string()))?,
            ),
        }))
    }

    fn as_multibase(&self) -> Result<String, KeyHandleError> {
        let codec: &[u8; 2] = &[0xeb, 0x01];
        let data = [codec, self.public_key.as_slice()].concat();
        Ok(format!("z{}", bs58::encode(data).into_string()))
    }

    fn as_raw(&self) -> Vec<u8> {
        self.public_key.clone()
    }

    fn verify_signature(
        &self,
        header: Vec<u8>,
        messages: Vec<Vec<u8>>,
        signature: &[u8],
    ) -> Result<(), SignerError> {
        BBSSigner::verify_bbs(header, messages, signature, &self.public_key)
    }

    fn derive_proof(
        &self,
        header: Vec<u8>,
        messages: Vec<(Vec<u8>, bool)>,
        signature: Vec<u8>,
    ) -> Result<Vec<u8>, SignerError> {
        let derive_input = BbsDeriveInput {
            header,
            messages,
            signature,
        };

        BBSSigner::derive_proof(&derive_input, &self.public_key)
    }

    fn verify_proof(
        &self,
        header: Vec<u8>,
        messages: Vec<(usize, Vec<u8>)>,
        presentation_header: Option<Vec<u8>>,
        proof: &[u8],
    ) -> Result<(), SignerError> {
        let input = BbsProofInput {
            header,
            presentation_header,
            proof: proof.to_vec(),
            messages,
        };

        BBSSigner::verify_proof(&input, &self.public_key)
    }
}

impl MultiMessageSignaturePrivateKeyHandle for BBSPrivateKeyHandle {
    fn sign(&self, header: Vec<u8>, messages: Vec<Vec<u8>>) -> Result<Vec<u8>, SignerError> {
        BBSSigner::sign_bbs(header, messages, &self.private_key, &self.public_key)
    }

    fn as_jwk(&self) -> Result<SecretString, KeyHandleError> {
        todo!()
    }
}
