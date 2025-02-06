use std::sync::Arc;

use ct_codecs::{Base64UrlSafeNoPadding, Decoder, Encoder};
use one_crypto::signer::bbs::BBSSigner;
use one_crypto::SignerError;
use pairing_crypto::bbs::ciphersuites::bls12_381::{PublicKey, SecretKey};
use pairing_crypto::bbs::ciphersuites::bls12_381_g1_sha_256::{proof_verify, sign, verify};
use pairing_crypto::bbs::{BbsProofVerifyRequest, BbsSignRequest, BbsVerifyRequest};
use zeroize::Zeroizing;

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
            private: Zeroizing::new(key_pair.private.to_vec()),
        })
    }

    fn reconstruct_key(
        &self,
        public_key: &[u8],
        private_key: Option<Zeroizing<Vec<u8>>>,
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
    private_key: Zeroizing<Vec<u8>>,
    public_key: Vec<u8>,
}

impl BBSPrivateKeyHandle {
    fn new(private_key: Zeroizing<Vec<u8>>, public_key: Vec<u8>) -> Self {
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
        header: Option<Vec<u8>>,
        messages: Option<Vec<Vec<u8>>>,
        signature: &[u8],
    ) -> Result<(), SignerError> {
        let header = header.ok_or(SignerError::CouldNotSign("missing header".to_string()))?;
        let messages = messages.ok_or(SignerError::CouldNotSign("missing messages".to_string()))?;

        let public_key = PublicKey::from_vec(&self.public_key)
            .map_err(|e| SignerError::CouldNotExtractPublicKey(e.to_string()))?;

        let result = verify(&BbsVerifyRequest {
            public_key: &public_key.to_octets(),
            header: Some(header),
            messages: Some(&messages),
            signature: signature
                .try_into()
                .map_err(|_| SignerError::InvalidSignature)?,
        })
        .map_err(|err| SignerError::CouldNotVerify(format!("couldn't verify: {err}")))?;

        if !result {
            return Err(SignerError::InvalidSignature);
        }

        Ok(())
    }

    fn derive_proof(
        &self,
        _header: Option<Vec<u8>>,
        _messages: Option<Vec<(Vec<u8>, bool)>>,
        _presentation_header: Option<Vec<u8>>,
        _signature: &[u8],
    ) -> Result<Vec<u8>, SignerError> {
        todo!()
    }

    fn verify_proof(
        &self,
        header: Option<Vec<u8>>,
        messages: Option<Vec<(usize, Vec<u8>)>>,
        presentation_header: Option<Vec<u8>>,
        proof: &[u8],
    ) -> Result<(), SignerError> {
        let header = header.ok_or(SignerError::CouldNotSign("missing header".to_string()))?;
        let messages = messages.ok_or(SignerError::CouldNotSign("missing messages".to_string()))?;

        let public_key = PublicKey::from_vec(&self.public_key)
            .map_err(|e| SignerError::CouldNotExtractPublicKey(e.to_string()))?;

        let verified = proof_verify(&BbsProofVerifyRequest {
            public_key: &public_key.to_octets(),
            proof,
            header: Some(header),
            messages: Some(messages.as_slice()),
            presentation_header,
        })
        .map_err(|e| SignerError::CouldNotVerify(e.to_string()));

        if !(verified?) {
            return Err(SignerError::CouldNotVerify(
                "Bbs proof verification error".to_owned(),
            ));
        }

        Ok(())
    }
}

impl MultiMessageSignaturePrivateKeyHandle for BBSPrivateKeyHandle {
    fn sign(
        &self,
        header: Option<Vec<u8>>,
        messages: Option<Vec<Vec<u8>>>,
    ) -> Result<Vec<u8>, SignerError> {
        let header = header.ok_or(SignerError::CouldNotSign("missing header".to_string()))?;
        let messages = messages.ok_or(SignerError::CouldNotSign("missing messages".to_string()))?;

        let secret_key = SecretKey::from_vec(&self.private_key)
            .map_err(|_| SignerError::CouldNotExtractKeyPair)?;
        let public_key = PublicKey::from_vec(&self.public_key)
            .map_err(|e| SignerError::CouldNotExtractPublicKey(e.to_string()))?;

        let signature = sign(&BbsSignRequest {
            secret_key: &secret_key.to_bytes(),
            public_key: &public_key.to_octets(),
            header: Some(header),
            messages: Some(&messages),
        })
        .map_err(|e| SignerError::CouldNotSign(e.to_string()))?;
        Ok(signature.to_vec())
    }

    fn as_jwk(&self) -> Result<Zeroizing<String>, KeyHandleError> {
        todo!()
    }
}
