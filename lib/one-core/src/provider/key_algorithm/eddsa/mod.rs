//! https://datatracker.ietf.org/doc/html/rfc8037

use std::sync::Arc;

use async_trait::async_trait;
use ct_codecs::{Base64UrlSafeNoPadding, Decoder, Encoder};
use one_crypto::Signer;
use one_crypto::encryption::EncryptionError;
use one_crypto::jwe::PrivateKeyAgreementHandle;
use one_crypto::signer::eddsa::EDDSASigner;
use secrecy::{ExposeSecret, SecretSlice};
use standardized_types::jwk::{JwkUse, PrivateJwk, PublicJwk, PublicJwkEc};

use crate::config::core_config::KeyAlgorithmType;
use crate::error::ContextWithErrorCode;
use crate::provider::key_algorithm::error::KeyAlgorithmError;
use crate::provider::key_algorithm::key::{
    KeyAgreementHandle, KeyHandle, KeyHandleError, PublicKeyAgreementHandle, SignatureKeyHandle,
    SignaturePrivateKeyHandle, SignaturePublicKeyHandle,
};
use crate::provider::key_algorithm::model::{Features, GeneratedKey, KeyAlgorithmCapabilities};
use crate::provider::key_algorithm::{KeyAlgorithm, parse_multibase_with_tag};

pub struct Eddsa;

#[cfg(test)]
mod test;

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
        let public_handle = Arc::new(
            EddsaPublicKeyHandle::new(key_pair.public.clone(), None)
                .error_while("creating public key handle")?,
        );

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
        r#use: Option<JwkUse>,
    ) -> Result<KeyHandle, KeyAlgorithmError> {
        if let Some(private_key) = private_key {
            let private_handle =
                Arc::new(EddsaPrivateKeyHandle::new(private_key, public_key.to_vec()));
            let public_handle = Arc::new(
                EddsaPublicKeyHandle::new(public_key.to_vec(), r#use)
                    .error_while("creating public key handle")?,
            );

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
            let public_handle = Arc::new(
                EddsaPublicKeyHandle::new(public_key.to_vec(), r#use)
                    .error_while("creating public key handle")?,
            );

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

    fn parse_jwk(&self, key: &PublicJwk) -> Result<KeyHandle, KeyAlgorithmError> {
        let PublicJwk::Okp(data) = key else {
            return Err(KeyAlgorithmError::InvalidKeyType);
        };

        match data.crv.as_str() {
            "Ed25519" => {
                let x = Base64UrlSafeNoPadding::decode_to_vec(&data.x, None)?;
                let handle = Arc::new(
                    EddsaPublicKeyHandle::new(x, data.r#use.clone())
                        .error_while("creating public key handle")?,
                );
                Ok(KeyHandle::SignatureAndKeyAgreement {
                    signature: SignatureKeyHandle::PublicKeyOnly(handle.clone()),
                    key_agreement: KeyAgreementHandle::PublicKeyOnly(handle),
                })
            }
            "X25519" => {
                if data.r#use == Some(JwkUse::Signature) {
                    return Err(KeyAlgorithmError::InvalidUse(JwkUse::Signature));
                }

                let x = Base64UrlSafeNoPadding::decode_to_vec(&data.x, None)?;
                let handle = Arc::new(X25519PublicKeyHandle::new(x));
                Ok(KeyHandle::KeyAgreementOnly(
                    KeyAgreementHandle::PublicKeyOnly(handle),
                ))
            }
            other_crv => Err(KeyAlgorithmError::NotSupported(format!("crv: {other_crv}"))),
        }
    }

    fn parse_private_jwk(&self, jwk: PrivateJwk) -> Result<GeneratedKey, KeyAlgorithmError> {
        match jwk {
            PrivateJwk::Okp(data) => {
                if data.crv != "Ed25519" {
                    return Err(KeyAlgorithmError::NotSupported(format!("crv {}", data.crv)));
                }
                let d: SecretSlice<u8> =
                    Base64UrlSafeNoPadding::decode_to_vec(data.d.expose_secret(), None)?.into();

                let keys = EDDSASigner::parse_key_pair(&d)?;

                let key =
                    self.reconstruct_key(&keys.public, Some(keys.private.clone()), data.r#use)?;
                Ok(GeneratedKey {
                    key,
                    public: keys.public,
                    private: keys.private,
                })
            }
            _ => Err(KeyAlgorithmError::InvalidKeyType),
        }
    }

    fn parse_multibase(&self, multibase: &str) -> Result<KeyHandle, KeyAlgorithmError> {
        let raw_pubkey = parse_multibase_with_tag(multibase, &[0xed, 0x01])?;
        self.reconstruct_key(&raw_pubkey, None, None)
    }

    fn parse_raw(&self, public_key_der: &[u8]) -> Result<KeyHandle, KeyAlgorithmError> {
        let key = EDDSASigner::public_key_from_der(public_key_der)?;
        let handle = Arc::new(
            EddsaPublicKeyHandle::new(key, None).error_while("creating public key handle")?,
        );
        Ok(KeyHandle::SignatureAndKeyAgreement {
            signature: SignatureKeyHandle::PublicKeyOnly(handle.clone()),
            key_agreement: KeyAgreementHandle::PublicKeyOnly(handle),
        })
    }
}

struct EddsaPublicKeyHandle {
    public_key: Vec<u8>,
    public_key_x25519: Vec<u8>,
    r#use: Option<JwkUse>,
}

impl EddsaPublicKeyHandle {
    fn new(public_key: Vec<u8>, r#use: Option<JwkUse>) -> Result<Self, KeyHandleError> {
        Ok(Self {
            public_key_x25519: EDDSASigner::public_key_into_x25519(&public_key)?,
            public_key,
            r#use,
        })
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
    fn as_jwk(&self) -> Result<PublicJwk, KeyHandleError> {
        eddsa_public_key_as_jwk(&self.public_key, "Ed25519", self.r#use.clone())
    }

    fn as_multibase(&self) -> Result<String, KeyHandleError> {
        eddsa_public_key_as_multibase(&self.public_key)
    }

    fn as_raw(&self) -> Vec<u8> {
        self.public_key.clone()
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), KeyHandleError> {
        Ok(EDDSASigner.verify(message, signature, &self.public_key)?)
    }
}

#[async_trait]
impl SignaturePrivateKeyHandle for EddsaPrivateKeyHandle {
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, KeyHandleError> {
        Ok(EDDSASigner.sign(message, &self.public_key, &self.private_key)?)
    }
}

#[async_trait]
impl PrivateKeyAgreementHandle for EddsaPrivateKeyHandle {
    async fn shared_secret(
        &self,
        remote_jwk: &PublicJwk,
    ) -> Result<SecretSlice<u8>, EncryptionError> {
        EDDSASigner::shared_secret_x25519(&self.private_key, remote_jwk)
    }
}

impl PublicKeyAgreementHandle for EddsaPublicKeyHandle {
    fn as_jwk(&self) -> Result<PublicJwk, KeyHandleError> {
        Ok(PublicJwk::Okp(PublicJwkEc {
            alg: Some("ECDH-ES".to_string()),
            // the only possible use for a x25519 key
            r#use: Some(JwkUse::Encryption),
            kid: None,
            crv: "X25519".to_string(),
            x: Base64UrlSafeNoPadding::encode_to_string(&self.public_key_x25519)?,
            y: None,
        }))
    }

    fn as_multibase(&self) -> Result<String, KeyHandleError> {
        x25519_public_key_as_multibase(&self.public_key_x25519)
    }

    fn as_raw(&self) -> Vec<u8> {
        self.public_key_x25519.to_owned()
    }
}

struct X25519PublicKeyHandle {
    public_key: Vec<u8>,
}

impl X25519PublicKeyHandle {
    fn new(public_key: Vec<u8>) -> Self {
        Self { public_key }
    }
}

impl PublicKeyAgreementHandle for X25519PublicKeyHandle {
    fn as_jwk(&self) -> Result<PublicJwk, KeyHandleError> {
        Ok(PublicJwk::Okp(PublicJwkEc {
            alg: Some("ECDH-ES".to_string()),
            // the only possible use for a x25519 key
            r#use: Some(JwkUse::Encryption),
            kid: None,
            crv: "X25519".to_string(),
            x: Base64UrlSafeNoPadding::encode_to_string(&self.public_key)?,
            y: None,
        }))
    }

    fn as_multibase(&self) -> Result<String, KeyHandleError> {
        x25519_public_key_as_multibase(&self.public_key)
    }

    fn as_raw(&self) -> Vec<u8> {
        self.public_key.clone()
    }
}

pub(crate) fn eddsa_public_key_as_jwk(
    public_key: &[u8],
    curve: &str,
    r#use: Option<JwkUse>,
) -> Result<PublicJwk, KeyHandleError> {
    let alg = match r#use {
        Some(JwkUse::Encryption) => Some("ECDH-ES".to_string()),
        Some(JwkUse::Signature) => Some("EdDSA".to_string()),
        _ => None,
    };
    Ok(PublicJwk::Okp(PublicJwkEc {
        alg,
        r#use,
        kid: None,
        crv: curve.to_string(),
        x: Base64UrlSafeNoPadding::encode_to_string(public_key)?,
        y: None,
    }))
}

pub(crate) fn eddsa_public_key_as_multibase(public_key: &[u8]) -> Result<String, KeyHandleError> {
    let codec = &[0xed, 0x1];
    let key = EDDSASigner::check_public_key(public_key)?;
    let data = [codec, key.as_slice()].concat();
    Ok(format!("z{}", bs58::encode(data).into_string()))
}

pub(crate) fn x25519_public_key_as_multibase(public_key: &[u8]) -> Result<String, KeyHandleError> {
    let codec = &[0xec, 0x1];
    let key = EDDSASigner::check_x25519_public_key(public_key)?;
    let data = [codec, key.as_slice()].concat();
    Ok(format!("z{}", bs58::encode(data).into_string()))
}
