use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use ed25519_compact::{PublicKey, x25519};
use secrecy::{ExposeSecret, SecretSlice};

use crate::encryption::EncryptionError;
use crate::jwe::{RemoteJwk, decode_b64};
use crate::{Signer, SignerError};

pub struct EDDSASigner {}

pub struct KeyPair {
    pub public: Vec<u8>,
    pub private: SecretSlice<u8>,
}

impl EDDSASigner {
    pub fn check_public_key(public_key: &[u8]) -> Result<Vec<u8>, SignerError> {
        let key = PublicKey::from_slice(public_key)
            .map_err(|e| SignerError::CouldNotExtractPublicKey(e.to_string()))?;
        Ok(key.to_vec())
    }

    pub fn public_key_from_der(public_key_der: &[u8]) -> Result<Vec<u8>, SignerError> {
        let pk = ed25519_compact::PublicKey::from_der(public_key_der)
            .map_err(|e| SignerError::CouldNotExtractPublicKey(e.to_string()))?;
        Ok(pk.to_vec())
    }

    pub fn generate_key_pair() -> KeyPair {
        let key_pair = ed25519_compact::KeyPair::generate();

        KeyPair {
            public: key_pair.pk.to_vec(),
            private: key_pair.sk.to_vec().into(),
        }
    }

    pub fn parse_private_key(secret_key: &SecretSlice<u8>) -> Result<KeyPair, SignerError> {
        let secret_key = ed25519_compact::SecretKey::from_slice(secret_key.expose_secret())
            .map_err(|_| SignerError::CouldNotExtractKeyPair)?;
        let public_key = secret_key.public_key();

        Ok(KeyPair {
            public: public_key.to_vec(),
            private: secret_key.to_vec().into(),
        })
    }

    pub fn public_key_into_x25519(public_key_eddsa: &[u8]) -> Result<Vec<u8>, SignerError> {
        let key = ed25519_compact::PublicKey::from_slice(public_key_eddsa)
            .map_err(|e| SignerError::CouldNotExtractPublicKey(e.to_string()))?;
        let key = ed25519_compact::x25519::PublicKey::from_ed25519(&key)
            .map_err(|e| SignerError::CouldNotExtractPublicKey(e.to_string()))?;
        Ok(key.to_vec())
    }

    pub fn private_key_into_x25519(
        private_key_eddsa: &SecretSlice<u8>,
    ) -> Result<SecretSlice<u8>, SignerError> {
        let key = ed25519_compact::SecretKey::from_slice(private_key_eddsa.expose_secret())
            .map_err(|_| SignerError::CouldNotExtractKeyPair)?;
        let key = ed25519_compact::x25519::SecretKey::from_ed25519(&key)
            .map_err(|_| SignerError::CouldNotExtractKeyPair)?;
        Ok(key.to_vec().into())
    }

    pub fn shared_secret_x25519(
        private_key_ed25519: &SecretSlice<u8>,
        recipient_jwk: &RemoteJwk,
    ) -> Result<SecretSlice<u8>, EncryptionError> {
        let secret_key =
            ed25519_compact::SecretKey::from_slice(private_key_ed25519.expose_secret())
                .map_err(|e| EncryptionError::Crypto(e.to_string()))?;
        let secret_x25519 = x25519::SecretKey::from_ed25519(&secret_key)
            .map_err(|e| EncryptionError::Crypto(e.to_string()))?;

        let peer_pub_key = Self::get_public_key_from_jwk(recipient_jwk)?;

        let shared_secret = *peer_pub_key.dh(&secret_x25519).map_err(|e| {
            EncryptionError::Crypto(format!("Failed to derive shared secret: {}", e))
        })?;
        Ok(SecretSlice::from(shared_secret.to_vec()))
    }

    pub fn ed25519_to_x25519_jwk(public_key_ed25519: &[u8]) -> Result<RemoteJwk, EncryptionError> {
        let public_key = ed25519_compact::PublicKey::from_slice(public_key_ed25519)
            .map_err(|e| EncryptionError::Crypto(e.to_string()))?;
        let public_x25519 = x25519::PublicKey::from_ed25519(&public_key)
            .map_err(|e| EncryptionError::Crypto(e.to_string()))?;

        Ok(RemoteJwk {
            kty: "OKP".to_string(),
            crv: "X25519".to_string(),
            x: Base64UrlSafeNoPadding::encode_to_string(public_x25519.to_vec()).map_err(|e| {
                EncryptionError::Crypto(format!("Failed to serialize public key bytes: {}", e))
            })?,
            y: None,
        })
    }

    fn get_public_key_from_jwk(
        remote_jwk: &RemoteJwk,
    ) -> Result<x25519::PublicKey, EncryptionError> {
        match remote_jwk.crv.as_str() {
            "Ed25519" => {
                let ed25519_pub_key = Self::ed25519_pub_key_from_jwk(remote_jwk)?;
                x25519::PublicKey::from_ed25519(&ed25519_pub_key).map_err(|e| {
                    EncryptionError::Crypto(format!(
                        "failed to convert ed25519 public key to x25519: {}",
                        e
                    ))
                })
            }
            "X25519" => Self::x25519_pub_key_from_jwk(remote_jwk),
            _ => Err(EncryptionError::Crypto("Invalid JWK crv".to_string())),
        }
    }

    fn x25519_pub_key_from_jwk(
        remote_jwk: &RemoteJwk,
    ) -> Result<x25519::PublicKey, EncryptionError> {
        let x = decode_b64(remote_jwk.x.as_str(), "x coordinate")?;
        let pub_key = x25519::PublicKey::from_slice(&x).map_err(|e| {
            EncryptionError::Crypto(format!("Failed to decode peer public key: {}", e))
        })?;
        Ok(pub_key)
    }

    fn ed25519_pub_key_from_jwk(
        remote_jwk: &RemoteJwk,
    ) -> Result<ed25519_compact::PublicKey, EncryptionError> {
        let x = decode_b64(remote_jwk.x.as_str(), "x coordinate")?;
        let pub_key = ed25519_compact::PublicKey::from_slice(&x).map_err(|e| {
            EncryptionError::Crypto(format!("Failed to decode peer public key: {}", e))
        })?;
        Ok(pub_key)
    }
}

impl Signer for EDDSASigner {
    fn sign(
        &self,
        input: &[u8],
        public_key: &[u8],
        private_key: &SecretSlice<u8>,
    ) -> Result<Vec<u8>, SignerError> {
        let ed25519_kp = ed25519_compact::KeyPair::from_slice(private_key.expose_secret())
            .map_err(|_| SignerError::CouldNotExtractKeyPair)?;

        if ed25519_kp.pk.as_slice() != public_key {
            return Err(SignerError::CouldNotExtractKeyPair);
        }

        Ok(ed25519_kp.sk.sign(input, None).to_vec())
    }

    fn verify(&self, input: &[u8], signature: &[u8], public_key: &[u8]) -> Result<(), SignerError> {
        let ed25519_pk = ed25519_compact::PublicKey::from_slice(public_key)
            .map_err(|_| SignerError::CouldNotExtractKeyPair)?;

        let ed25519_signature = ed25519_compact::Signature::from_slice(signature)
            .map_err(|e| SignerError::CouldNotVerify(e.to_string()))?;

        ed25519_pk
            .verify(input, &ed25519_signature)
            .map_err(|_| SignerError::InvalidSignature)?;
        Ok(())
    }
}
