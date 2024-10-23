use ed25519_compact::PublicKey;
use zeroize::Zeroizing;

use crate::{Signer, SignerError};

pub struct EDDSASigner {}

pub struct KeyPair {
    pub public: Vec<u8>,
    pub private: Zeroizing<Vec<u8>>,
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

    pub fn parse_private_key(secret_key: &[u8]) -> Result<KeyPair, SignerError> {
        let secret_key = ed25519_compact::SecretKey::from_slice(secret_key)
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
        private_key_eddsa: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, SignerError> {
        let key = ed25519_compact::SecretKey::from_slice(private_key_eddsa)
            .map_err(|_| SignerError::CouldNotExtractKeyPair)?;
        let key = ed25519_compact::x25519::SecretKey::from_ed25519(&key)
            .map_err(|_| SignerError::CouldNotExtractKeyPair)?;
        Ok(key.to_vec().into())
    }
}

impl Signer for EDDSASigner {
    fn sign(
        &self,
        input: &[u8],
        public_key: &[u8],
        private_key: &[u8],
    ) -> Result<Vec<u8>, SignerError> {
        let ed25519_kp = ed25519_compact::KeyPair::from_slice(private_key)
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
