use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::KeyPair;
use aws_lc_rs::signature::{
    KeyPair as _, RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_SHA256, UnparsedPublicKey,
};
use secrecy::{ExposeSecret, SecretSlice};

use crate::{Signer, SignerError};

/// RSA PKCS#1 v1.5 with SHA-256 (JOSE `RS256`).
/// [RFC 7518 §3.3](https://www.rfc-editor.org/rfc/rfc7518#section-3.3).
pub struct RsaSigner;

impl RsaSigner {
    pub fn public_key(private_key: &SecretSlice<u8>) -> Result<Vec<u8>, SignerError> {
        Ok(key_pair(private_key)?.public_key().as_ref().to_vec())
    }
}

fn key_pair(private_key: &SecretSlice<u8>) -> Result<KeyPair, SignerError> {
    KeyPair::from_pkcs8(private_key.expose_secret())
        .map_err(|err| SignerError::CouldNotExtractPrivateKey(err.to_string()))
}

impl Signer for RsaSigner {
    fn sign(
        &self,
        input: &[u8],
        public_key: &[u8],
        private_key: &SecretSlice<u8>,
    ) -> Result<Vec<u8>, SignerError> {
        let key_pair = key_pair(private_key)?;
        if key_pair.public_key().as_ref() != public_key {
            return Err(SignerError::CouldNotExtractKeyPair);
        }
        let mut signature = vec![0; key_pair.public_modulus_len()];
        key_pair
            .sign(
                &RSA_PKCS1_SHA256,
                // aws-lc-rs handles randomness internally, this argument is ignored but part of the fn signature for ring compatibility
                &SystemRandom::new(),
                input,
                &mut signature,
            )
            .map_err(|err| SignerError::CouldNotSign(err.to_string()))?;
        Ok(signature)
    }

    fn verify(&self, input: &[u8], signature: &[u8], public_key: &[u8]) -> Result<(), SignerError> {
        UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, public_key)
            .verify(input, signature)
            .map_err(|_| SignerError::InvalidSignature)
    }
}

#[cfg(test)]
mod test {
    use aws_lc_rs::encoding::AsDer;
    use aws_lc_rs::rsa::KeySize;

    use super::*;

    #[test]
    fn sign_and_verify() {
        let private_key: SecretSlice<u8> = KeyPair::generate(KeySize::Rsa2048)
            .unwrap()
            .as_der()
            .unwrap()
            .as_ref()
            .to_vec()
            .into();
        let public_key = RsaSigner::public_key(&private_key).unwrap();

        let signature = RsaSigner.sign(b"input", &public_key, &private_key).unwrap();

        RsaSigner.verify(b"input", &signature, &public_key).unwrap();
        assert!(RsaSigner.verify(b"other", &signature, &public_key).is_err());
        assert!(RsaSigner.sign(b"input", b"other", &private_key).is_err());
    }
}
