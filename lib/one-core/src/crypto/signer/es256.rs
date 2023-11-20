use super::{Signer, SignerError};
use did_key::{CoreSign, Generate, KeyMaterial, P256KeyPair};

pub struct ES256Signer {}

impl Signer for ES256Signer {
    fn sign(
        &self,
        input: &str,
        public_key: &[u8],
        private_key: &[u8],
    ) -> Result<Vec<u8>, SignerError> {
        let key = P256KeyPair::from_secret_key(private_key);
        if key.public_key_bytes() != public_key {
            return Err(SignerError::CouldNotExtractKeyPair);
        }

        Ok(key.sign(input.as_bytes()).to_vec())
    }

    fn verify(&self, input: &str, signature: &[u8], public_key: &[u8]) -> Result<(), SignerError> {
        let es256_pk = P256KeyPair::from_public_key(public_key);
        es256_pk
            .verify(input.as_bytes(), signature)
            .map_err(|_| SignerError::InvalidSignature)?;

        Ok(())
    }
}
