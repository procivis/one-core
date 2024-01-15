use super::{Signer, SignerError};
use pqc_dilithium::*;
pub struct CRYDI3Signer {}

impl Signer for CRYDI3Signer {
    fn sign(
        &self,
        input: &str,
        public_key: &[u8],
        private_key: &[u8],
    ) -> Result<Vec<u8>, SignerError> {
        let key_pair = Keypair::new(public_key.to_vec(), private_key.to_vec())
            .map_err(|_| SignerError::CouldNotExtractKeyPair)?;

        Ok(key_pair.sign(input.as_bytes()).to_vec())
    }

    fn verify(&self, input: &str, signature: &[u8], public_key: &[u8]) -> Result<(), SignerError> {
        verify(signature, input.as_bytes(), public_key).map_err(|_| SignerError::InvalidSignature)
    }
}
