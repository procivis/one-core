use pqc_dilithium::*;

use crate::{Signer, SignerError};
pub struct CRYDI3Signer {}

impl Signer for CRYDI3Signer {
    fn sign(
        &self,
        input: &[u8],
        public_key: &[u8],
        private_key: &[u8],
    ) -> Result<Vec<u8>, SignerError> {
        let key_pair = Keypair::new(public_key.to_vec(), private_key.to_vec())
            .map_err(|_| SignerError::CouldNotExtractKeyPair)?;

        Ok(key_pair.sign(input).to_vec())
    }

    fn verify(&self, input: &[u8], signature: &[u8], public_key: &[u8]) -> Result<(), SignerError> {
        verify(signature, input, public_key).map_err(|_| SignerError::InvalidSignature)
    }
}
