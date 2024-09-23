use crate::{Signer, SignerError};

pub struct EDDSASigner {}

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
