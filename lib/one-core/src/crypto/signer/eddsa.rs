use super::{Signer, SignerError};

pub struct EDDSASigner {}

impl Signer for EDDSASigner {
    fn sign(&self, input: &str, key_pair: &[u8]) -> Result<Vec<u8>, SignerError> {
        let ed25519_kp = ed25519_compact::KeyPair::from_slice(key_pair)
            .map_err(|_| SignerError::CouldNotExtractKeyPair)?;
        Ok(ed25519_kp.sk.sign(input, None).to_vec())
    }

    fn verify(&self, input: &str, signature: &[u8], public_key: &[u8]) -> Result<(), SignerError> {
        let ed25519_pk = ed25519_compact::PublicKey::from_slice(public_key)
            .map_err(|_| SignerError::CouldNotExtractKeyPair)?;

        let ed25519_signature = ed25519_compact::Signature::from_slice(signature)
            .map_err(|_| SignerError::CouldNotVerify)?;

        ed25519_pk
            .verify(input, &ed25519_signature)
            .map_err(|_| SignerError::InvalidSignature)?;
        Ok(())
    }
}
