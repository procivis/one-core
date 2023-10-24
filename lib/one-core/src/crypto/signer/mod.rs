use thiserror::Error;

pub mod eddsa;

#[derive(Debug, PartialEq, Eq, Error)]
pub enum SignerError {
    #[error("Could not sign")]
    CouldNotSign,
    #[error("Could not extract keypair")]
    CouldNotExtractKeyPair,
    #[error("Could not extract public key")]
    CouldNotExtractPublicKey,
    #[error("Could not verify")]
    CouldNotVerify,
    #[error("Invalid signature")]
    InvalidSignature,
}

#[cfg_attr(test, mockall::automock)]
pub trait Signer {
    fn sign(
        &self,
        input: &str,
        public_key: &[u8],
        private_key: &[u8],
    ) -> Result<Vec<u8>, SignerError>;
    fn verify(&self, input: &str, signature: &[u8], public_key: &[u8]) -> Result<(), SignerError>;
}
