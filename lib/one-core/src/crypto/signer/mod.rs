use thiserror::Error;

pub mod eddsa;

#[derive(Debug, PartialEq, Eq, Error)]
pub enum SignerError {
    #[error("Could not sign")]
    CouldNotSign,
    #[error("Could not extract keypair")]
    CouldNotExtractKeyPair,
    #[error("Could not extract public key: `{0}`")]
    CouldNotExtractPublicKey(String),
    #[error("Could not verify: `{0}`")]
    CouldNotVerify(String),
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Missing algorithm `{0}`")]
    MissingAlgorithm(String),
    #[error("Missing key")]
    MissingKey,
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
