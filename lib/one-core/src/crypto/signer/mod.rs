use self::error::SignerError;

pub mod eddsa;
pub mod error;

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
