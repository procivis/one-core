use self::error::SignerError;

pub mod crydi3;
pub mod eddsa;
pub mod error;
pub mod es256;

#[cfg_attr(test, mockall::automock)]
pub trait Signer: Send + Sync {
    fn sign(
        &self,
        input: &[u8],
        public_key: &[u8],
        private_key: &[u8],
    ) -> Result<Vec<u8>, SignerError>;
    fn verify(&self, input: &[u8], signature: &[u8], public_key: &[u8]) -> Result<(), SignerError>;
}
