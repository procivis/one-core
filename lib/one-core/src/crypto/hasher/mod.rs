use thiserror::Error;
pub mod sha256;

#[derive(Debug, PartialEq, Eq, Error)]
pub enum HasherError {
    #[error("Could not hash")]
    CouldNotHash,
}

pub trait Hasher {
    fn hash_base64(&self, input: &[u8]) -> Result<String, HasherError>;
}
