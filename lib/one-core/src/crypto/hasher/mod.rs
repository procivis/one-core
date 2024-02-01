use self::error::HasherError;

pub mod error;
pub mod sha256;

#[cfg_attr(test, mockall::automock)]
pub trait Hasher: Send + Sync {
    fn hash_base64(&self, input: &[u8]) -> Result<String, HasherError>;
    fn hash(&self, input: &[u8]) -> Result<Vec<u8>, HasherError>;
}
