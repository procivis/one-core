use self::error::HasherError;

pub mod error;
pub mod sha256;

#[cfg_attr(test, mockall::automock)]
pub trait Hasher {
    fn hash_base64(&self, input: &[u8]) -> Result<String, HasherError>;
}
