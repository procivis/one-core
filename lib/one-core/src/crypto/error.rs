use thiserror::Error;

#[derive(Debug, PartialEq, Eq, Error)]
pub enum CryptoProviderError {
    #[error("Missing hasher: `{0}`")]
    MissingHasher(String),
    #[error("Missing signer: `{0}`")]
    MissingSigner(String),
}
