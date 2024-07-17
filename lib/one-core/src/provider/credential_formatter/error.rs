use thiserror::Error;

#[derive(Debug, PartialEq, Eq, Error)]
pub enum ParseError {
    #[error("Failed: `{0}`")]
    Failed(String),
}
