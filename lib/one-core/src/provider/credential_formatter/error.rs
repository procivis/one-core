use thiserror::Error;

#[derive(Debug, PartialEq, Eq, Error)]
pub enum FormatterError {
    #[error("Failed: `{0}`")]
    Failed(String),
    #[error("Could not sign: `{0}`")]
    CouldNotSign(String),
    #[error("Could not verify: `{0}`")]
    CouldNotVerify(String),
    #[error("Could not format: `{0}`")]
    CouldNotFormat(String),
    #[error("Could not extract credentials: `{0}`")]
    CouldNotExtractCredentials(String),
    #[error("Could not extract presentation: `{0}`")]
    CouldNotExtractPresentation(String),
    #[error("Could not extract claims from presentation: `{0}`")]
    CouldNotExtractClaimsFromPresentation(String),
    #[error("Incorrect signature")]
    IncorrectSignature,
    #[error("Missing signer")]
    MissingSigner,
    #[error("Missing hasher")]
    MissingHasher,
    #[error("Missing part")]
    MissingPart,
    #[error("Missing disclosure")]
    MissingDisclosure,
    #[error("Missing issuer")]
    MissingIssuer,
    #[error("Missing claim")]
    MissingClaim,
}

#[derive(Debug, PartialEq, Eq, Error)]
pub enum ParseError {
    #[error("Failed: `{0}`")]
    Failed(String),
}
