use one_crypto::CryptoProviderError;
use thiserror::Error;

#[derive(Debug, PartialEq, Eq, Error)]
pub enum ParseError {
    #[error("Failed: `{0}`")]
    Failed(String),
}

#[derive(Debug, PartialEq, Error)]
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
    #[error("Missing part")]
    MissingPart,
    #[error("Missing disclosure")]
    MissingDisclosure,
    #[error("Missing issuer")]
    MissingIssuer,
    #[error("Missing credential subject")]
    MissingHolder,
    #[error("Missing claim")]
    MissingClaim,
    #[error("Only BBS is allowed")]
    BBSOnly,
    #[error("Crypto library error: `{0}`")]
    CryptoError(#[from] CryptoProviderError),
    #[error("{formatter} formatter missing missing base url")]
    MissingBaseUrl { formatter: &'static str },
    #[error("JSON mapping error: `{0}`")]
    JsonMapping(String),
    #[error("Jsonptr assign error: `{0}`")]
    JsonPtrAssignError(#[from] jsonptr::assign::AssignError),
    #[error("Jsonptr parse error: `{0}`")]
    JsonPtrParseError(#[from] jsonptr::ParseError),
    #[error("Float value is NaN")]
    FloatValueIsNaN,
}
