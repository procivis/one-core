use std::convert::Infallible;
use std::string::FromUtf8Error;

use thiserror::Error;

use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};
use crate::model::identifier::IdentifierType;
use crate::util::rdf_canonization::CanonizationError;

#[derive(Debug, Error)]
pub enum FormatterError {
    #[error("Could not verify: `{0}`")]
    CouldNotVerify(String),
    #[error("Could not format: `{0}`")]
    CouldNotFormat(String),
    #[error("Could not extract credentials: `{0}`")]
    CouldNotExtractCredentials(String),
    #[error("Could not extract presentation: `{0}`")]
    CouldNotExtractPresentation(String),
    #[error("Only BBS is allowed")]
    BBSOnly,
    #[error("JSON mapping error: `{0}`")]
    JsonMapping(String),
    #[error("Float value is NaN")]
    FloatValueIsNaN,
    #[error("Unsupported identifier type `{0}`")]
    UnsupportedIdentifierType(IdentifierType),

    #[error("Crypto library error: `{0}`")]
    CryptoError(#[from] one_crypto::CryptoProviderError),
    #[error("Jsonptr assign error: `{0}`")]
    JsonPtrAssignError(#[from] jsonptr::assign::Error),
    #[error("Jsonptr parse error: `{0}`")]
    JsonPtrParseError(#[from] jsonptr::ParseError),
    #[error("Json serialization error: `{0}`")]
    JsonSerialization(#[from] serde_json::Error),
    #[error("Json serialization error: `{0}`")]
    JsonSyntaxSerialization(#[from] json_syntax::SerializeError),
    #[error("Json deserialization error: `{0}`")]
    JsonSyntaxDeserialization(#[from] json_syntax::DeserializeError),
    #[error("Encoding error: `{0}`")]
    EncodingError(#[from] ct_codecs::Error),
    #[error("CBOR serialization: `{0}`")]
    CBORSerialization(#[from] ciborium::ser::Error<std::io::Error>),
    #[error("CBOR parsing: `{0}`")]
    CBORParsing(#[from] ciborium::de::Error<std::io::Error>),
    #[error("CBOR value: `{0}`")]
    CBORValue(#[from] ciborium::value::Error),
    #[error("COSE error: `{0}`")]
    CoseError(#[from] coset::CoseError),
    #[error("Encoding error: `{0}`")]
    Base58(#[from] bs58::decode::Error),
    #[error("Hash error: `{0}`")]
    HasherError(#[from] one_crypto::HasherError),
    #[error("URL error: `{0}`")]
    Url(#[from] url::ParseError),
    #[error("String parsing error: `{0}`")]
    FromUtf8Error(#[from] FromUtf8Error),
    #[error("C14n error: `{0}`")]
    C14nError(#[from] sophia_c14n::C14nError<Infallible>),
    #[error("RDF error: `{0}`")]
    ToRdfError(#[from] json_ld::ToRdfError),
    #[error("Expand error: `{0}`")]
    ExpandError(#[from] json_ld::ExpandError),
    #[error("Canonization error: `{0}`")]
    CanonizationError(#[from] CanonizationError),

    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for FormatterError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::BBSOnly => ErrorCode::BR_0090,
            Self::CouldNotVerify(_)
            | Self::CouldNotFormat(_)
            | Self::CouldNotExtractCredentials(_)
            | Self::CouldNotExtractPresentation(_)
            | Self::CryptoError(_)
            | Self::JsonMapping(_)
            | Self::JsonPtrAssignError(_)
            | Self::JsonPtrParseError(_)
            | Self::JsonSerialization(_)
            | Self::JsonSyntaxSerialization(_)
            | Self::JsonSyntaxDeserialization(_)
            | Self::EncodingError(_)
            | Self::CBORSerialization(_)
            | Self::CBORParsing(_)
            | Self::CBORValue(_)
            | Self::CoseError(_)
            | Self::Base58(_)
            | Self::Url(_)
            | Self::FromUtf8Error(_)
            | Self::C14nError(_)
            | Self::ToRdfError(_)
            | Self::ExpandError(_)
            | Self::CanonizationError(_)
            | Self::HasherError(_)
            | Self::UnsupportedIdentifierType(_)
            | Self::FloatValueIsNaN => ErrorCode::BR_0057,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}
