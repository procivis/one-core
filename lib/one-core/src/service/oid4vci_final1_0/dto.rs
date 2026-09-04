use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use standardized_types::openid4vci::{
    CredentialIssuerMetadata, CredentialRequest, CredentialResponse,
};

/// Credential Response, extended with the Procivis-specific `redirectUri` parameter.
#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpenID4VCICredentialResponseDTO {
    #[serde(rename = "redirectUri")]
    pub redirect_uri: Option<String>,

    #[serde(flatten)]
    pub standard: CredentialResponse,
}

/// Body of a Credential Request, either plain JSON or a JWE encrypted to one of the issuer keys
/// advertised in `credential_request_encryption`.
#[derive(Clone, Debug)]
pub enum CredentialRequestPayload {
    Plain(Box<CredentialRequest>),
    /// Compact serialized JWE.
    Encrypted(String),
}

/// Body of a Credential Response, encrypted when the wallet asked for it via
/// `credential_response_encryption`.
#[derive(Clone, Debug)]
pub enum CredentialResponsePayload {
    Plain(Box<OpenID4VCICredentialResponseDTO>),
    /// Compact serialized JWE.
    Encrypted(String),
}

#[derive(Clone, Debug)]
pub enum OID4VCIFinal1_0MetadataResponseTypeEnum {
    Model,
    Jwt,
}

#[derive(Clone, Debug)]
pub enum OID4VCIFinal1_0IssuerMetadataResponseEnum {
    Model(Box<CredentialIssuerMetadata>),
    Jwt(String),
}
