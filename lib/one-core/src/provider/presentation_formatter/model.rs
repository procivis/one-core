use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use time::OffsetDateTime;

use crate::config::core_config::{FormatType, VerificationProtocolType};
use crate::provider::credential_formatter::model::IdentifierDetails;

#[derive(Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PresentationFormatterCapabilities {
    pub supported_credential_formats: Vec<FormatType>,
}

pub struct CredentialToPresent {
    pub raw_credential: String,
    pub credential_format: FormatType,
}

#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize)]
pub struct ExtractedPresentation {
    pub id: Option<String>,
    pub issued_at: Option<OffsetDateTime>,
    pub expires_at: Option<OffsetDateTime>,
    pub issuer: Option<IdentifierDetails>,
    pub nonce: Option<String>,
    pub credentials: Vec<String>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct FormattedPresentation {
    pub vp_token: String,
    pub oidc_format: String,
}

#[derive(Debug, Default)]
pub struct FormatPresentationCtx {
    pub nonce: Option<String>,
    pub mdoc_session_transcript: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct ExtractPresentationCtx {
    pub verification_protocol_type: VerificationProtocolType,
    pub nonce: Option<String>,
    pub format_nonce: Option<String>,
    pub issuance_date: Option<OffsetDateTime>,
    pub expiration_date: Option<OffsetDateTime>,
    pub mdoc_session_transcript: Option<Vec<u8>>,
    pub client_id: Option<String>,
    pub response_uri: Option<String>,
}
