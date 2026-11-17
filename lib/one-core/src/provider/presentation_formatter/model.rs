use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use shared_types::{DidValue, SerializedCredential};
use standardized_types::jwk::PublicJwk;
use time::OffsetDateTime;

use crate::config::core_config::{FormatType, VerificationProtocolType};
use crate::provider::credential_formatter::model::IdentifierDetails;
use crate::provider::presentation_formatter::mso_mdoc::model::DeviceNamespaces;
use crate::provider::transaction_data::processed_transaction_data::ProcessedTransactionData;

pub struct CredentialToPresent {
    pub credential_token: String,
    pub credential_format: FormatType,
}

#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedPresentation {
    pub id: Option<String>,
    pub issued_at: Option<OffsetDateTime>,
    pub expires_at: Option<OffsetDateTime>,
    pub issuer: Option<IdentifierDetails>,
    pub nonce: Option<String>,
    pub credentials: Vec<SerializedCredential>,
    pub transaction_data: Option<PresentedTransactionData>,
}

/// Transaction data evidence attached by the holder to the presentation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PresentedTransactionData {
    /// Custom top-level claims of the SD-JWT VC Key Binding JWT
    KbJwtClaims(serde_json::Map<String, serde_json::Value>),
    /// The mdoc `DeviceSigned` namespaces, merged over all documents
    DeviceSignedElements(DeviceNamespaces),
}

impl PresentedTransactionData {
    pub fn is_empty(&self) -> bool {
        match self {
            Self::KbJwtClaims(claims) => claims.is_empty(),
            Self::DeviceSignedElements(namespaces) => {
                namespaces.values().all(|elements| elements.is_empty())
            }
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct FormattedPresentation {
    pub vp_token: String,
    pub oidc_format: String,
}

#[derive(Debug, Default, Clone)]
pub struct FormatPresentationCtx {
    pub holder_did: Option<DidValue>,
    pub nonce: Option<String>,
    pub audience: Option<String>,
    pub mdoc_session_transcript: Option<Vec<u8>>,
    /// The transaction data to be included in the presentation.
    pub transaction_data: Option<ProcessedTransactionData>,
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
    /// only for DC-API transport
    pub dc_api_origin: Option<String>,
    pub verifier_key: Option<PublicJwk>,
}
