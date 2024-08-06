use anyhow::Context;
use ct_codecs::{Base64UrlSafeNoPadding, Decoder};
use one_providers::exchange_protocol::openid4vc::model::PresentationSubmissionMappingDTO;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

use super::dto::OpenID4VPPresentationDefinition;
use super::openidvc_ble::BLEPeer;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BleOpenId4VpResponse {
    pub vp_token: String,
    pub presentation_submission: PresentationSubmissionMappingDTO,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BleOpenId4VpRequest {
    #[serde(rename = "iss")]
    pub verifier_client_id: String,
    pub nonce: String,
    pub presentation_definition: OpenID4VPPresentationDefinition,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct OpenID4VCInteractionContent {
    pub pre_authorized_code_used: bool,
    pub access_token: String,
    #[serde(with = "time::serde::rfc3339::option")]
    pub access_token_expires_at: Option<OffsetDateTime>,
    pub refresh_token: Option<String>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub refresh_token_expires_at: Option<OffsetDateTime>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct OpenID4VPInteractionContent {
    pub nonce: String,
    pub presentation_definition: OpenID4VPPresentationDefinition,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HolderInteractionData {
    pub issuer_url: String,
    pub credential_endpoint: String,
    pub access_token: String,
    #[serde(with = "time::serde::rfc3339::option")]
    pub access_token_expires_at: Option<OffsetDateTime>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub refresh_token: Option<String>,
    #[serde(
        with = "time::serde::rfc3339::option",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub refresh_token_expires_at: Option<OffsetDateTime>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BLEOpenID4VPInteractionData {
    pub task_id: Uuid,
    pub peer: BLEPeer,
    pub nonce: Option<String>,
    // nonce coming from the identity request
    pub holder_nonce: Option<String>,
    pub presentation_definition: Option<OpenID4VPPresentationDefinition>,
    pub presentation_submission: Option<BleOpenId4VpResponse>,
    pub client_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JwePayload {
    pub aud: Url,
    #[serde(with = "unix_timestamp")]
    pub exp: OffsetDateTime,
    pub vp_token: String,
    pub presentation_submission: PresentationSubmissionMappingDTO,
    pub state: String,
}

impl JwePayload {
    pub(crate) fn try_from_json_base64_decode(payload: &[u8]) -> anyhow::Result<Self> {
        let payload = Base64UrlSafeNoPadding::decode_to_vec(payload, None)
            .context("MdocJwePayload base64 decoding failed")?;

        let payload =
            serde_json::from_slice(&payload).context("MdocJwePayload deserialization failed")?;

        Ok(payload)
    }
}

mod unix_timestamp {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use time::OffsetDateTime;

    pub fn serialize<S>(datetime: &OffsetDateTime, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        datetime.unix_timestamp().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<OffsetDateTime, D::Error>
    where
        D: Deserializer<'de>,
    {
        let timestamp = i64::deserialize(deserializer)?;

        OffsetDateTime::from_unix_timestamp(timestamp).map_err(serde::de::Error::custom)
    }
}
