use anyhow::Context;
use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use serde::{Deserialize, Serialize};
use shared_types::DidValue;
use time::OffsetDateTime;
use url::Url;

use crate::service::oidc::dto::PresentationSubmissionMappingDTO;

use super::dto::OpenID4VPPresentationDefinition;

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct OpenID4VCIInteractionContent {
    pub pre_authorized_code_used: bool,
    pub access_token: String,
    #[serde(with = "time::serde::rfc3339::option")]
    pub access_token_expires_at: Option<OffsetDateTime>,
}

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct OpenID4VPInteractionContent {
    pub nonce: String,
    pub presentation_definition: OpenID4VPPresentationDefinition,
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct HolderInteractionData {
    pub issuer_url: String,
    pub credential_endpoint: String,
    pub access_token: String,
    #[serde(with = "time::serde::rfc3339::option")]
    pub access_token_expires_at: Option<OffsetDateTime>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MdocJwePayload {
    pub iss: DidValue,
    pub aud: Url,
    #[serde(with = "unix_timestamp")]
    pub exp: OffsetDateTime,
    pub vp_token: String,
    pub presentation_submission: PresentationSubmissionMappingDTO,
    pub state: String,
}

impl MdocJwePayload {
    pub(crate) fn try_into_json_base64_encode(&self) -> anyhow::Result<String> {
        let payload = serde_json::to_vec(self).context("MdocJwePayload serialization failed")?;
        let payload = Base64UrlSafeNoPadding::encode_to_string(payload)
            .context("MdocJwePayload base64 encoding failed")?;

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
