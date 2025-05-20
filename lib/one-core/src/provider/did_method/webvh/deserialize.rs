use serde::{Deserialize, Serialize};
use serde_with::{OneOrMany, serde_as};
use time::OffsetDateTime;

use crate::provider::credential_formatter::vcdm::VcdmProof;
use crate::provider::did_method::dto::DidDocumentDTO;
use crate::provider::did_method::webvh::common::DidLogParameters;

// https://identity.foundation/didwebvh/v0.3/#the-did-log-file
#[serde_as]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DidLogEntry {
    pub version_id: String,
    #[serde(with = "time::serde::iso8601")]
    pub version_time: OffsetDateTime,
    pub parameters: DidLogParameters,
    pub state: DidDocState,
    #[serde(default)]
    #[serde_as(as = "OneOrMany<_>")]
    pub proof: Vec<VcdmProof>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Copy)]
pub enum DidMethodVersion {
    #[serde(rename = "did:tdw:0.3")]
    V3,
}

#[derive(Debug, Deserialize)]
pub struct DidDocState {
    pub value: Document,
}

#[derive(Debug)]
pub struct Document {
    pub source: json_syntax::Value,
    pub document: DidDocumentDTO,
}

impl<'de> Deserialize<'de> for Document {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let source = serde_json::Value::deserialize(deserializer)?;
        let document = DidDocumentDTO::deserialize(&source).map_err(serde::de::Error::custom)?;
        let source = json_syntax::Value::from_serde_json(source);

        Ok(Self { source, document })
    }
}
