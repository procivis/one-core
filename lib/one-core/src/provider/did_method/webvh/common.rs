use anyhow::Context;
use one_crypto::Hasher;
use one_crypto::hasher::sha256::SHA256;
use serde::{Deserialize, Serialize};
use serde_with::{OneOrMany, serde_as, skip_serializing_none};
use time::OffsetDateTime;

use crate::provider::credential_formatter::vcdm::VcdmProof;
use crate::provider::did_method::dto::DidDocumentDTO;
use crate::provider::did_method::error::DidMethodError;

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

#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DidLogParameters {
    pub method: Option<DidMethodVersion>,
    pub prerotation: Option<bool>,
    pub portable: Option<bool>,
    #[serde(default)]
    pub update_keys: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub next_key_hashes: Vec<String>,
    pub scid: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub witness: Vec<String>,
    pub deactivated: Option<bool>,
    pub ttl: Option<u32>,
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

pub fn canonicalized_hash(mut data: json_syntax::Value) -> Result<Vec<u8>, DidMethodError> {
    data.canonicalize();
    SHA256.hash(data.to_string().as_bytes()).map_err(|err| {
        DidMethodError::ResolutionError(format!("Failed to hash canonicalized JSON: {}", err))
    })
}

pub fn multihash_b58_encode(input: &[u8]) -> Result<String, anyhow::Error> {
    let multihash =
        multihash::Multihash::<32>::wrap(0x12, input).context("Failed to create multihash")?;

    Ok(bs58::encode(multihash.to_bytes()).into_string())
}
