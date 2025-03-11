use std::collections::BTreeMap;

use anyhow::bail;
use serde::{Deserialize, Serialize};

pub(super) const CBOR_PREFIX_BASE: [u8; 3] = [0xd9, 0x5d, 0x02];
pub(super) const CBOR_PREFIX_DERIVED: [u8; 3] = [0xd9, 0x5d, 0x03];

pub struct ParsedBbsDerivedProofComponents {
    pub bbs_proof: Vec<u8>,
    pub decompressed_label_map: BTreeMap<String, String>,
    pub mandatory_indexes: Vec<usize>,
    pub selective_indexes: Vec<usize>,
    pub presentation_header: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(into = "ciborium::Value")]
#[serde(try_from = "ciborium::Value")]
pub struct BbsBaseProofComponents {
    pub bbs_signature: Vec<u8>,
    pub bbs_header: Vec<u8>,
    pub public_key: Vec<u8>,
    pub hmac_key: Vec<u8>,
    pub mandatory_pointers: Vec<String>,
}

impl From<BbsBaseProofComponents> for ciborium::Value {
    fn from(value: BbsBaseProofComponents) -> Self {
        ciborium::Value::Array(vec![
            ciborium::Value::Bytes(value.bbs_signature),
            ciborium::Value::Bytes(value.bbs_header),
            ciborium::Value::Bytes(value.public_key),
            ciborium::Value::Bytes(value.hmac_key),
            ciborium::Value::Array(
                value
                    .mandatory_pointers
                    .into_iter()
                    .map(ciborium::Value::Text)
                    .collect(),
            ),
        ])
    }
}

impl TryFrom<ciborium::Value> for BbsBaseProofComponents {
    type Error = anyhow::Error;

    fn try_from(value: ciborium::Value) -> anyhow::Result<Self> {
        let mut array = value
            .into_array()
            .map_err(|_| anyhow::anyhow!("Expected an array for bbs+ derivedProof"))?
            .into_iter();

        let bbs_signature = match array.next().map(|v| v.into_bytes()) {
            Some(Ok(bytes)) => bytes,
            Some(Err(_)) => {
                bail!("Invalid value for `bbs_signature` property, expected byte array")
            }
            None => bail!("Missing `bbs_signature` property"),
        };

        let bbs_header = match array.next().map(|v| v.into_bytes()) {
            Some(Ok(bytes)) => bytes,
            Some(Err(_)) => bail!("Invalid value for `bbs_header` property, expected byte array"),
            None => bail!("Missing `bbs_header` property"),
        };

        let public_key = match array.next().map(|v| v.into_bytes()) {
            Some(Ok(bytes)) => bytes,
            Some(Err(_)) => bail!("Invalid value for `public_key` property, expected byte array"),
            None => bail!("Missing `public_key` property"),
        };

        let hmac_key = match array.next().map(|v| v.into_bytes()) {
            Some(Ok(bytes)) => bytes,
            Some(Err(_)) => bail!("Invalid value for `hmac_key` property, expected byte array"),
            None => bail!("Missing `hmac_key` property"),
        };

        let mandatory_pointers = match array.next().map(|v| v.deserialized()) {
            Some(Ok(pointers)) => pointers,
            Some(Err(_)) => {
                bail!("Invalid value for `mandatory_pointers` property, expected byte array")
            }
            None => bail!("Missing `mandatory_pointers` property"),
        };

        Ok(BbsBaseProofComponents {
            bbs_signature,
            bbs_header,
            public_key,
            hmac_key,
            mandatory_pointers,
        })
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(into = "ciborium::Value")]
#[serde(try_from = "ciborium::Value")]
pub struct BbsDerivedProofComponents {
    pub bbs_proof: Vec<u8>,
    pub compressed_label_map: BTreeMap<usize, usize>,
    pub mandatory_indexes: Vec<usize>,
    pub selective_indexes: Vec<usize>,
    pub presentation_header: Vec<u8>,
}

impl From<BbsDerivedProofComponents> for ciborium::Value {
    fn from(value: BbsDerivedProofComponents) -> Self {
        let compressed_label_map = value
            .compressed_label_map
            .into_iter()
            .map(|(k, v)| {
                (
                    ciborium::Value::Integer(k.into()),
                    ciborium::Value::Integer(v.into()),
                )
            })
            .collect();

        ciborium::Value::Array(vec![
            ciborium::Value::Bytes(value.bbs_proof),
            ciborium::Value::Map(compressed_label_map),
            ciborium::Value::Array(
                value
                    .mandatory_indexes
                    .into_iter()
                    .map(|i| ciborium::Value::Integer(i.into()))
                    .collect(),
            ),
            ciborium::Value::Array(
                value
                    .selective_indexes
                    .into_iter()
                    .map(|i| ciborium::Value::Integer(i.into()))
                    .collect(),
            ),
            ciborium::Value::Bytes(value.presentation_header),
        ])
    }
}

impl TryFrom<ciborium::Value> for BbsDerivedProofComponents {
    type Error = anyhow::Error;

    fn try_from(value: ciborium::Value) -> Result<Self, Self::Error> {
        let mut array = value
            .into_array()
            .map_err(|_| anyhow::anyhow!("Expected an array for bbs+ derivedProof"))?
            .into_iter();

        let bbs_proof = match array.next().map(|v| v.into_bytes()) {
            Some(Ok(bytes)) => bytes,
            Some(Err(_)) => bail!("Invalid value for `bbs_proof` property, expected byte array"),
            None => bail!("Missing `bbs_proof` property"),
        };

        let compressed_label_map: BTreeMap<usize, usize> =
            match array.next().map(|v| v.deserialized()) {
                Some(Ok(map)) => map,
                Some(Err(err)) => bail!("Invalid value for `compressed_label_map` property: {err}"),
                None => bail!("Missing `compressed_label_map` property"),
            };

        let mandatory_indices: Vec<usize> = match array.next().map(|v| v.deserialized()) {
            Some(Ok(indices)) => indices,
            Some(Err(err)) => bail!("Invalid value for `mandatory_indices` property: {err}"),
            None => bail!("Missing `mandatory_indices` property"),
        };

        let selective_indices: Vec<usize> = match array.next().map(|v| v.deserialized()) {
            Some(Ok(indices)) => indices,
            Some(Err(err)) => bail!("Invalid value for `selective_indices` property: {err}"),
            None => bail!("Missing `selective_indices` property"),
        };

        let presentation_header = match array.next().map(|v| v.into_bytes()) {
            Some(Ok(bytes)) => bytes,
            Some(Err(_)) => {
                bail!("Invalid value for `presentation_header` property, expected byte array")
            }
            None => bail!("Missing `presentation_header` property"),
        };

        Ok(BbsDerivedProofComponents {
            bbs_proof,
            compressed_label_map,
            mandatory_indexes: mandatory_indices,
            selective_indexes: selective_indices,
            presentation_header,
        })
    }
}
