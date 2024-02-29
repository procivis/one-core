use std::collections::HashMap;

use serde::{Deserialize, Serialize};

pub(super) static CBOR_PREFIX_BASE: [u8; 3] = [0xd9, 0x5d, 0x02];
pub(super) static CBOR_PREFIX_DERIVED: [u8; 3] = [0xd9, 0x5d, 0x03];

#[derive(Debug, Clone)]
pub struct GroupedFormatDataDocument {
    pub mandatory: TransformedEntry,
    pub non_mandatory: TransformedEntry,
}

#[derive(Debug, Clone)]
pub struct TransformedEntry {
    pub data_type: String,
    pub value: Vec<GroupEntry>,
}

#[derive(Debug, Clone)]
pub struct GroupEntry {
    pub index: usize,
    pub entry: String,
}

#[derive(Debug, Clone)]
pub struct HashData {
    pub transformed_document: GroupedFormatDataDocument,
    pub proof_config_hash: Vec<u8>,
    pub mandatory_hash: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum StringOrVec {
    VecString(Vec<String>),
    Bytes(Vec<u8>),
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(into = "Vec<StringOrVec>")]
#[serde(from = "Vec<StringOrVec>")]
pub struct BbsProofComponents {
    pub bbs_signature: Vec<u8>,
    pub bbs_header: Vec<u8>,
    pub public_key: Vec<u8>,
    pub hmac_key: Vec<u8>,
    pub mandatory_pointers: Vec<String>,
}

impl From<BbsProofComponents> for Vec<StringOrVec> {
    fn from(value: BbsProofComponents) -> Self {
        vec![
            StringOrVec::Bytes(value.bbs_signature),
            StringOrVec::Bytes(value.bbs_header),
            StringOrVec::Bytes(value.public_key),
            StringOrVec::Bytes(value.hmac_key),
            StringOrVec::VecString(value.mandatory_pointers),
        ]
    }
}

impl From<Vec<StringOrVec>> for BbsProofComponents {
    fn from(value: Vec<StringOrVec>) -> Self {
        BbsProofComponents {
            bbs_signature: if let StringOrVec::Bytes(value) = &value[0] {
                value.clone()
            } else {
                vec![]
            },
            bbs_header: if let StringOrVec::Bytes(value) = &value[1] {
                value.clone()
            } else {
                vec![]
            },
            public_key: if let StringOrVec::Bytes(value) = &value[2] {
                value.clone()
            } else {
                vec![]
            },
            hmac_key: if let StringOrVec::Bytes(value) = &value[3] {
                value.clone()
            } else {
                vec![]
            },
            mandatory_pointers: if let StringOrVec::VecString(value) = &value[4] {
                value.clone()
            } else {
                vec![]
            },
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum DeriveProofComponent {
    LabelMap(HashMap<usize, usize>),
    NumberArray(Vec<usize>),
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(into = "Vec<DeriveProofComponent>")]
#[serde(from = "Vec<DeriveProofComponent>")]
pub struct BbsDerivedProofComponents {
    pub bbs_proof: Vec<u8>,
    pub compressed_label_map: HashMap<usize, usize>,
    pub mandatory_indices: Vec<usize>,
    pub selective_indices: Vec<usize>,
    pub presentation_header: Vec<u8>,
}

impl From<BbsDerivedProofComponents> for Vec<DeriveProofComponent> {
    fn from(value: BbsDerivedProofComponents) -> Self {
        vec![
            DeriveProofComponent::NumberArray(
                value.bbs_proof.into_iter().map(|v| v as usize).collect(),
            ),
            DeriveProofComponent::LabelMap(value.compressed_label_map),
            DeriveProofComponent::NumberArray(value.mandatory_indices),
            DeriveProofComponent::NumberArray(value.selective_indices),
            DeriveProofComponent::NumberArray(
                value
                    .presentation_header
                    .into_iter()
                    .map(|v| v as usize)
                    .collect(),
            ),
        ]
    }
}

impl From<Vec<DeriveProofComponent>> for BbsDerivedProofComponents {
    fn from(value: Vec<DeriveProofComponent>) -> Self {
        BbsDerivedProofComponents {
            bbs_proof: if let DeriveProofComponent::NumberArray(value) = &value[0] {
                value.iter().map(|v| *v as u8).collect()
            } else {
                vec![]
            },
            compressed_label_map: if let DeriveProofComponent::LabelMap(value) = &value[1] {
                value.clone()
            } else {
                HashMap::new()
            },
            mandatory_indices: if let DeriveProofComponent::NumberArray(value) = &value[2] {
                value.clone()
            } else {
                vec![]
            },
            selective_indices: if let DeriveProofComponent::NumberArray(value) = &value[3] {
                value.clone()
            } else {
                vec![]
            },
            presentation_header: if let DeriveProofComponent::NumberArray(value) = &value[4] {
                value.iter().map(|v| *v as u8).collect()
            } else {
                vec![]
            },
        }
    }
}
