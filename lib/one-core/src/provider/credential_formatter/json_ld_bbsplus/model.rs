use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct TransformedDataDocument {
    pub mandatory_pointers: Vec<String>,
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
    pub transformed_document: TransformedDataDocument,
    pub proof_config_hash: Vec<u8>,
    pub mandatory_hash: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum StringOrVec {
    VecString(Vec<String>),
    Bytes(Vec<u8>),
}

#[derive(Serialize, Deserialize, Clone)]
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
