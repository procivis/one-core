use serde::{Deserialize, Serialize};

use crate::provider::credential_formatter::vcdm::JwtVcdmCredential;

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VcClaim {
    pub vc: JwtVcdmCredential,
}

#[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct TokenStatusListContent {
    pub status_list: TokenStatusListSubject,
}

#[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct TokenStatusListSubject {
    pub bits: usize,
    #[serde(rename = "lst")]
    pub value: String,
}
