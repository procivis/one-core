use serde::{Deserialize, Serialize};
use shared_types::DidValue;
use time::OffsetDateTime;

use crate::provider::credential_formatter::{
    status_list_jwt_formatter::common::{from_timestamp, into_timestamp, StatusPurpose},
    Context,
};

#[derive(Debug, Serialize, Deserialize)]
pub enum ContentType {
    VerifiableCredential,
    BitstringStatusListCredential,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VCContent {
    #[serde(rename = "@context")]
    pub context: Vec<Context>,
    pub id: String,
    pub r#type: Vec<ContentType>,
    pub issuer: DidValue,
    #[serde(serialize_with = "into_timestamp", deserialize_with = "from_timestamp")]
    pub issued: OffsetDateTime,
    pub credential_subject: CredentialSubject,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum SubjectType {
    BitstringStatusList,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSubject {
    pub id: String,
    pub r#type: SubjectType,
    pub status_purpose: StatusPurpose,
    pub encoded_list: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VC {
    pub vc: VCContent,
}
