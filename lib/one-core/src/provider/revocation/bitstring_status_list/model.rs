use serde::{Deserialize, Serialize};
use shared_types::DidValue;
use time::OffsetDateTime;

use crate::model::revocation_list::RevocationListPurpose;
use crate::provider::credential_formatter::vcdm::ContextType;
use crate::provider::revocation::bitstring_status_list::jwt_formatter::{
    from_timestamp_opt, into_timestamp_opt,
};
use crate::provider::revocation::model::RevocationListId;

#[derive(Debug, Serialize, Deserialize)]
pub enum ContentType {
    VerifiableCredential,
    BitstringStatusListCredential,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VCContent {
    #[serde(rename = "@context")]
    pub context: Vec<ContextType>,
    pub id: Option<String>,
    pub r#type: Vec<ContentType>,
    pub issuer: DidValue,
    // we keep this field for backwards compatibility with VCDM v1.1
    #[serde(
        serialize_with = "into_timestamp_opt",
        deserialize_with = "from_timestamp_opt"
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued: Option<OffsetDateTime>,
    #[serde(
        serialize_with = "into_timestamp_opt",
        deserialize_with = "from_timestamp_opt"
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<OffsetDateTime>,
    #[serde(
        serialize_with = "into_timestamp_opt",
        deserialize_with = "from_timestamp_opt"
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<OffsetDateTime>,
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

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum StatusPurpose {
    Revocation,
    Suspension,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RevocationUpdateData {
    pub id: RevocationListId,
    pub value: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RevocationList {
    pub id: RevocationListId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub credentials: Vec<u8>,
    pub purpose: RevocationListPurpose,
}
