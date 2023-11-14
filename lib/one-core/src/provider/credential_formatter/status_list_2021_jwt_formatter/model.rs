use serde::{Deserialize, Deserializer, Serialize, Serializer};
use shared_types::DidValue;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

fn into_timestamp<S>(dt: &OffsetDateTime, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let formatted = format!(
        "{}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        dt.year(),
        dt.month() as i32,
        dt.day(),
        dt.hour(),
        dt.minute(),
        dt.second()
    );
    formatted.serialize(s)
}

fn from_timestamp<'de, D>(deserializer: D) -> Result<OffsetDateTime, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;

    String::deserialize(deserializer).and_then(|string| {
        OffsetDateTime::parse(&string, &Rfc3339).map_err(|err| Error::custom(err.to_string()))
    })
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ContentType {
    VerifiableCredential,
    StatusList2021Credential,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VCContent {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub id: String,
    pub r#type: Vec<ContentType>,
    pub issuer: DidValue,
    #[serde(serialize_with = "into_timestamp", deserialize_with = "from_timestamp")]
    pub issued: OffsetDateTime,
    pub credential_subject: CredentialSubject,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum StatusPurpose {
    Revocation,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum SubjectType {
    StatusList2021,
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
