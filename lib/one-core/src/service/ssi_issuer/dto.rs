use std::collections::HashMap;

use serde::Deserialize;
use shared_types::CredentialId;

use crate::service::credential::dto::DetailCredentialClaimResponseDTO;
use crate::service::credential_schema::dto::CredentialSchemaDetailResponseDTO;
use crate::service::did::dto::DidListItemResponseDTO;

#[derive(Clone, Debug, Deserialize)]
pub struct IssuerResponseDTO {
    pub credential: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct JsonLDContextResponseDTO {
    pub context: JsonLDContextDTO,
}

#[derive(Clone, Debug, PartialEq)]
pub struct JsonLDContextDTO {
    pub version: f64,
    pub protected: bool,
    pub id: String,
    pub r#type: String,
    pub entities: HashMap<String, JsonLDEntityDTO>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum JsonLDEntityDTO {
    Reference(String),
    Inline(JsonLDInlineEntityDTO),
    NestedObject(JsonLDNestedEntityDTO),
    // TODO: nested claims (ONE-1317)
}
#[derive(Clone, Debug, PartialEq)]
pub struct JsonLDNestedEntityDTO {
    pub id: String,
    pub context: JsonLDNestedContextDTO,
}

#[derive(Clone, Debug, PartialEq)]
pub struct JsonLDNestedContextDTO {
    pub entities: HashMap<String, JsonLDEntityDTO>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct JsonLDInlineEntityDTO {
    pub id: String,
    pub context: JsonLDContextDTO,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectIssuerResponseDTO {
    pub id: CredentialId,
    pub schema: CredentialSchemaDetailResponseDTO,
    pub issuer_did: DidListItemResponseDTO,
    pub claims: Vec<DetailCredentialClaimResponseDTO>,
    pub redirect_uri: Option<String>,
}
