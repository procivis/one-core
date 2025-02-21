use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_with::skip_serializing_none;
use shared_types::CredentialId;
use url::Url;

use crate::service::credential::dto::DetailCredentialClaimResponseDTO;
use crate::service::credential_schema::dto::{
    CredentialSchemaDetailResponseDTO, CredentialSchemaLayoutPropertiesResponseDTO,
};
use crate::service::did::dto::DidListItemResponseDTO;

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

/// (Partial) SD-JWT VC type metadata.
/// See https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-05.html#name-type-metadata-format for
/// more details.
#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SdJwtVcTypeMetadataResponseDTO {
    // StringOrURI
    pub vct: String,

    #[serde(default)]
    pub name: Option<String>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub display: Vec<SdJwtVcDisplayMetadataDTO>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<SdJwtVcClaimDTO>,

    #[serde(default)]
    pub schema: Option<serde_json::Value>,

    #[serde(default)]
    pub schema_uri: Option<Url>,
    // Non-standard property
    #[serde(default)]
    pub layout_properties: Option<CredentialSchemaLayoutPropertiesResponseDTO>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SdJwtVcDisplayMetadataDTO {
    pub lang: String,
    pub name: String,

    #[serde(default)]
    pub rendering: Option<SdJwtVcRenderingDTO>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SdJwtVcRenderingDTO {
    #[serde(default)]
    pub simple: Option<SdJwtVcSimpleRenderingDTO>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SdJwtVcSimpleRenderingDTO {
    #[serde(default)]
    pub logo: Option<SdJwtVcSimpleRenderingLogoDTO>,

    #[serde(default)]
    pub background_color: Option<String>,

    #[serde(default)]
    pub text_color: Option<String>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SdJwtVcSimpleRenderingLogoDTO {
    pub uri: Url,

    #[serde(default)]
    pub alt_text: Option<String>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SdJwtVcClaimDTO {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub path: Vec<Value>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub display: Vec<SdJwtVcClaimDisplayDTO>,

    #[serde(default)]
    pub sd: Option<SdJwtVcClaimSd>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SdJwtVcClaimSd {
    Always,
    Allowed,
    Never,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SdJwtVcClaimDisplayDTO {
    pub lang: String,
    pub label: String,
}
