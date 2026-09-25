use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_with::skip_serializing_none;
use standardized_types::jwk::PublicJwk;
use url::Url;

use crate::service::credential_schema::dto::CredentialSchemaLayoutPropertiesResponseDTO;

#[derive(Clone, Debug, PartialEq)]
pub struct JsonLDContextResponseDTO {
    pub context: JsonLDContextDTO,
}

#[derive(Clone, Debug, PartialEq)]
pub struct JsonLDContextDTO {
    // this is needed just for the root context
    pub version: Option<f64>,
    pub protected: bool,
    pub id: String,
    pub r#type: String,
    pub entities: HashMap<String, JsonLDEntityDTO>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum JsonLDEntityDTO {
    Inline(JsonLDInlineEntityDTO),
    NestedObject(JsonLDNestedEntityDTO),
}
#[derive(Clone, Debug, PartialEq)]
pub struct JsonLDNestedEntityDTO {
    pub id: String,
    pub context: JsonLDNestedContextDTO,
}

#[derive(Clone, Debug, PartialEq)]
pub struct JsonLDNestedContextDTO {
    pub protected: bool,
    pub id: String,
    pub r#type: String,
    pub entities: HashMap<String, JsonLDEntityDTO>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct JsonLDInlineEntityDTO {
    pub id: String,
    pub r#type: Option<String>,
    pub context: Option<JsonLDContextDTO>,
}

/// (Partial) SD-JWT VC type metadata.
/// See https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-19#name-type-metadata-format for
/// more details.
#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SdJwtVcTypeMetadataResponseDTO {
    // StringOrURI
    pub vct: String,

    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub display: Vec<SdJwtVcDisplayMetadataDTO>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<SdJwtVcClaimDTO>,

    // Non-standard property
    #[serde(default)]
    pub layout_properties: Option<CredentialSchemaLayoutPropertiesResponseDTO>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SdJwtVcDisplayMetadataDTO {
    pub locale: String,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,

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
    pub background_image: Option<SdJwtVcSimpleRenderingBackgroundImageDTO>,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SdJwtVcSimpleRenderingBackgroundImageDTO {
    pub uri: Url,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SdJwtVcClaimDTO {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub path: Vec<Value>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub display: Vec<SdJwtVcClaimDisplayDTO>,

    #[serde(default)]
    pub mandatory: Option<bool>,

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

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SdJwtVcClaimDisplayDTO {
    pub locale: String,
    pub label: String,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Clone, Debug)]
pub struct SdJwtVcIssuerMetadata {
    pub issuer: String,
    pub jwks: SdJwtVcIssuerMetadataJwks,
}

#[derive(Clone, Debug)]
pub enum SdJwtVcIssuerMetadataJwks {
    Jwks(Vec<PublicJwk>),
    JwksUri(String),
}
