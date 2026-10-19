use std::collections::HashMap;

use standardized_types::jwk::PublicJwk;
use standardized_types::sd_jwt_vc;

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

/// SD-JWT VC type metadata as served by the VCT endpoints.
///
/// Wraps the standard [`sd_jwt_vc`] types with non-standard extensions.
#[derive(Clone, Debug, PartialEq)]
pub struct SdJwtVcTypeMetadataResponseDTO {
    pub vct: String,
    pub name: Option<String>,
    pub description: Option<String>,
    pub display: Vec<SdJwtVcDisplayMetadataDTO>,
    pub claims: Vec<sd_jwt_vc::ClaimMetadata>,
    // Non-standard property
    pub layout_properties: Option<CredentialSchemaLayoutPropertiesResponseDTO>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SdJwtVcDisplayMetadataDTO {
    pub display: sd_jwt_vc::DisplayMetadata,
    /// Non-standard property: SWIYU expects the locale as `lang` (in addition to `locale`)
    pub lang: Option<String>,
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
