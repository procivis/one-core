//! Spec https://openid.net/specs/openid-4-verifiable-presentations-1_0.html

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_with::{VecSkipError, serde_as, skip_serializing_none};

use crate::jwa::EncryptionAlgorithm;
use crate::jwk::PublicJwk;

#[serde_as]
#[skip_serializing_none]
#[cfg_attr(feature = "utoipa", proc_macros::options_not_nullable)]
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Default)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct ClientMetadata {
    #[serde(default)]
    pub jwks: Option<ClientMetadataJwks>,
    #[serde(default)]
    pub jwks_uri: Option<String>,
    pub vp_formats_supported: HashMap<String, PresentationFormat>,
    #[serde_as(as = "Option<VecSkipError<_>>")]
    #[serde(default)]
    pub encrypted_response_enc_values_supported: Option<Vec<EncryptionAlgorithm>>,
    #[serde(default)]
    pub id_token_encrypted_response_enc: Option<String>,
    #[serde(default)]
    pub id_token_encrypted_response_alg: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub subject_syntax_types_supported: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize, Debug, Default, PartialEq)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct ClientMetadataJwks {
    pub keys: Vec<PublicJwk>,
}

// All vp_formats_supported fields are optional,
// this variant is matched first
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct EmptyEntry {}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[serde(untagged)]
pub enum PresentationFormat {
    Empty(EmptyEntry),
    SdJwtVcAlgs(SdJwtVcAlgs),
    LdpVcAlgs(LdpVcAlgs),
    W3CJwtAlgs(W3CJwtAlgs),
    W3CLdpAlgs(W3CLdpAlgs),
    MdocAlgs(MdocAlgs),
    // TODO: Clean this up
    GenericAlgList(GenericAlgs),
    Other(serde_json::Value),
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct SdJwtVcAlgs {
    #[serde(
        rename = "sd-jwt_alg_values",
        skip_serializing_if = "Vec::is_empty",
        default
    )]
    pub sd_jwt_alg_values: Vec<String>,
    #[serde(
        rename = "kb-jwt_alg_values",
        skip_serializing_if = "Vec::is_empty",
        default
    )]
    pub kb_jwt_alg_values: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct GenericAlgs {
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub alg: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct W3CJwtAlgs {
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub alg_values: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct W3CLdpAlgs {
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub proof_type_values: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub cryptosuite_values: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct MdocAlgs {
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub issuerauth_alg_values: Vec<i32>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub deviceauth_alg_values: Vec<i32>,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct LdpVcAlgs {
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub proof_type: Vec<String>,
}
