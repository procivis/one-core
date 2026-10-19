//! SD-JWT-based Verifiable Credentials (SD-JWT VC)
//!
//! Spec <https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc>

use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_with::skip_serializing_none;
use url::Url;

/// (Partial) SD-JWT VC type metadata.
///
/// <https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-19#name-type-metadata-format>
#[skip_serializing_none]
#[cfg_attr(feature = "utoipa", proc_macros::options_not_nullable)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "utoipa", schema(as = SdJwtVcTypeMetadata))]
pub struct TypeMetadata {
    /// StringOrURI
    pub vct: String,
    pub name: Option<String>,
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub display: Vec<DisplayMetadata>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<ClaimMetadata>,
}

/// <https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-19#name-display-metadata>
#[skip_serializing_none]
#[cfg_attr(feature = "utoipa", proc_macros::options_not_nullable)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "utoipa", schema(as = SdJwtVcDisplayMetadata))]
pub struct DisplayMetadata {
    pub locale: String,
    pub name: String,
    pub description: Option<String>,
    pub rendering: Option<Rendering>,
}

/// <https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-19#name-rendering-metadata>
#[skip_serializing_none]
#[cfg_attr(feature = "utoipa", proc_macros::options_not_nullable)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "utoipa", schema(as = SdJwtVcRendering))]
pub struct Rendering {
    pub simple: Option<SimpleRendering>,
}

/// <https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-19#name-rendering-method-simple>
#[skip_serializing_none]
#[cfg_attr(feature = "utoipa", proc_macros::options_not_nullable)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "utoipa", schema(as = SdJwtVcSimpleRendering))]
pub struct SimpleRendering {
    pub logo: Option<Logo>,
    pub background_image: Option<BackgroundImage>,
    pub background_color: Option<String>,
    pub text_color: Option<String>,
}

/// <https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-19#name-logo-metadata>
#[skip_serializing_none]
#[cfg_attr(feature = "utoipa", proc_macros::options_not_nullable)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "utoipa", schema(as = SdJwtVcLogo))]
pub struct Logo {
    pub uri: Url,
    pub alt_text: Option<String>,
}

/// <https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-19#name-background-image-metadata>
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "utoipa", schema(as = SdJwtVcBackgroundImage))]
pub struct BackgroundImage {
    pub uri: Url,
}

/// <https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-19#name-claim-metadata>
#[skip_serializing_none]
#[cfg_attr(feature = "utoipa", proc_macros::options_not_nullable)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "utoipa", schema(as = SdJwtVcClaimMetadata))]
pub struct ClaimMetadata {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub path: Vec<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub display: Vec<ClaimDisplay>,
    pub mandatory: Option<bool>,
    pub sd: Option<SelectiveDisclosure>,
}

/// <https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-19#name-claim-selective-disclosure->
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "utoipa", schema(as = SdJwtVcSelectiveDisclosure))]
#[serde(rename_all = "lowercase")]
pub enum SelectiveDisclosure {
    Always,
    Allowed,
    Never,
}

/// <https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-19#name-claim-display-metadata>
#[skip_serializing_none]
#[cfg_attr(feature = "utoipa", proc_macros::options_not_nullable)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "utoipa", schema(as = SdJwtVcClaimDisplay))]
pub struct ClaimDisplay {
    pub locale: String,
    pub label: String,
    pub description: Option<String>,
}
