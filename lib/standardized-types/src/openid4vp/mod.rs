//! Spec https://openid.net/specs/openid-4-verifiable-presentations-1_0.html

pub mod authorization_request;
pub mod authorization_response;
pub mod dcql;
pub mod transaction_data;

pub use authorization_request::*;
pub use authorization_response::*;
use serde::{Deserialize, Serialize};
use serde_with::{VecSkipError, serde_as, skip_serializing_none};
pub use transaction_data::*;

use crate::iana::EncryptionAlgorithm;
use crate::jwk::Jwks;

#[serde_as]
#[skip_serializing_none]
#[cfg_attr(feature = "utoipa", proc_macros::options_not_nullable)]
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Default)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct ClientMetadata {
    #[serde(default)]
    pub jwks: Option<Jwks>,
    #[serde(default)]
    pub jwks_uri: Option<String>,
    // As per https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-new-parameters:
    // REQUIRED when not available to the Wallet via another mechanism.
    //
    // -> For the DTO this is optional
    #[serde(default)]
    pub vp_formats_supported: VPFormatsSupported,
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

#[skip_serializing_none]
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Default)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct VPFormatsSupported {
    /// <https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.1.3.1.1>
    pub jwt_vc_json: Option<W3CJwtAlgs>,

    /// <https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.1.3.2.1>
    pub ldp_vc: Option<W3CLdpAlgs>,

    /// <https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.2>
    pub mso_mdoc: Option<MdocAlgs>,

    /// <https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.3.1>
    #[serde(rename = "dc+sd-jwt")]
    pub dc_sd_jwt: Option<SdJwtVcAlgs>,
}

/// <https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.3.4>
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
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

/// <https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.1.3.1.3>
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct W3CJwtAlgs {
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub alg_values: Vec<String>,
}

/// <https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.1.3.2.3>
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct W3CLdpAlgs {
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub proof_type_values: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub cryptosuite_values: Vec<String>,
}

/// <https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.2.2>
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct MdocAlgs {
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub issuerauth_alg_values: Vec<i32>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub deviceauth_alg_values: Vec<i32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub enum ResponseMode {
    #[serde(rename = "direct_post")]
    DirectPost,
    #[serde(rename = "direct_post.jwt")]
    DirectPostJwt,
}
