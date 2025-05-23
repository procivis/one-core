use std::collections::HashMap;

use indexmap::IndexMap;
use one_core::provider::did_method::dto::{
    DidDocumentDTO, DidServiceEndointDTO, DidVerificationMethodDTO,
};
use one_core::provider::issuance_protocol::openid4vci_draft13::error::OpenID4VCIError;
use one_core::provider::issuance_protocol::openid4vci_draft13::model::{
    ExtendedSubjectClaimsDTO, ExtendedSubjectDTO, OpenID4VCICredentialValueDetails,
};
use one_core::provider::revocation::lvvc::dto::IssuerResponseDTO;
use one_core::provider::verification_protocol::openid4vp::model::{
    AuthorizationEncryptedResponseAlgorithm,
    AuthorizationEncryptedResponseContentEncryptionAlgorithm,
};
use one_core::service::error::ServiceError;
use one_core::service::key::dto::{
    PublicKeyJwkDTO, PublicKeyJwkEllipticDataDTO, PublicKeyJwkMlweDataDTO, PublicKeyJwkOctDataDTO,
    PublicKeyJwkRsaDataDTO,
};
use one_core::service::ssi_issuer::dto::{
    JsonLDContextDTO, JsonLDContextResponseDTO, JsonLDEntityDTO, JsonLDInlineEntityDTO,
    JsonLDNestedContextDTO, JsonLDNestedEntityDTO, SdJwtVcClaimDTO, SdJwtVcClaimDisplayDTO,
    SdJwtVcClaimSd, SdJwtVcDisplayMetadataDTO, SdJwtVcRenderingDTO, SdJwtVcSimpleRenderingDTO,
    SdJwtVcSimpleRenderingLogoDTO, SdJwtVcTypeMetadataResponseDTO,
};
use one_core::service::trust_anchor::dto::{
    GetTrustAnchorEntityListResponseDTO, GetTrustAnchorResponseDTO,
};
use one_core::service::trust_entity::dto::{
    CreateTrustEntityFromDidPublisherRequestDTO, UpdateTrustEntityActionFromDidRequestDTO,
    UpdateTrustEntityFromDidRequestDTO,
};
use one_dto_mapper::{
    From, Into, TryInto, convert_inner, convert_inner_of_inner, try_convert_inner,
    try_convert_inner_of_inner,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_with::{OneOrMany, serde_as, skip_serializing_none};
use shared_types::{CredentialId, DidValue, TrustAnchorId, TrustEntityId};
use strum::Display;
use time::OffsetDateTime;
use url::Url;
use utoipa::{IntoParams, ToSchema};

use crate::endpoint::credential_schema::dto::{
    CredentialSchemaLayoutPropertiesRestDTO, WalletStorageTypeRestEnum,
};
use crate::endpoint::trust_entity::dto::{TrustEntityRoleRest, TrustEntityStateRest};
use crate::serialize::front_time;

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(DidDocumentDTO)]
pub(crate) struct DidDocumentRestDTO {
    #[serde(rename = "@context")]
    pub context: serde_json::Value,
    pub id: DidValue,
    #[from(with_fn = convert_inner)]
    pub verification_method: Vec<DidVerificationMethodRestDTO>,
    pub authentication: Option<Vec<String>>,
    pub assertion_method: Option<Vec<String>>,
    pub key_agreement: Option<Vec<String>>,
    pub capability_invocation: Option<Vec<String>>,
    pub capability_delegation: Option<Vec<String>>,
    pub also_known_as: Option<Vec<String>>,
    #[from(with_fn = convert_inner_of_inner)]
    pub service: Option<Vec<DidServiceEndointRestDTO>>,
}

#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(DidServiceEndointDTO)]
pub(crate) struct DidServiceEndointRestDTO {
    pub id: String,
    #[serde_as(as = "OneOrMany<_>")]
    pub r#type: Vec<String>,
    pub service_endpoint: serde_json::Value,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(DidVerificationMethodDTO)]
pub(crate) struct DidVerificationMethodRestDTO {
    pub id: String,
    pub r#type: String,
    pub controller: String,
    pub public_key_jwk: PublicKeyJwkRestDTO,
}

/// JWK representation of the public key used to verify the DID.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[serde(tag = "kty")]
#[from(PublicKeyJwkDTO)]
pub(crate) enum PublicKeyJwkRestDTO {
    #[serde(rename = "EC")]
    Ec(PublicKeyJwkEllipticDataRestDTO),
    #[serde(rename = "RSA")]
    Rsa(PublicKeyJwkRsaDataRestDTO),
    #[serde(rename = "OKP")]
    Okp(PublicKeyJwkEllipticDataRestDTO),
    #[serde(rename = "oct")]
    Oct(PublicKeyJwkOctDataRestDTO),
    #[serde(rename = "MLWE")]
    Mlwe(PublicKeyJwkMlweDataRestDTO),
}

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema, From)]
#[from(PublicKeyJwkMlweDataDTO)]
pub(crate) struct PublicKeyJwkMlweDataRestDTO {
    pub r#use: Option<String>,
    pub alg: String,
    pub x: String,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema, From)]
#[from(PublicKeyJwkOctDataDTO)]
pub(crate) struct PublicKeyJwkOctDataRestDTO {
    pub r#use: Option<String>,
    pub k: String,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema, From)]
#[from(PublicKeyJwkRsaDataDTO)]
pub(crate) struct PublicKeyJwkRsaDataRestDTO {
    pub r#use: Option<String>,
    pub e: String,
    pub n: String,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema, From)]
#[from(PublicKeyJwkEllipticDataDTO)]
pub(crate) struct PublicKeyJwkEllipticDataRestDTO {
    pub r#use: Option<String>,
    pub crv: String,
    pub x: String,
    pub y: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
pub(crate) struct OpenID4VCIErrorResponseRestDTO {
    pub error: OpenID4VCIErrorRestEnum,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema, From)]
#[serde(rename_all = "snake_case")]
#[from(OpenID4VCIError)]
pub(crate) enum OpenID4VCIErrorRestEnum {
    UnsupportedGrantType,
    InvalidGrant,
    InvalidRequest,
    InvalidToken,
    InvalidOrMissingProof,
    UnsupportedCredentialFormat,
    UnsupportedCredentialType,
    CredentialRequestDenied,
    RuntimeError(String),
}

#[derive(Debug, Clone, Serialize, ToSchema, From)]
#[from(AuthorizationEncryptedResponseAlgorithm)]
pub(crate) enum OID4VPAuthorizationEncryptedResponseAlgorithm {
    #[serde(rename = "ECDH-ES")]
    EcdhEs,
}

#[derive(Debug, Clone, Serialize, PartialEq, ToSchema, Display, From)]
#[from(AuthorizationEncryptedResponseContentEncryptionAlgorithm)]
pub(crate) enum OID4VPAuthorizationEncryptedResponseContentEncryptionAlgorithm {
    A256GCM,
    #[serde(rename = "A128CBC-HS256")]
    #[strum(serialize = "A128CBC-HS256")]
    A128CBCHS256,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(IssuerResponseDTO)]
pub(crate) struct LVVCIssuerResponseRestDTO {
    pub credential: String,
}

#[derive(Clone, Debug, Deserialize, IntoParams, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PostSsiIssuerRejectQueryParams {
    pub credential_id: CredentialId,
}

#[derive(Clone, Debug, Deserialize, IntoParams, Serialize)]
#[into_params(parameter_in = Query)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PostSsiIssuerSubmitQueryParams {
    pub credential_id: CredentialId,
    pub did_value: DidValue,
}

#[skip_serializing_none]
#[derive(Clone, Serialize, Deserialize, Debug, From, ToSchema)]
#[from(ExtendedSubjectDTO)]
pub(crate) struct ExtendedSubjectRestDTO {
    #[from(with_fn = convert_inner)]
    pub keys: Option<ExtendedSubjectClaimsRestDTO>,
    #[from(with_fn = convert_inner)]
    pub wallet_storage_type: Option<WalletStorageTypeRestEnum>,
}

#[derive(Clone, Serialize, Deserialize, Debug, ToSchema)]
pub(crate) struct ExtendedSubjectClaimsRestDTO {
    #[serde(flatten)]
    pub claims: IndexMap<String, ProcivisSubjectClaimValueRestDTO>,
}

impl From<ExtendedSubjectClaimsDTO> for ExtendedSubjectClaimsRestDTO {
    fn from(value: ExtendedSubjectClaimsDTO) -> Self {
        Self {
            claims: value
                .claims
                .into_iter()
                .map(|(key, value)| (key, value.into()))
                .collect(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, From, ToSchema)]
#[from(OpenID4VCICredentialValueDetails)]
pub(crate) struct ProcivisSubjectClaimValueRestDTO {
    pub value: String,
    pub value_type: String,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(JsonLDContextResponseDTO)]
pub(crate) struct JsonLDContextResponseRestDTO {
    #[serde(rename = "@context")]
    pub context: JsonLDContextRestDTO,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(JsonLDContextDTO)]
pub(crate) struct JsonLDContextRestDTO {
    #[serde(rename = "@version", skip_serializing_if = "Option::is_none")]
    pub version: Option<f64>,
    #[serde(rename = "@protected")]
    pub protected: bool,
    pub id: String,
    pub r#type: String,
    #[serde(flatten)]
    #[from(with_fn = convert_inner)]
    pub entities: HashMap<String, JsonLDEntityRestDTO>,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(JsonLDEntityDTO)]
#[serde(untagged)]
pub(crate) enum JsonLDEntityRestDTO {
    Inline(JsonLDInlineEntityRestDTO),
    NestedObject(JsonLDNestedEntityRestDTO),
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(JsonLDNestedEntityDTO)]
pub(crate) struct JsonLDNestedEntityRestDTO {
    #[serde(rename = "@context")]
    pub context: JsonLDNestedContextRestDTO,
    #[serde(rename = "@id")]
    pub id: String,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(JsonLDNestedContextDTO)]
pub(crate) struct JsonLDNestedContextRestDTO {
    #[serde(rename = "@protected")]
    pub protected: bool,
    pub id: String,
    pub r#type: String,
    #[serde(flatten)]
    #[from(with_fn = convert_inner)]
    pub entities: HashMap<String, JsonLDEntityRestDTO>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(JsonLDInlineEntityDTO)]
pub(crate) struct JsonLDInlineEntityRestDTO {
    #[serde(rename = "@context")]
    #[from(with_fn = convert_inner)]
    pub context: Option<JsonLDContextRestDTO>,
    #[serde(rename = "@id")]
    pub id: String,
    #[serde(rename = "@type")]
    #[from(with_fn = convert_inner)]
    pub r#type: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, ToSchema, From)]
#[from(GetTrustAnchorResponseDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GetTrustAnchorResponseRestDTO {
    pub id: TrustAnchorId,
    pub name: String,
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    #[serde(serialize_with = "front_time")]
    pub created_date: OffsetDateTime,
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    #[serde(serialize_with = "front_time")]
    pub last_modified: OffsetDateTime,
    #[from(with_fn = convert_inner)]
    pub entities: Vec<GetTrustEntityResponseRestDTO>,
}

#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, PartialEq, ToSchema, From)]
#[from(GetTrustAnchorEntityListResponseDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GetTrustEntityResponseRestDTO {
    pub id: TrustEntityId,
    pub name: String,

    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    #[serde(serialize_with = "front_time")]
    pub created_date: OffsetDateTime,
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    #[serde(serialize_with = "front_time")]
    pub last_modified: OffsetDateTime,

    pub logo: Option<String>,
    pub website: Option<String>,
    pub terms_url: Option<String>,
    pub privacy_url: Option<String>,
    pub role: TrustEntityRoleRest,
    pub state: TrustEntityStateRest,

    pub did: DidValue,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(SdJwtVcTypeMetadataResponseDTO)]
pub(crate) struct SdJwtVcTypeMetadataResponseRestDTO {
    pub vct: String,
    pub name: Option<String>,
    #[serde(default)]
    #[from(with_fn = convert_inner)]
    pub display: Vec<SdJwtVcDisplayMetadataRestDTO>,
    #[serde(default)]
    #[from(with_fn = convert_inner)]
    pub claims: Vec<SdJwtVcClaimRestDTO>,
    #[serde(default)]
    pub schema: Option<serde_json::Value>,
    #[serde(default)]
    pub schema_uri: Option<Url>,
    #[from(with_fn = convert_inner)]
    pub layout_properties: Option<CredentialSchemaLayoutPropertiesRestDTO>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(SdJwtVcDisplayMetadataDTO)]
pub(crate) struct SdJwtVcDisplayMetadataRestDTO {
    pub lang: String,
    pub name: String,
    #[from(with_fn = convert_inner)]
    pub rendering: Option<SdJwtVcRenderingRestDTO>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(SdJwtVcRenderingDTO)]
pub(crate) struct SdJwtVcRenderingRestDTO {
    #[from(with_fn = convert_inner)]
    pub simple: Option<SdJwtVcSimpleRenderingRestDTO>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(SdJwtVcSimpleRenderingDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SdJwtVcSimpleRenderingRestDTO {
    #[from(with_fn = convert_inner)]
    pub logo: Option<SdJwtVcSimpleRenderingLogoRestDTO>,
    pub background_color: Option<String>,
    pub text_color: Option<String>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(SdJwtVcSimpleRenderingLogoDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SdJwtVcSimpleRenderingLogoRestDTO {
    pub uri: Url,
    pub alt_text: Option<String>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(SdJwtVcClaimDTO)]
pub(crate) struct SdJwtVcClaimRestDTO {
    pub path: Vec<Value>,
    #[serde(default)]
    #[from(with_fn = convert_inner)]
    pub display: Vec<SdJwtVcClaimDisplayRestDTO>,
    #[from(with_fn = convert_inner)]
    pub sd: Option<SdJwtVcClaimSdRestEnum>,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(SdJwtVcClaimSd)]
#[serde(rename_all = "lowercase")]
pub(crate) enum SdJwtVcClaimSdRestEnum {
    Always,
    Allowed,
    Never,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(SdJwtVcClaimDisplayDTO)]
pub(crate) struct SdJwtVcClaimDisplayRestDTO {
    pub lang: String,
    pub label: String,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema, TryInto)]
#[try_into(T = UpdateTrustEntityFromDidRequestDTO, Error = ServiceError)]
#[serde(rename_all = "camelCase")]
pub struct PatchTrustEntityRequestRestDTO {
    #[try_into(with_fn = convert_inner, infallible)]
    #[schema(nullable = false)]
    pub action: Option<PatchTrustEntityActionRestDTO>,
    /// Specify the entity name.
    #[serde(default)]
    #[schema(nullable = false)]
    #[try_into(with_fn = convert_inner, infallible)]
    pub name: Option<String>,
    /// base64 encoded image. Maximum size = 50kb.
    #[serde(default, with = "::serde_with::rust::double_option")]
    #[try_into(with_fn = try_convert_inner_of_inner)]
    pub logo: Option<Option<String>>,
    /// Specify the entity's domain name.
    #[serde(default, with = "::serde_with::rust::double_option")]
    #[try_into(with_fn = convert_inner_of_inner, infallible)]
    pub website: Option<Option<String>>,
    /// Specify a Terms of Service URL.
    #[serde(default, with = "::serde_with::rust::double_option")]
    #[try_into(with_fn = convert_inner_of_inner, infallible)]
    pub terms_url: Option<Option<String>>,
    /// Specify the Privacy Policy URL.
    #[serde(default, with = "::serde_with::rust::double_option")]
    #[try_into(with_fn = convert_inner_of_inner, infallible)]
    pub privacy_url: Option<Option<String>>,
    /// Whether the entity is a trusted issuer, verifier, or both.
    #[try_into(with_fn = convert_inner, infallible)]
    #[serde(default)]
    #[schema(nullable = false)]
    pub role: Option<TrustEntityRoleRest>,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema, Into)]
#[into(UpdateTrustEntityActionFromDidRequestDTO)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PatchTrustEntityActionRestDTO {
    AdminActivate,
    Activate,
    Withdraw,
    Remove,
}

#[derive(Clone, Debug, Deserialize, ToSchema, TryInto)]
#[try_into(T = CreateTrustEntityFromDidPublisherRequestDTO, Error = ServiceError)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SSIPostTrustEntityRequestRestDTO {
    /// Specify trust anchor ID.
    #[serde(default)]
    #[try_into(with_fn = convert_inner, infallible)]
    pub trust_anchor_id: Option<TrustAnchorId>,
    /// Specify DID value.
    #[try_into(infallible)]
    pub did: DidValue,
    /// Specify the entity name.
    #[try_into(infallible)]
    pub name: String,
    /// base64 encoded image. Maximum size = 50kb.
    #[try_into(with_fn = try_convert_inner)]
    pub logo: Option<String>,
    /// Specify the entity's domain name.
    #[try_into(with_fn = convert_inner, infallible)]
    pub website: Option<String>,
    /// Specify a Terms of Service url.
    #[try_into(with_fn = convert_inner, infallible)]
    pub terms_url: Option<String>,
    /// Specify the Privacy Policy url.
    #[try_into(with_fn = convert_inner, infallible)]
    pub privacy_url: Option<String>,
    #[try_into(infallible)]
    pub role: TrustEntityRoleRest,
}
