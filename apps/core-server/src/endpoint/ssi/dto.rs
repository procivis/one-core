use std::collections::HashMap;

use one_core::provider::did_method::dto::{
    DidDocumentDTO, DidServiceEndointDTO, DidVerificationMethodDTO,
};
use one_core::provider::issuance_protocol::openid4vci_draft13::error::OpenID4VCIError;
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
use proc_macros::options_not_nullable;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_with::{OneOrMany, serde_as, skip_serializing_none};
use shared_types::{DidValue, TrustAnchorId, TrustEntityId, TrustEntityKey};
use strum::Display;
use time::OffsetDateTime;
use url::Url;
use utoipa::ToSchema;

use crate::endpoint::credential_schema::dto::CredentialSchemaLayoutPropertiesRestDTO;
use crate::endpoint::trust_entity::dto::{
    TrustEntityRoleRest, TrustEntityStateRest, TrustEntityTypeRest,
};
use crate::serialize::front_time;

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
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
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(DidServiceEndointDTO)]
pub(crate) struct DidServiceEndointRestDTO {
    pub id: String,
    #[serde_as(as = "OneOrMany<_>")]
    pub r#type: Vec<String>,
    pub service_endpoint: serde_json::Value,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(DidVerificationMethodDTO)]
pub(crate) struct DidVerificationMethodRestDTO {
    pub id: String,
    pub r#type: String,
    pub controller: String,
    pub public_key_jwk: PublicKeyJwkRestDTO,
}

/// JWK representation of the public key used to verify the DID.
#[derive(Clone, Debug, Serialize, ToSchema, From)]
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

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(PublicKeyJwkMlweDataDTO)]
pub(crate) struct PublicKeyJwkMlweDataRestDTO {
    pub r#use: Option<String>,
    pub alg: Option<String>,
    pub x: String,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(PublicKeyJwkOctDataDTO)]
pub(crate) struct PublicKeyJwkOctDataRestDTO {
    pub alg: Option<String>,
    pub r#use: Option<String>,
    pub k: String,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(PublicKeyJwkRsaDataDTO)]
pub(crate) struct PublicKeyJwkRsaDataRestDTO {
    pub r#use: Option<String>,
    pub alg: Option<String>,
    pub e: String,
    pub n: String,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(PublicKeyJwkEllipticDataDTO)]
pub(crate) struct PublicKeyJwkEllipticDataRestDTO {
    pub r#use: Option<String>,
    pub alg: Option<String>,
    pub crv: String,
    pub x: String,
    pub y: Option<String>,
}

#[derive(Clone, Debug, Serialize, ToSchema)]
pub(crate) struct OpenID4VCIErrorResponseRestDTO {
    pub error: OpenID4VCIErrorRestEnum,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, ToSchema, From)]
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
    InvalidNotificationId,
    InvalidNotificationRequest,
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

#[options_not_nullable]
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
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    #[serde(serialize_with = "front_time")]
    pub created_date: OffsetDateTime,
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    #[serde(serialize_with = "front_time")]
    pub last_modified: OffsetDateTime,
    #[from(with_fn = convert_inner)]
    pub entities: Vec<GetSsiTrustEntityResponseRestDTO>,
}

#[options_not_nullable]
#[derive(Debug, Clone, Serialize, PartialEq, ToSchema, From)]
#[from(GetTrustAnchorEntityListResponseDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GetSsiTrustEntityResponseRestDTO {
    pub id: TrustEntityId,
    pub name: String,

    #[schema(example = "2023-06-09T14:19:57.000Z")]
    #[serde(serialize_with = "front_time")]
    pub created_date: OffsetDateTime,
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    #[serde(serialize_with = "front_time")]
    pub last_modified: OffsetDateTime,

    pub logo: Option<String>,
    pub website: Option<String>,
    pub terms_url: Option<String>,
    pub privacy_url: Option<String>,
    pub role: TrustEntityRoleRest,
    pub state: TrustEntityStateRest,
    pub r#type: TrustEntityTypeRest,
    pub entity_key: TrustEntityKey,
    pub content: Option<String>,
    pub did: Option<DidValue>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(SdJwtVcTypeMetadataResponseDTO)]
pub(crate) struct SdJwtVcTypeMetadataResponseRestDTO {
    pub vct: String,
    pub name: Option<String>,
    #[from(with_fn = convert_inner)]
    pub display: Vec<SdJwtVcDisplayMetadataRestDTO>,
    #[from(with_fn = convert_inner)]
    pub claims: Vec<SdJwtVcClaimRestDTO>,
    pub schema: Option<serde_json::Value>,
    pub schema_uri: Option<Url>,
    #[from(with_fn = convert_inner)]
    pub layout_properties: Option<CredentialSchemaLayoutPropertiesRestDTO>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(SdJwtVcDisplayMetadataDTO)]
pub(crate) struct SdJwtVcDisplayMetadataRestDTO {
    pub lang: String,
    pub name: String,
    #[from(with_fn = convert_inner)]
    pub rendering: Option<SdJwtVcRenderingRestDTO>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(SdJwtVcRenderingDTO)]
pub(crate) struct SdJwtVcRenderingRestDTO {
    #[from(with_fn = convert_inner)]
    pub simple: Option<SdJwtVcSimpleRenderingRestDTO>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(SdJwtVcSimpleRenderingDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SdJwtVcSimpleRenderingRestDTO {
    #[from(with_fn = convert_inner)]
    pub logo: Option<SdJwtVcSimpleRenderingLogoRestDTO>,
    pub background_color: Option<String>,
    pub text_color: Option<String>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(SdJwtVcSimpleRenderingLogoDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SdJwtVcSimpleRenderingLogoRestDTO {
    pub uri: Url,
    pub alt_text: Option<String>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(SdJwtVcClaimDTO)]
pub(crate) struct SdJwtVcClaimRestDTO {
    pub path: Vec<Value>,
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
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema, Default)]
#[serde(rename_all = "camelCase")]
pub struct PatchTrustEntityRequestRestDTO {
    /// Update the entity's status on the trust anchor.
    #[schema(nullable = false)]
    pub action: Option<PatchTrustEntityActionRestDTO>,
    /// Specify the entity name.
    #[serde(default)]
    #[schema(nullable = false)]
    pub name: Option<String>,
    /// base64 encoded image. Maximum size = 50kb.
    #[serde(default, with = "::serde_with::rust::double_option")]
    pub logo: Option<Option<String>>,
    /// Specify the entity's domain name.
    #[serde(default, with = "::serde_with::rust::double_option")]
    pub website: Option<Option<String>>,
    /// Specify a Terms of Service URL.
    #[serde(default, with = "::serde_with::rust::double_option")]
    pub terms_url: Option<Option<String>>,
    /// Specify the Privacy Policy URL.
    #[serde(default, with = "::serde_with::rust::double_option")]
    pub privacy_url: Option<Option<String>>,
    /// Whether the entity is a trusted issuer, verifier, or both.
    #[serde(default)]
    #[schema(nullable = false)]
    pub role: Option<TrustEntityRoleRest>,
    /// When adding a new certificate, put the PEM content here.
    #[serde(default)]
    pub content: Option<String>,
}

impl TryFrom<PatchTrustEntityRequestRestDTO> for UpdateTrustEntityFromDidRequestDTO {
    type Error = ServiceError;

    fn try_from(value: PatchTrustEntityRequestRestDTO) -> Result<Self, Self::Error> {
        Ok(Self {
            action: convert_inner(value.action),
            name: convert_inner(value.name),
            logo: try_convert_inner_of_inner(value.logo.map(|i| i.filter(|s| !s.is_empty())))?,
            website: convert_inner_of_inner(value.website),
            terms_url: convert_inner_of_inner(value.terms_url),
            privacy_url: convert_inner_of_inner(value.privacy_url),
            role: convert_inner(value.role),
            content: convert_inner(value.content),
        })
    }
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

#[options_not_nullable]
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
