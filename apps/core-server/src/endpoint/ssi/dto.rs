use std::collections::HashMap;

use one_core::provider::did_method::dto::{
    DidDocumentDTO, DidServiceEndointDTO, DidVerificationMethodDTO,
};
use one_core::provider::issuance_protocol::error::OpenID4VCIError;
use one_core::service::ssi_issuer::dto::{
    JsonLDContextDTO, JsonLDContextResponseDTO, JsonLDEntityDTO, JsonLDInlineEntityDTO,
    JsonLDNestedContextDTO, JsonLDNestedEntityDTO, SdJwtVcClaimDTO, SdJwtVcClaimDisplayDTO,
    SdJwtVcClaimSd, SdJwtVcDisplayMetadataDTO, SdJwtVcRenderingDTO,
    SdJwtVcSimpleRenderingBackgroundImageDTO, SdJwtVcSimpleRenderingDTO,
    SdJwtVcSimpleRenderingLogoDTO, SdJwtVcTypeMetadataResponseDTO,
};
use one_core::service::trust_collection::dto::{TrustCollectionPublicResponseDTO, TrustListDTO};
use one_dto_mapper::{From, convert_inner, convert_inner_of_inner};
use proc_macros::options_not_nullable;
use serde::Serialize;
use serde_json::Value;
use serde_with::{OneOrMany, serde_as};
use shared_types::{DidValue, TrustListSubscriberId, TrustListSubscriptionId};
use standardized_types::jwk::PublicJwk;
use url::Url;
use utoipa::ToSchema;

use crate::deserialize::one_or_many;
use crate::endpoint::credential_schema::dto::CredentialSchemaLayoutPropertiesRestDTO;
use crate::endpoint::trust_list_publication::dto::TrustListRoleRestEnum;

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
    #[schema(schema_with = one_or_many::<String>)]
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
    pub public_key_jwk: PublicJwk,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema)]
pub(crate) struct OpenID4VCIErrorResponseRestDTO {
    pub error: OpenID4VCIErrorRestEnum,
    pub error_description: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, ToSchema, From)]
#[serde(rename_all = "snake_case")]
#[from(OpenID4VCIError)]
pub(crate) enum OpenID4VCIErrorRestEnum {
    UnsupportedGrantType,
    InvalidGrant,
    InvalidClient,
    InvalidRequest,
    InvalidToken,
    InvalidNonce,
    InvalidOrMissingProof,
    UnsupportedCredentialFormat,
    UnsupportedCredentialType,
    CredentialRequestDenied,
    InvalidNotificationId,
    InvalidNotificationRequest,
    InvalidEncryptionParameters,
    UseAttestationChallenge,
    UseFreshAttestation,
    InvalidDpopProof,
    RuntimeError(String),
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

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(SdJwtVcTypeMetadataResponseDTO)]
pub(crate) struct SdJwtVcTypeMetadataResponseRestDTO {
    pub vct: String,
    pub name: Option<String>,
    pub description: Option<String>,
    #[from(with_fn = convert_inner)]
    pub display: Vec<SdJwtVcDisplayMetadataRestDTO>,
    #[from(with_fn = convert_inner)]
    pub claims: Vec<SdJwtVcClaimRestDTO>,
    #[from(with_fn = convert_inner)]
    pub layout_properties: Option<CredentialSchemaLayoutPropertiesRestDTO>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(SdJwtVcDisplayMetadataDTO)]
pub(crate) struct SdJwtVcDisplayMetadataRestDTO {
    pub locale: String,
    pub name: String,
    pub description: Option<String>,
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
pub(crate) struct SdJwtVcSimpleRenderingRestDTO {
    #[from(with_fn = convert_inner)]
    pub logo: Option<SdJwtVcSimpleRenderingLogoRestDTO>,
    #[from(with_fn = convert_inner)]
    pub background_image: Option<SdJwtVcSimpleRenderingBackgroundImageRestDTO>,
    pub background_color: Option<String>,
    pub text_color: Option<String>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(SdJwtVcSimpleRenderingLogoDTO)]
pub(crate) struct SdJwtVcSimpleRenderingLogoRestDTO {
    pub uri: Url,
    pub alt_text: Option<String>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(SdJwtVcSimpleRenderingBackgroundImageDTO)]
pub struct SdJwtVcSimpleRenderingBackgroundImageRestDTO {
    pub uri: Url,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(SdJwtVcClaimDTO)]
pub(crate) struct SdJwtVcClaimRestDTO {
    pub path: Vec<Value>,
    #[from(with_fn = convert_inner)]
    pub display: Vec<SdJwtVcClaimDisplayRestDTO>,
    pub mandatory: Option<bool>,
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

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(SdJwtVcClaimDisplayDTO)]
pub(crate) struct SdJwtVcClaimDisplayRestDTO {
    pub locale: String,
    pub label: String,
    pub description: Option<String>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(TrustCollectionPublicResponseDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TrustCollectionResponseRestDTO {
    pub name: String,
    #[from(with_fn = convert_inner)]
    pub trust_lists: Vec<TrustListRestDTO>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(TrustListDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TrustListRestDTO {
    pub name: String,
    pub id: TrustListSubscriptionId,
    #[from(with_fn = convert_inner)]
    pub role: Option<TrustListRoleRestEnum>,
    pub reference: String,
    pub r#type: TrustListSubscriberId,
}
