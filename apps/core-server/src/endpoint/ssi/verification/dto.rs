use std::collections::HashMap;

use one_core::provider::verification_protocol::openid4vp::model::{
    DcqlSubmission, LdpVcAlgs, NestedPresentationSubmissionDescriptorDTO, OpenID4VPAlgs,
    OpenID4VPClientMetadataJwkDTO, OpenID4VPClientMetadataJwks, OpenID4VPDirectPostRequestDTO,
    OpenID4VPDirectPostResponseDTO, OpenID4VPDraftClientMetadata, OpenID4VPMdocAlgs,
    OpenID4VPPresentationDefinition, OpenID4VPPresentationDefinitionConstraint,
    OpenID4VPPresentationDefinitionConstraintField,
    OpenID4VPPresentationDefinitionConstraintFieldFilter,
    OpenID4VPPresentationDefinitionInputDescriptor, OpenID4VPVcSdJwtAlgs, OpenID4VPW3CJwtAlgs,
    OpenID4VPW3CLdpAlgs, OpenID4VpEmptyEntry, OpenID4VpPresentationFormat, PexSubmission,
    PresentationSubmissionDescriptorDTO, PresentationSubmissionMappingDTO, ResponseSubmission,
    VpSubmissionData,
};
use one_dto_mapper::{From, Into, convert_inner};
use proc_macros::options_not_nullable;
use serde::{Deserialize, Serialize};
use serde_with::json::JsonString;
use serde_with::{OneOrMany, serde_as};
use shared_types::InteractionId;
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::endpoint::ssi::dto::{
    OID4VPAuthorizationEncryptedResponseAlgorithm,
    OID4VPAuthorizationEncryptedResponseContentEncryptionAlgorithm, PublicKeyJwkRestDTO,
};
use crate::serialize::front_time_option;

#[options_not_nullable]
#[derive(Clone, Debug, Deserialize, ToSchema, Into)]
#[into(OpenID4VPDirectPostRequestDTO)]
pub(crate) struct OpenID4VPDirectPostRequestRestDTO {
    #[serde(flatten)]
    pub submission_data: VpSubmissionDataRestDTO,
    #[schema(example = "3fa85f64-5717-4562-b3fc-2c963f66afa6")]
    pub state: Option<InteractionId>,
}

/// Represents the different types of VP token submissions supported by OpenID4VP.
/// Untagged serialization automatically detects the submission type.
#[derive(Clone, Debug, Deserialize, ToSchema, Into)]
#[into(VpSubmissionData)]
#[serde(untagged)]
pub(crate) enum VpSubmissionDataRestDTO {
    /// Presentation Exchange submission with presentation_submission field
    Pex(PexSubmissionRestDTO),
    /// DCQL submission with vp_token map structure
    Dcql(DcqlSubmissionRestDTO),
    /// Response submission with response field (JWE encrypted payload)
    EncryptedResponse(ResponseSubmissionRestDTO),
}

#[serde_as]
#[derive(Debug, Deserialize, Clone, Into, ToSchema)]
#[into(PexSubmission)]
pub(crate) struct PexSubmissionRestDTO {
    #[serde_as(as = "OneOrMany<_>")]
    pub vp_token: Vec<String>,
    #[serde_as(as = "JsonString")]
    pub presentation_submission: PresentationSubmissionMappingRestDTO,
}

#[serde_as]
#[derive(Debug, Deserialize, Clone, ToSchema, Into)]
#[into(DcqlSubmission)]
pub(crate) struct DcqlSubmissionRestDTO {
    #[serde_as(as = "JsonString")]
    pub vp_token: HashMap<String, Vec<String>>,
}

#[derive(Debug, Deserialize, Clone, ToSchema, Into)]
#[into(ResponseSubmission)]
pub(crate) struct ResponseSubmissionRestDTO {
    pub response: String,
}

#[derive(Clone, Debug, Deserialize, ToSchema, Into)]
#[into(PresentationSubmissionMappingDTO)]
pub(crate) struct PresentationSubmissionMappingRestDTO {
    pub id: String,
    pub definition_id: String,
    #[into(with_fn = convert_inner)]
    pub descriptor_map: Vec<PresentationSubmissionDescriptorRestDTO>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Deserialize, ToSchema, Into)]
#[into(PresentationSubmissionDescriptorDTO)]
pub(crate) struct PresentationSubmissionDescriptorRestDTO {
    pub id: String,
    #[schema(example = "SD_JWT")]
    pub format: String,
    pub path: String,
    #[into(with_fn = convert_inner)]
    pub path_nested: Option<NestedPresentationSubmissionDescriptorRestDTO>,
}

#[derive(Clone, Debug, Deserialize, ToSchema, Into)]
#[into(NestedPresentationSubmissionDescriptorDTO)]
pub(crate) struct NestedPresentationSubmissionDescriptorRestDTO {
    pub format: String,
    pub path: String,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(OpenID4VPDirectPostResponseDTO)]
pub(crate) struct OpenID4VPDirectPostResponseRestDTO {
    pub redirect_uri: Option<String>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(OpenID4VPDraftClientMetadata)]
pub(crate) struct OpenID4VPDraftClientMetadataResponseRestDTO {
    #[from(with_fn = convert_inner)]
    pub jwks: Option<OpenID4VPClientMetadataJwksRestDTO>,
    pub jwks_uri: Option<String>,
    pub id_token_encrypted_response_enc: Option<String>,
    pub id_token_encrypted_response_alg: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub subject_syntax_types_supported: Vec<String>,
    #[from(with_fn = convert_inner)]
    pub vp_formats: HashMap<String, OpenID4VPFormatRestDTO>,
    #[from(with_fn = convert_inner)]
    pub authorization_encrypted_response_alg: Option<OID4VPAuthorizationEncryptedResponseAlgorithm>,
    #[from(with_fn = convert_inner)]
    pub authorization_encrypted_response_enc:
        Option<OID4VPAuthorizationEncryptedResponseContentEncryptionAlgorithm>,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(OpenID4VPClientMetadataJwks)]
pub(crate) struct OpenID4VPClientMetadataJwksRestDTO {
    #[from(with_fn = convert_inner)]
    pub keys: Vec<OpenID4VPClientMetadataJwkRestDTO>,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(OpenID4VPClientMetadataJwkDTO)]
pub(crate) struct OpenID4VPClientMetadataJwkRestDTO {
    #[serde(rename = "kid")]
    pub key_id: String,
    #[serde(flatten)]
    pub jwk: PublicKeyJwkRestDTO,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(OpenID4VpEmptyEntry)]
pub(crate) struct OpenID4VpEmptyEntryRestDTO {}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(OpenID4VpPresentationFormat)]
#[serde(untagged)]
pub(crate) enum OpenID4VPFormatRestDTO {
    Empty(OpenID4VpEmptyEntryRestDTO),
    SdJwtVcAlgs(OpenID4VPVcSdJwtAlgsRestDTO),
    LdpVcAlgs(LdpVcAlgsRestDTO),
    W3CJwtAlgs(OpenID4VPW3CJwtAlgsRestDTO),
    W3CLdpAlgs(OpenID4VPW3CLdpAlgsRestDTO),
    MdocAlgs(OpenID4VPMdocAlgsRestDTO),
    GenericAlgList(OpenID4VPAlgsRestDTO),
    Other(serde_json::Value),
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(OpenID4VPVcSdJwtAlgs)]
pub(crate) struct OpenID4VPVcSdJwtAlgsRestDTO {
    #[serde(skip_serializing_if = "Vec::is_empty", rename = "sd-jwt_alg_values")]
    pub sd_jwt_alg_values: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", rename = "kb-jwt_alg_values")]
    pub kb_jwt_alg_values: Vec<String>,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(LdpVcAlgs)]
pub(crate) struct LdpVcAlgsRestDTO {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub proof_type: Vec<String>,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(OpenID4VPAlgs)]
pub(crate) struct OpenID4VPAlgsRestDTO {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub alg: Vec<String>,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(OpenID4VPW3CJwtAlgs)]
pub(crate) struct OpenID4VPW3CJwtAlgsRestDTO {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub alg_values: Vec<String>,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(OpenID4VPW3CLdpAlgs)]
pub(crate) struct OpenID4VPW3CLdpAlgsRestDTO {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub proof_type_values: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub cryptosuite_values: Vec<String>,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(OpenID4VPMdocAlgs)]
pub(crate) struct OpenID4VPMdocAlgsRestDTO {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub issuerauth_alg_values: Vec<i32>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub deviceauth_alg_values: Vec<i32>,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(OpenID4VPPresentationDefinition)]
pub(crate) struct OpenID4VPPresentationDefinitionResponseRestDTO {
    pub id: String,
    #[from(with_fn = convert_inner)]
    pub input_descriptors: Vec<OpenID4VPPresentationDefinitionInputDescriptorRestDTO>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(OpenID4VPPresentationDefinitionInputDescriptor)]
pub(crate) struct OpenID4VPPresentationDefinitionInputDescriptorRestDTO {
    pub id: String,
    pub name: Option<String>,
    pub purpose: Option<String>,
    #[from(with_fn = convert_inner)]
    pub format: HashMap<String, OpenID4VPFormatRestDTO>,
    pub constraints: OpenID4VPPresentationDefinitionConstraintRestDTO,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(OpenID4VPPresentationDefinitionConstraint)]
pub(crate) struct OpenID4VPPresentationDefinitionConstraintRestDTO {
    #[from(with_fn = convert_inner)]
    pub fields: Vec<OpenID4VPPresentationDefinitionConstraintFieldRestDTO>,
    #[serde(serialize_with = "front_time_option")]
    #[schema(nullable = false, example = "2023-06-09T14:19:57.000Z")]
    pub validity_credential_nbf: Option<OffsetDateTime>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(OpenID4VPPresentationDefinitionConstraintField)]
pub(crate) struct OpenID4VPPresentationDefinitionConstraintFieldRestDTO {
    #[from(with_fn = convert_inner)]
    pub id: Option<Uuid>,
    pub path: Vec<String>,
    pub optional: Option<bool>,
    #[from(with_fn = convert_inner)]
    pub filter: Option<OpenID4VPPresentationDefinitionConstraintFieldFilterRestDTO>,
    pub intent_to_retain: Option<bool>,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(OpenID4VPPresentationDefinitionConstraintFieldFilter)]
pub(crate) struct OpenID4VPPresentationDefinitionConstraintFieldFilterRestDTO {
    pub r#type: String,
    pub r#const: String,
}
