use std::collections::HashMap;

use one_core::provider::verification_protocol::openid4vp::model::{
    DcqlSubmission, NestedPresentationSubmissionDescriptorDTO, OpenID4VPDirectPostRequestDTO,
    OpenID4VPDirectPostResponseDTO, OpenID4VPDraftClientMetadata, OpenID4VPPresentationDefinition,
    OpenID4VPPresentationDefinitionConstraint, OpenID4VPPresentationDefinitionConstraintField,
    OpenID4VPPresentationDefinitionConstraintFieldFilter,
    OpenID4VPPresentationDefinitionInputDescriptor, PexSubmission,
    PresentationSubmissionDescriptorDTO, PresentationSubmissionMappingDTO, ResponseSubmission,
    VpSubmissionData,
};
use one_dto_mapper::{From, Into, convert_inner};
use proc_macros::options_not_nullable;
use serde::{Deserialize, Serialize};
use serde_with::json::JsonString;
use serde_with::{OneOrMany, serde_as};
use shared_types::InteractionId;
use standardized_types::jwa::EncryptionAlgorithm;
use standardized_types::openid4vp::{ClientMetadataJwks, PresentationFormat};
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::endpoint::ssi::dto::OID4VPAuthorizationEncryptedResponseAlgorithm;
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
    pub jwks: Option<ClientMetadataJwks>,
    pub jwks_uri: Option<String>,
    pub id_token_encrypted_response_enc: Option<String>,
    pub id_token_encrypted_response_alg: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub subject_syntax_types_supported: Vec<String>,
    #[from(with_fn = convert_inner)]
    pub vp_formats: HashMap<String, PresentationFormat>,
    #[from(with_fn = convert_inner)]
    pub authorization_encrypted_response_alg: Option<OID4VPAuthorizationEncryptedResponseAlgorithm>,
    pub authorization_encrypted_response_enc: Option<EncryptionAlgorithm>,
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
    pub format: HashMap<String, PresentationFormat>,
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
