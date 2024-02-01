use std::collections::HashMap;

use crate::{
    endpoint::credential_schema::dto::CredentialSchemaListItemResponseRestDTO,
    serialize::front_time,
};
use dto_mapper::{convert_inner, convert_inner_of_inner, From, Into};
use one_core::provider::did_method::dto::DidDocumentDTO;
use one_core::provider::did_method::dto::DidVerificationMethodDTO;
use one_core::provider::did_method::dto::PublicKeyJwkDTO;
use one_core::provider::did_method::dto::PublicKeyJwkEllipticDataDTO;
use one_core::provider::did_method::dto::PublicKeyJwkMlweDataDTO;
use one_core::provider::did_method::dto::PublicKeyJwkOctDataDTO;
use one_core::provider::did_method::dto::PublicKeyJwkRsaDataDTO;
use one_core::provider::transport_protocol::openid4vc::dto::{
    OpenID4VCICredentialDefinition, OpenID4VCICredentialOfferCredentialDTO,
    OpenID4VCICredentialOfferDTO, OpenID4VCICredentialSubject, OpenID4VCICredentialValueDetails,
    OpenID4VCIGrant, OpenID4VCIGrants,
};
use one_core::service::oidc::dto::{
    NestedPresentationSubmissionDescriptorDTO, OpenID4VPDirectPostRequestDTO,
    OpenID4VPDirectPostResponseDTO, PresentationSubmissionDescriptorDTO,
    PresentationSubmissionMappingDTO,
};
use one_core::service::ssi_issuer::dto::{
    JsonLDContextDTO, JsonLDContextResponseDTO, JsonLDEntityDTO, JsonLDInlineEntityDTO,
};
use one_core::service::{
    oidc::dto::{
        OpenID4VCICredentialDefinitionRequestDTO, OpenID4VCICredentialRequestDTO,
        OpenID4VCICredentialResponseDTO, OpenID4VCIDiscoveryResponseDTO, OpenID4VCIError,
        OpenID4VCIIssuerMetadataCredentialDefinitionResponseDTO,
        OpenID4VCIIssuerMetadataCredentialSupportedDisplayDTO,
        OpenID4VCIIssuerMetadataCredentialSupportedResponseDTO,
        OpenID4VCIIssuerMetadataResponseDTO, OpenID4VCIProofRequestDTO, OpenID4VCITokenRequestDTO,
        OpenID4VCITokenResponseDTO,
    },
    ssi_issuer::dto::IssuerResponseDTO,
    ssi_verifier::dto::{ConnectVerifierResponseDTO, ProofRequestClaimDTO},
};
use serde::{Deserialize, Serialize};
use serde_with::{self, json::JsonString};
use shared_types::DidValue;
use time::OffsetDateTime;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ProofRequestQueryParams {
    pub proof: Uuid,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConnectRequestRestDTO {
    pub did: DidValue,
}

// verifier specific
#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(rename_all = "camelCase")]
pub struct PostSsiVerifierConnectQueryParams {
    pub protocol: String,
    pub proof: Uuid,
    pub redirect_uri: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[from(ConnectVerifierResponseDTO)]
#[serde(rename_all = "camelCase")]
pub struct ConnectVerifierResponseRestDTO {
    #[from(with_fn = convert_inner)]
    pub claims: Vec<ProofRequestClaimRestDTO>,
    pub verifier_did: DidValue,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[from(OpenID4VCIIssuerMetadataResponseDTO)]
pub struct OpenID4VCIIssuerMetadataResponseRestDTO {
    pub credential_issuer: String,
    pub credential_endpoint: String,
    #[from(with_fn = convert_inner)]
    pub credentials_supported: Vec<OpenID4VCIIssuerMetadataCredentialSupportedResponseRestDTO>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[from(OpenID4VCIIssuerMetadataCredentialSupportedResponseDTO)]
pub struct OpenID4VCIIssuerMetadataCredentialSupportedResponseRestDTO {
    pub format: String,
    pub credential_definition: OpenID4VCIIssuerMetadataCredentialDefinitionResponseRestDTO,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[from(with_fn = convert_inner_of_inner)]
    pub display: Option<Vec<OpenID4VCIIssuerMetadataCredentialSupportedDisplayRestDTO>>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[from(OpenID4VCIIssuerMetadataCredentialSupportedDisplayDTO)]
pub struct OpenID4VCIIssuerMetadataCredentialSupportedDisplayRestDTO {
    pub name: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[from(OpenID4VCIIssuerMetadataCredentialDefinitionResponseDTO)]
pub struct OpenID4VCIIssuerMetadataCredentialDefinitionResponseRestDTO {
    pub r#type: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[from(OpenID4VCIDiscoveryResponseDTO)]
pub struct OpenID4VCIDiscoveryResponseRestDTO {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    pub response_types_supported: Vec<String>,
    pub grant_types_supported: Vec<String>,
    pub subject_types_supported: Vec<String>,
    pub id_token_signing_alg_values_supported: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, Into)]
#[into(OpenID4VCITokenRequestDTO)]
pub struct OpenID4VCITokenRequestRestDTO {
    pub grant_type: String,
    #[serde(rename = "pre-authorized_code")]
    pub pre_authorized_code: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, Into)]
#[into(OpenID4VCICredentialDefinitionRequestDTO)]
pub struct OpenID4VCICredentialDefinitionRequestRestDTO {
    pub r#type: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, Into)]
#[into(OpenID4VCICredentialRequestDTO)]
pub struct OpenID4VCICredentialRequestRestDTO {
    pub format: String,
    pub credential_definition: OpenID4VCICredentialDefinitionRequestRestDTO,
    pub proof: OpenID4VCIProofRequestRestDTO,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, Into)]
#[into(OpenID4VCIProofRequestDTO)]
pub struct OpenID4VCIProofRequestRestDTO {
    pub proof_type: String,
    pub jwt: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(DidDocumentDTO)]
pub struct DidDocumentRestDTO {
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

    #[serde(flatten)]
    pub rest: serde_json::Value,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(DidVerificationMethodDTO)]
pub struct DidVerificationMethodRestDTO {
    pub id: String,
    pub r#type: String,
    pub controller: String,
    pub public_key_jwk: PublicKeyJwkRestDTO,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[serde(tag = "kty")]
#[from(PublicKeyJwkDTO)]
pub enum PublicKeyJwkRestDTO {
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

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema, From)]
#[from(PublicKeyJwkMlweDataDTO)]
pub struct PublicKeyJwkMlweDataRestDTO {
    pub r#use: Option<String>,
    pub alg: String,
    pub x: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema, From)]
#[from(PublicKeyJwkOctDataDTO)]
pub struct PublicKeyJwkOctDataRestDTO {
    pub r#use: Option<String>,
    pub k: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema, From)]
#[from(PublicKeyJwkRsaDataDTO)]
pub struct PublicKeyJwkRsaDataRestDTO {
    pub r#use: Option<String>,
    pub e: String,
    pub n: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema, From)]
#[from(PublicKeyJwkEllipticDataDTO)]
pub struct PublicKeyJwkEllipticDataRestDTO {
    pub r#use: Option<String>,
    pub crv: String,
    pub x: String,
    pub y: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[serde(transparent)]
pub struct DurationSecondsRest(pub i64);

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[from(OpenID4VCITokenResponseDTO)]
pub struct OpenID4VCITokenResponseRestDTO {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: DurationSecondsRest,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
pub struct OpenID4VCIErrorResponseRestDTO {
    pub error: OpenID4VCIErrorRestEnum,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema, From)]
#[serde(rename_all = "snake_case")]
#[from(OpenID4VCIError)]
pub enum OpenID4VCIErrorRestEnum {
    UnsupportedGrantType,
    InvalidGrant,
    InvalidRequest,
    InvalidToken,
    InvalidOrMissingProof,
    UnsupportedCredentialFormat,
    UnsupportedCredentialType,
    VPFormatsNotSupported,
    VCFormatsNotSupported,
}

#[serde_with::serde_as]
#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, Into)]
#[into(OpenID4VPDirectPostRequestDTO)]
pub struct OpenID4VPDirectPostRequestRestDTO {
    #[serde_as(as = "JsonString")]
    pub presentation_submission: PresentationSubmissionMappingRestDTO,
    #[schema(example = "<jwt/sdjwt token>")]
    pub vp_token: String,
    #[schema(example = "<UUID>")]
    pub state: Uuid,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, Into)]
#[into(PresentationSubmissionMappingDTO)]
pub struct PresentationSubmissionMappingRestDTO {
    pub id: String,
    pub definition_id: String,
    #[into(with_fn = convert_inner)]
    pub descriptor_map: Vec<PresentationSubmissionDescriptorRestDTO>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, Into)]
#[into(PresentationSubmissionDescriptorDTO)]
pub struct PresentationSubmissionDescriptorRestDTO {
    pub id: String,
    #[schema(example = "SDJWT")]
    pub format: String,
    pub path: String,
    #[into(with_fn = convert_inner)]
    pub path_nested: Option<NestedPresentationSubmissionDescriptorRestDTO>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, Into)]
#[into(NestedPresentationSubmissionDescriptorDTO)]
pub struct NestedPresentationSubmissionDescriptorRestDTO {
    pub format: String,
    pub path: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[from(OpenID4VPDirectPostResponseDTO)]
pub struct OpenID4VPDirectPostResponseRestDTO {
    pub redirect_uri: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(ProofRequestClaimDTO)]
pub struct ProofRequestClaimRestDTO {
    pub id: Uuid,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,
    pub key: String,
    pub datatype: String,
    pub required: bool,
    pub credential_schema: CredentialSchemaListItemResponseRestDTO,
}

// issuer specific
#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(rename_all = "camelCase")]
pub struct PostSsiIssuerConnectQueryParams {
    pub protocol: String,
    pub credential: Uuid,
    pub redirect_uri: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(IssuerResponseDTO)]
pub struct IssuerResponseRestDTO {
    pub credential: String,
    pub format: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(OpenID4VCICredentialResponseDTO)]
pub struct OpenID4VCICredentialResponseRestDTO {
    pub credential: String,
    pub format: String,
    pub redirect_uri: Option<String>,
}

#[derive(Clone, Debug, Deserialize, IntoParams, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PostSsiIssuerRejectQueryParams {
    pub credential_id: Uuid,
}

#[derive(Clone, Debug, Deserialize, IntoParams, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PostSsiIssuerSubmitQueryParams {
    pub credential_id: Uuid,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(OpenID4VCICredentialOfferDTO)]
pub struct OpenID4VCICredentialOfferRestDTO {
    pub credential_issuer: String,
    #[from(with_fn = convert_inner)]
    pub credentials: Vec<OpenID4VCICredentialOfferCredentialRestDTO>,
    pub grants: OpenID4VCIGrantsRestDTO,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(OpenID4VCIGrants)]
pub struct OpenID4VCIGrantsRestDTO {
    #[serde(rename = "urn:ietf:params:oauth:grant-type:pre-authorized_code")]
    pub code: OpenID4VCIGrantRestDTO,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(OpenID4VCIGrant)]
pub struct OpenID4VCIGrantRestDTO {
    #[serde(rename = "pre-authorized_code")]
    pub pre_authorized_code: String,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(OpenID4VCICredentialOfferCredentialDTO)]
pub struct OpenID4VCICredentialOfferCredentialRestDTO {
    pub format: String,
    pub credential_definition: OpenID4VCICredentialDefinitionRestDTO,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(OpenID4VCICredentialDefinition)]
#[serde(rename_all = "camelCase")]
pub struct OpenID4VCICredentialDefinitionRestDTO {
    pub r#type: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[from(with_fn = convert_inner)]
    pub credential_subject: Option<OpenID4VCICredentialSubjectRestDTO>,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(OpenID4VCICredentialSubject)]
pub struct OpenID4VCICredentialSubjectRestDTO {
    #[serde(flatten)]
    #[from(with_fn = convert_inner)]
    pub keys: HashMap<String, OpenID4VCICredentialValueDetailsRestDTO>,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(OpenID4VCICredentialValueDetails)]
pub struct OpenID4VCICredentialValueDetailsRestDTO {
    pub value: String,
    pub value_type: String,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(JsonLDContextResponseDTO)]
pub struct JsonLDContextResponseRestDTO {
    #[serde(rename = "@context")]
    pub context: JsonLDContextRestDTO,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(JsonLDContextDTO)]
pub struct JsonLDContextRestDTO {
    #[serde(rename = "@version")]
    pub version: f64,
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
pub enum JsonLDEntityRestDTO {
    Reference(String),
    Inline(JsonLDInlineEntityRestDTO),
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(JsonLDInlineEntityDTO)]
pub struct JsonLDInlineEntityRestDTO {
    #[serde(rename = "@context")]
    pub context: JsonLDContextRestDTO,
    #[serde(rename = "@id")]
    pub id: String,
}
