use std::collections::HashMap;

use one_core::provider::did_method::model::{DidDocument, DidVerificationMethod};
use one_core::provider::exchange_protocol::openid4vc::error::OpenID4VCIError;
use one_core::provider::exchange_protocol::openid4vc::model::{
    AuthorizationEncryptedResponseAlgorithm,
    AuthorizationEncryptedResponseContentEncryptionAlgorithm,
    NestedPresentationSubmissionDescriptorDTO, OpenID4VCICredentialDefinition,
    OpenID4VCICredentialDefinitionRequestDTO, OpenID4VCICredentialOfferClaim,
    OpenID4VCICredentialOfferCredentialDTO, OpenID4VCICredentialOfferDTO,
    OpenID4VCICredentialRequestDTO, OpenID4VCICredentialSubject, OpenID4VCICredentialValueDetails,
    OpenID4VCIDiscoveryResponseDTO, OpenID4VCIGrant, OpenID4VCIGrants,
    OpenID4VCIIssuerMetadataCredentialDefinitionResponseDTO,
    OpenID4VCIIssuerMetadataCredentialSchemaResponseDTO,
    OpenID4VCIIssuerMetadataCredentialSupportedDisplayDTO,
    OpenID4VCIIssuerMetadataCredentialSupportedResponseDTO,
    OpenID4VCIIssuerMetadataMdocClaimsValuesDTO, OpenID4VCIIssuerMetadataResponseDTO,
    OpenID4VCIProofRequestDTO, OpenID4VCITokenResponseDTO, OpenID4VPClientMetadata,
    OpenID4VPClientMetadataJwkDTO, OpenID4VPDirectPostRequestDTO, OpenID4VPDirectPostResponseDTO,
    OpenID4VPFormat, OpenID4VPPresentationDefinition, OpenID4VPPresentationDefinitionConstraint,
    OpenID4VPPresentationDefinitionConstraintField,
    OpenID4VPPresentationDefinitionConstraintFieldFilter,
    OpenID4VPPresentationDefinitionInputDescriptor,
    OpenID4VPPresentationDefinitionInputDescriptorFormat, PresentationSubmissionDescriptorDTO,
    PresentationSubmissionMappingDTO,
};
use one_core::service::key::dto::{
    PublicKeyJwkDTO, PublicKeyJwkEllipticDataDTO, PublicKeyJwkMlweDataDTO, PublicKeyJwkOctDataDTO,
    PublicKeyJwkRsaDataDTO,
};
use one_core::service::oidc::dto::OpenID4VCICredentialResponseDTO;
use one_core::service::ssi_issuer::dto::{
    IssuerResponseDTO, JsonLDContextDTO, JsonLDContextResponseDTO, JsonLDEntityDTO,
    JsonLDInlineEntityDTO, JsonLDNestedContextDTO, JsonLDNestedEntityDTO,
};
use one_core::service::trust_anchor::dto::GetTrustAnchorResponseDTO;
use one_core::service::trust_entity::dto::GetTrustEntityResponseDTO;
use one_dto_mapper::{convert_inner, convert_inner_of_inner, From, Into};
use serde::{Deserialize, Serialize};
use serde_with::json::JsonString;
use shared_types::{CredentialId, DidValue, KeyId, TrustAnchorId, TrustEntityId};
use time::OffsetDateTime;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::endpoint::credential_schema::dto::{CredentialSchemaType, WalletStorageTypeRestEnum};
use crate::endpoint::trust_anchor::dto::GetTrustAnchorDetailResponseRestDTO;
use crate::endpoint::trust_entity::dto::TrustEntityRoleRest;
use crate::serialize::{front_time, front_time_option};

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
    #[serde(skip_serializing_if = "Option::is_none")]
    #[from(with_fn = convert_inner_of_inner)]
    pub claims: Option<HashMap<String, OpenID4VCIIssuerMetadataMdocClaimsValuesRestDTO>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[from(with_fn = convert_inner_of_inner)]
    pub order: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[from(with_fn = convert_inner)]
    pub credential_definition: Option<OpenID4VCIIssuerMetadataCredentialDefinitionResponseRestDTO>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub doctype: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[from(with_fn = convert_inner_of_inner)]
    pub display: Option<Vec<OpenID4VCIIssuerMetadataCredentialSupportedDisplayRestDTO>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[from(with_fn = convert_inner)]
    pub wallet_storage_type: Option<WalletStorageTypeRestEnum>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[from(OpenID4VCIIssuerMetadataCredentialSupportedDisplayDTO)]
pub struct OpenID4VCIIssuerMetadataCredentialSupportedDisplayRestDTO {
    pub name: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[from(OpenID4VCIIssuerMetadataCredentialDefinitionResponseDTO)]
#[serde(rename_all = "camelCase")]
pub struct OpenID4VCIIssuerMetadataCredentialDefinitionResponseRestDTO {
    pub r#type: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[from(with_fn = convert_inner)]
    pub credential_schema: Option<OpenID4VCIIssuerMetadataCredentialSchemaRestDTO>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[from(OpenID4VCIIssuerMetadataCredentialSchemaResponseDTO)]
pub struct OpenID4VCIIssuerMetadataCredentialSchemaRestDTO {
    pub id: String,
    pub r#type: CredentialSchemaType,
}

#[derive(Clone, Debug, Deserialize, Serialize, From)]
#[from(OpenID4VCIIssuerMetadataMdocClaimsValuesDTO)]
pub struct OpenID4VCIIssuerMetadataMdocClaimsValuesRestDTO {
    #[from(with_fn = convert_inner)]
    #[serde(skip_serializing_if = "HashMap::is_empty", default)]
    pub value: HashMap<String, OpenID4VCIIssuerMetadataMdocClaimsValuesRestDTO>,
    /// Indication of what type of key storage the wallet should use. See the [wallet storage type](/api/resources/credential_schemas#wallet-storage-type) guide.
    pub value_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mandatory: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub order: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub array: Option<bool>,
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

#[derive(Clone, Debug, Deserialize, ToSchema)]
pub struct OpenID4VCITokenRequestRestDTO {
    #[schema(example = "urn:ietf:params:oauth:grant-type:pre-authorized_code")]
    pub grant_type: String,
    #[serde(rename = "pre-authorized_code")]
    pub pre_authorized_code: Option<String>,
    pub refresh_token: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, Into)]
#[into(OpenID4VCICredentialDefinitionRequestDTO)]
pub struct OpenID4VCICredentialDefinitionRequestRestDTO {
    pub r#type: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, ToSchema, Into)]
#[into(OpenID4VCICredentialRequestDTO)]
pub struct OpenID4VCICredentialRequestRestDTO {
    pub format: String,
    #[into(with_fn = convert_inner)]
    pub credential_definition: Option<OpenID4VCICredentialDefinitionRequestRestDTO>,
    #[into(with_fn = convert_inner)]
    pub doctype: Option<String>,
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
#[from(DidDocument)]
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
#[from(DidVerificationMethod)]
pub struct DidVerificationMethodRestDTO {
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
pub struct TimestampRest(pub i64);

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[from(OpenID4VCITokenResponseDTO)]
pub struct OpenID4VCITokenResponseRestDTO {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: TimestampRest,
    #[from(with_fn = convert_inner)]
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub refresh_token: Option<String>,
    #[from(with_fn = convert_inner)]
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub refresh_token_expires_in: Option<TimestampRest>,
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
    RuntimeError(String),
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, Into)]
#[into(OpenID4VPDirectPostRequestDTO)]
pub struct OpenID4VPDirectPostRequestRestDTO {
    #[into(with_fn = convert_inner)]
    #[serde(flatten)]
    pub presentation_submission: Option<InternalPresentationSubmissionMappingRestDTO>,
    #[schema(example = "<jwt/sdjwt token>")]
    #[into(with_fn = convert_inner)]
    pub vp_token: Option<String>,
    #[schema(example = "<UUID>")]
    #[into(with_fn = convert_inner)]
    pub state: Option<Uuid>,
    #[into(with_fn = convert_inner)]
    pub response: Option<String>,
}

impl From<InternalPresentationSubmissionMappingRestDTO> for PresentationSubmissionMappingDTO {
    fn from(value: InternalPresentationSubmissionMappingRestDTO) -> Self {
        Self {
            id: value.presentation_submission.id,
            definition_id: value.presentation_submission.definition_id,
            descriptor_map: value
                .presentation_submission
                .descriptor_map
                .into_iter()
                .map(|p| p.into())
                .collect(),
        }
    }
}

#[serde_with::serde_as]
#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
pub struct InternalPresentationSubmissionMappingRestDTO {
    #[serde_as(as = "JsonString")]
    pub presentation_submission: PresentationSubmissionMappingRestDTO,
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

// issuer specific
#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(rename_all = "camelCase")]
pub struct PostSsiIssuerConnectQueryParams {
    pub protocol: String,
    pub credential: CredentialId,
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
    pub credential_id: CredentialId,
}

#[derive(Clone, Debug, Deserialize, IntoParams, Serialize)]
#[into_params(parameter_in = Query)]
#[serde(rename_all = "camelCase")]
pub struct PostSsiIssuerSubmitQueryParams {
    pub credential_id: CredentialId,
    pub did_value: DidValue,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    #[from(with_fn = convert_inner)]
    pub credential_definition: Option<OpenID4VCICredentialDefinitionRestDTO>,
    /// Indication of what type of key storage the wallet should use. See the [wallet storage type](/api/resources/credential_schemas#wallet-storage-type) guide.
    #[from(with_fn = convert_inner)]
    pub wallet_storage_type: Option<WalletStorageTypeRestEnum>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub doctype: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[from(with_fn = convert_inner_of_inner)]
    pub claims: Option<HashMap<String, OpenID4VCICredentialOfferClaimDTO>>,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(OpenID4VCICredentialOfferClaim)]
pub struct OpenID4VCICredentialOfferClaimDTO {
    #[schema(no_recursion)]
    pub value: OpenID4VCICredentialOfferClaimValueDTO,
    pub value_type: String,
}

#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(untagged)]
pub enum OpenID4VCICredentialOfferClaimValueDTO {
    Nested(HashMap<String, OpenID4VCICredentialOfferClaimDTO>),
    String(String),
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
    NestedObject(JsonLDNestedEntityRestDTO),
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(JsonLDNestedEntityDTO)]
pub struct JsonLDNestedEntityRestDTO {
    #[serde(rename = "@context")]
    pub context: JsonLDNestedContextRestDTO,
    #[serde(rename = "@id")]
    pub id: String,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(JsonLDNestedContextDTO)]
pub struct JsonLDNestedContextRestDTO {
    #[serde(flatten)]
    #[from(with_fn = convert_inner)]
    pub entities: HashMap<String, JsonLDEntityRestDTO>,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(JsonLDInlineEntityDTO)]
pub struct JsonLDInlineEntityRestDTO {
    #[serde(rename = "@context")]
    pub context: JsonLDContextRestDTO,
    #[serde(rename = "@id")]
    pub id: String,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(OpenID4VPPresentationDefinition)]
pub struct OpenID4VPPresentationDefinitionResponseRestDTO {
    pub id: Uuid,
    #[from(with_fn = convert_inner)]
    pub input_descriptors: Vec<OpenID4VPPresentationDefinitionInputDescriptorRestDTO>,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(OpenID4VPPresentationDefinitionInputDescriptor)]
pub struct OpenID4VPPresentationDefinitionInputDescriptorRestDTO {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    #[from(with_fn = convert_inner)]
    pub format: HashMap<String, OpenID4VPPresentationDefinitionInputDescriptorFormatRestDTO>,
    pub constraints: OpenID4VPPresentationDefinitionConstraintRestDTO,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(OpenID4VPPresentationDefinitionInputDescriptorFormat)]
pub struct OpenID4VPPresentationDefinitionInputDescriptorFormatRestDTO {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub alg: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub proof_type: Vec<String>,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(OpenID4VPPresentationDefinitionConstraint)]
pub struct OpenID4VPPresentationDefinitionConstraintRestDTO {
    #[from(with_fn = convert_inner)]
    pub fields: Vec<OpenID4VPPresentationDefinitionConstraintFieldRestDTO>,
    #[serde(serialize_with = "front_time_option")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub validity_credential_nbf: Option<OffsetDateTime>,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(OpenID4VPPresentationDefinitionConstraintField)]
pub struct OpenID4VPPresentationDefinitionConstraintFieldRestDTO {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[from(with_fn = convert_inner)]
    pub id: Option<Uuid>,
    pub path: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub optional: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[from(with_fn = convert_inner)]
    pub filter: Option<OpenID4VPPresentationDefinitionConstraintFieldFilterRestDTO>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intent_to_retain: Option<bool>,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(OpenID4VPPresentationDefinitionConstraintFieldFilter)]
pub struct OpenID4VPPresentationDefinitionConstraintFieldFilterRestDTO {
    pub r#type: String,
    pub r#const: String,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(OpenID4VPFormat)]
pub struct OpenID4VPFormatRestDTO {
    pub alg: Vec<String>,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(OpenID4VPClientMetadata)]
pub struct OpenID4VPClientMetadataResponseRestDTO {
    #[from(with_fn = convert_inner)]
    pub jwks: Vec<OpenID4VPClientMetadataJwkRestDTO>,
    #[from(with_fn = convert_inner)]
    pub vp_formats: HashMap<String, OpenID4VPFormatRestDTO>,
    pub client_id_scheme: String,
    #[from(with_fn = convert_inner)]
    pub authorization_encrypted_response_alg: Option<OID4VPAuthorizationEncryptedResponseAlgorithm>,
    #[from(with_fn = convert_inner)]
    pub authorization_encrypted_response_enc:
        Option<OID4VPAuthorizationEncryptedResponseContentEncryptionAlgorithm>,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(OpenID4VPClientMetadataJwkDTO)]
pub struct OpenID4VPClientMetadataJwkRestDTO {
    #[serde(rename = "kid")]
    pub key_id: KeyId,
    #[serde(flatten)]
    pub jwk: PublicKeyJwkRestDTO,
}

#[derive(Debug, Clone, Serialize, ToSchema, From)]
#[from(AuthorizationEncryptedResponseAlgorithm)]
pub enum OID4VPAuthorizationEncryptedResponseAlgorithm {
    #[serde(rename = "ECDH-ES")]
    EcdhEs,
}

#[derive(Debug, Clone, Serialize, PartialEq, ToSchema, From)]
#[from(AuthorizationEncryptedResponseContentEncryptionAlgorithm)]
pub enum OID4VPAuthorizationEncryptedResponseContentEncryptionAlgorithm {
    A256GCM,
}

#[derive(Debug, Clone, Serialize, PartialEq, ToSchema, From)]
#[from(GetTrustAnchorResponseDTO)]
#[serde(rename_all = "camelCase")]
pub struct GetTrustAnchorResponseRestDTO {
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

#[derive(Debug, Clone, Serialize, PartialEq, ToSchema, From)]
#[from(GetTrustEntityResponseDTO)]
#[serde(rename_all = "camelCase")]
pub struct GetTrustEntityResponseRestDTO {
    pub id: TrustEntityId,
    pub name: String,
    pub entity_id: String,

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

    #[from(with_fn = convert_inner)]
    pub trust_anchor: Option<GetTrustAnchorDetailResponseRestDTO>,
}
