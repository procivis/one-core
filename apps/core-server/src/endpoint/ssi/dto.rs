use std::collections::HashMap;

use indexmap::IndexMap;
use one_core::common_mapper::{opt_secret_string, secret_string};
use one_core::provider::did_method::dto::{
    DidDocumentDTO, DidServiceEndointDTO, DidVerificationMethodDTO,
};
use one_core::provider::issuance_protocol::openid4vci_draft13::error::OpenID4VCIError;
use one_core::provider::issuance_protocol::openid4vci_draft13::model::{
    ExtendedSubjectClaimsDTO, ExtendedSubjectDTO, OpenID4VCICredentialConfigurationData,
    OpenID4VCICredentialDefinitionRequestDTO, OpenID4VCICredentialOfferDTO,
    OpenID4VCICredentialRequestDTO, OpenID4VCICredentialSubjectItem,
    OpenID4VCICredentialValueDetails, OpenID4VCIDiscoveryResponseDTO, OpenID4VCIGrant,
    OpenID4VCIGrants, OpenID4VCIIssuerMetadataCredentialSchemaResponseDTO,
    OpenID4VCIIssuerMetadataCredentialSupportedDisplayDTO,
    OpenID4VCIIssuerMetadataDisplayResponseDTO, OpenID4VCIIssuerMetadataResponseDTO,
    OpenID4VCIProofRequestDTO, OpenID4VCIProofTypeSupported, OpenID4VCITokenResponseDTO,
};
use one_core::provider::revocation::lvvc::dto::IssuerResponseDTO;
use one_core::provider::verification_protocol::openid4vp_draft20::model::{
    AuthorizationEncryptedResponseAlgorithm,
    AuthorizationEncryptedResponseContentEncryptionAlgorithm, LdpVcAlgs,
    NestedPresentationSubmissionDescriptorDTO, OpenID4VPAlgs, OpenID4VPClientMetadata,
    OpenID4VPClientMetadataJwkDTO, OpenID4VPClientMetadataJwks, OpenID4VPDirectPostRequestDTO,
    OpenID4VPDirectPostResponseDTO, OpenID4VPPresentationDefinition,
    OpenID4VPPresentationDefinitionConstraint, OpenID4VPPresentationDefinitionConstraintField,
    OpenID4VPPresentationDefinitionConstraintFieldFilter,
    OpenID4VPPresentationDefinitionInputDescriptor, OpenID4VPVcSdJwtAlgs,
    OpenID4VpPresentationFormat, PresentationSubmissionDescriptorDTO,
    PresentationSubmissionMappingDTO,
};
use one_core::service::error::ServiceError;
use one_core::service::key::dto::{
    PublicKeyJwkDTO, PublicKeyJwkEllipticDataDTO, PublicKeyJwkMlweDataDTO, PublicKeyJwkOctDataDTO,
    PublicKeyJwkRsaDataDTO,
};
use one_core::service::oid4vci_draft13::dto::OpenID4VCICredentialResponseDTO;
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
    convert_inner, convert_inner_of_inner, try_convert_inner, try_convert_inner_of_inner, From,
    Into, TryInto,
};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_with::json::JsonString;
use serde_with::{serde_as, skip_serializing_none, OneOrMany};
use shared_types::{CredentialId, DidValue, ProofId, TrustAnchorId, TrustEntityId};
use strum::Display;
use time::OffsetDateTime;
use url::Url;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::endpoint::credential_schema::dto::{
    CredentialSchemaLayoutPropertiesRestDTO, CredentialSchemaType, WalletStorageTypeRestEnum,
};
use crate::endpoint::trust_entity::dto::{TrustEntityRoleRest, TrustEntityStateRest};
use crate::serialize::{front_time, front_time_option};

// verifier specific
#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(rename_all = "camelCase")]
pub struct PostSsiVerifierConnectQueryParams {
    pub protocol: String,
    pub proof: ProofId,
    pub redirect_uri: Option<String>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
pub struct OpenID4VCIIssuerMetadataResponseRestDTO {
    pub credential_issuer: String,
    pub credential_endpoint: String,
    pub credential_configurations_supported:
        IndexMap<String, OpenID4VCIIssuerMetadataCredentialSupportedResponseRestDTO>,
    pub display: Option<Vec<OpenID4VCIIssuerMetadataDisplayResponseRestDTO>>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[from(OpenID4VCIIssuerMetadataDisplayResponseDTO)]
pub struct OpenID4VCIIssuerMetadataDisplayResponseRestDTO {
    pub name: String,
    pub locale: String,
}

// TODO! Support in mapper somehow?
impl From<OpenID4VCIIssuerMetadataResponseDTO> for OpenID4VCIIssuerMetadataResponseRestDTO {
    fn from(value: OpenID4VCIIssuerMetadataResponseDTO) -> Self {
        Self {
            credential_issuer: value.credential_issuer,
            credential_endpoint: value.credential_endpoint,
            credential_configurations_supported: value
                .credential_configurations_supported
                .into_iter()
                .map(|(key, value)| (key, value.into()))
                .collect(),
            display: convert_inner_of_inner(value.display),
        }
    }
}

#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[from(OpenID4VCICredentialConfigurationData)]
pub struct OpenID4VCIIssuerMetadataCredentialSupportedResponseRestDTO {
    pub format: String,
    #[schema(value_type = Object,
        example = "{
            credential_schema_id: {
                claims: {
                    claim1: {
                        mandatory: true
                    }
                },
                display: [
                {
                    name: \"Schema name\"
                }
                ],
                doctype: \"eu.europa.ec.eudi.hiid.1\",
                format: \"mso_mdoc\",
            }
        }",
    )]
    pub claims: Option<IndexMap<String, OpenID4VCICredentialSubjectItem>>,
    #[from(with_fn = convert_inner_of_inner)]
    pub order: Option<Vec<String>>,
    #[from(with_fn = convert_inner)]
    pub credential_definition: Option<OpenID4VCICredentialDefinitionRequestRestDTO>,
    pub doctype: Option<String>,
    #[from(with_fn = convert_inner_of_inner)]
    pub display: Option<Vec<OpenID4VCIIssuerMetadataCredentialSupportedDisplayRestDTO>>,
    #[from(with_fn = convert_inner)]
    pub wallet_storage_type: Option<WalletStorageTypeRestEnum>,
    #[from(with_fn = convert_inner)]
    pub vct: Option<String>,
    pub cryptographic_binding_methods_supported: Option<Vec<String>>,
    pub credential_signing_alg_values_supported: Option<Vec<String>>,
    #[schema(value_type = Object)]
    pub proof_types_supported: Option<IndexMap<String, OpenID4VCIProofTypeSupported>>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[from(OpenID4VCIIssuerMetadataCredentialSupportedDisplayDTO)]
pub struct OpenID4VCIIssuerMetadataCredentialSupportedDisplayRestDTO {
    pub name: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[from(OpenID4VCIIssuerMetadataCredentialSchemaResponseDTO)]
pub struct OpenID4VCIIssuerMetadataCredentialSchemaRestDTO {
    pub id: String,
    pub r#type: CredentialSchemaType,
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

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, Into, From)]
#[into(OpenID4VCICredentialDefinitionRequestDTO)]
#[from(OpenID4VCICredentialDefinitionRequestDTO)]
#[serde(rename_all = "camelCase")]
pub struct OpenID4VCICredentialDefinitionRequestRestDTO {
    pub r#type: Vec<String>,

    #[serde(rename = "credentialSubject")]
    #[schema(value_type = Object,
        example = "{
            claim1: {
                mandatory: true
            },
            claim2: {
                mandatory: true
            }
        }",
    )]
    pub credential_subject: Option<OpenID4VCICredentialSubjectItem>,
}

#[derive(Clone, Debug, Deserialize, ToSchema, Into)]
#[into(OpenID4VCICredentialRequestDTO)]
pub struct OpenID4VCICredentialRequestRestDTO {
    pub format: String,
    #[into(with_fn = convert_inner)]
    pub credential_definition: Option<OpenID4VCICredentialDefinitionRequestRestDTO>,
    #[into(with_fn = convert_inner)]
    pub doctype: Option<String>,
    pub vct: Option<String>,
    pub proof: OpenID4VCIProofRequestRestDTO,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, Into)]
#[into(OpenID4VCIProofRequestDTO)]
pub struct OpenID4VCIProofRequestRestDTO {
    pub proof_type: String,
    pub jwt: String,
}

#[skip_serializing_none]
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
    pub also_known_as: Option<Vec<String>>,
    #[from(with_fn = convert_inner_of_inner)]
    pub service: Option<Vec<DidServiceEndointRestDTO>>,
}

#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(DidServiceEndointDTO)]
pub struct DidServiceEndointRestDTO {
    pub id: String,
    #[serde_as(as = "OneOrMany<_>")]
    pub r#type: Vec<String>,
    pub service_endpoint: serde_json::Value,
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

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema, From)]
#[from(PublicKeyJwkMlweDataDTO)]
pub struct PublicKeyJwkMlweDataRestDTO {
    pub r#use: Option<String>,
    pub alg: String,
    pub x: String,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema, From)]
#[from(PublicKeyJwkOctDataDTO)]
pub struct PublicKeyJwkOctDataRestDTO {
    pub r#use: Option<String>,
    pub k: String,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema, From)]
#[from(PublicKeyJwkRsaDataDTO)]
pub struct PublicKeyJwkRsaDataRestDTO {
    pub r#use: Option<String>,
    pub e: String,
    pub n: String,
}

#[skip_serializing_none]
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

#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[from(OpenID4VCITokenResponseDTO)]
pub struct OpenID4VCITokenResponseRestDTO {
    #[serde(with = "secret_string")]
    #[schema(value_type = String, example = "secret")]
    pub access_token: SecretString,
    pub token_type: String,
    pub expires_in: TimestampRest,
    #[from(with_fn = convert_inner)]
    #[serde(with = "opt_secret_string")]
    #[schema(value_type = String, example = "secret", nullable = false)]
    pub refresh_token: Option<SecretString>,
    #[from(with_fn = convert_inner)]
    pub refresh_token_expires_in: Option<TimestampRest>,
    pub c_nonce: Option<String>,
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
    CredentialRequestDenied,
    RuntimeError(String),
}

#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, Into)]
#[into(OpenID4VPDirectPostRequestDTO)]
pub struct OpenID4VPDirectPostRequestRestDTO {
    #[into(with_fn = convert_inner)]
    #[serde(flatten)]
    pub presentation_submission: Option<InternalPresentationSubmissionMappingRestDTO>,
    #[schema(example = "<jwt/sd_jwt token>")]
    #[into(with_fn = convert_inner)]
    pub vp_token: Option<String>,
    #[schema(example = "3fa85f64-5717-4562-b3fc-2c963f66afa6")]
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

#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, Into)]
#[into(PresentationSubmissionDescriptorDTO)]
pub struct PresentationSubmissionDescriptorRestDTO {
    pub id: String,
    #[schema(example = "SD_JWT")]
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

#[skip_serializing_none]
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

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(IssuerResponseDTO)]
pub struct LVVCIssuerResponseRestDTO {
    pub credential: String,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(OpenID4VCICredentialResponseDTO)]
pub struct OpenID4VCICredentialResponseRestDTO {
    pub credential: String,
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

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(OpenID4VCICredentialOfferDTO)]
pub struct OpenID4VCICredentialOfferRestDTO {
    pub credential_issuer: String,
    pub credential_configuration_ids: Vec<String>,
    pub grants: OpenID4VCIGrantsRestDTO,

    #[from(with_fn = convert_inner)]
    pub credential_subject: Option<ExtendedSubjectRestDTO>,
    #[from(with_fn = convert_inner)]
    pub issuer_did: Option<DidValue>,
}

#[skip_serializing_none]
#[derive(Clone, Serialize, Deserialize, Debug, From, ToSchema)]
#[from(ExtendedSubjectDTO)]
pub struct ExtendedSubjectRestDTO {
    #[from(with_fn = convert_inner)]
    pub keys: Option<ExtendedSubjectClaimsRestDTO>,
    #[from(with_fn = convert_inner)]
    pub wallet_storage_type: Option<WalletStorageTypeRestEnum>,
}

#[derive(Clone, Serialize, Deserialize, Debug, ToSchema)]
pub struct ExtendedSubjectClaimsRestDTO {
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
pub struct ProcivisSubjectClaimValueRestDTO {
    pub value: String,
    pub value_type: String,
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

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct OpenID4VCICredentialDefinitionRestDTO {
    pub r#type: Vec<String>,
    #[schema(value_type = Object,
        example = "{
            credential_schema_id: {
                claims: {
                    claim1: {
                        mandatory: true
                    }
                },
                display: [
                {
                    name: \"Schema name\"
                }
                ],
                doctype: \"eu.europa.ec.eudi.hiid.1\",
                format: \"mso_mdoc\",
            }
        }",
    )]
    pub credential_subject: Option<OpenID4VCICredentialSubjectItem>,
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
pub enum JsonLDEntityRestDTO {
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
pub struct JsonLDInlineEntityRestDTO {
    #[serde(rename = "@context")]
    #[from(with_fn = convert_inner)]
    pub context: Option<JsonLDContextRestDTO>,
    #[serde(rename = "@id")]
    pub id: String,
    #[serde(rename = "@type")]
    #[from(with_fn = convert_inner)]
    pub r#type: Option<String>,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(OpenID4VPPresentationDefinition)]
pub struct OpenID4VPPresentationDefinitionResponseRestDTO {
    pub id: String,
    #[from(with_fn = convert_inner)]
    pub input_descriptors: Vec<OpenID4VPPresentationDefinitionInputDescriptorRestDTO>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(OpenID4VPPresentationDefinitionInputDescriptor)]
pub struct OpenID4VPPresentationDefinitionInputDescriptorRestDTO {
    pub id: String,
    pub name: Option<String>,
    pub purpose: Option<String>,
    #[from(with_fn = convert_inner)]
    pub format: HashMap<String, OpenID4VPFormatRestDTO>,
    pub constraints: OpenID4VPPresentationDefinitionConstraintRestDTO,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(OpenID4VPPresentationDefinitionConstraint)]
pub struct OpenID4VPPresentationDefinitionConstraintRestDTO {
    #[from(with_fn = convert_inner)]
    pub fields: Vec<OpenID4VPPresentationDefinitionConstraintFieldRestDTO>,
    #[serde(serialize_with = "front_time_option")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub validity_credential_nbf: Option<OffsetDateTime>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(OpenID4VPPresentationDefinitionConstraintField)]
pub struct OpenID4VPPresentationDefinitionConstraintFieldRestDTO {
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
pub struct OpenID4VPPresentationDefinitionConstraintFieldFilterRestDTO {
    pub r#type: String,
    pub r#const: String,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(OpenID4VpPresentationFormat)]
#[serde(untagged)]
pub enum OpenID4VPFormatRestDTO {
    SdJwtVcAlgs(OpenID4VPVcSdJwtAlgsRestDTO),
    LdpVcAlgs(LdpVcAlgsRestDTO),
    GenericAlgList(OpenID4VPAlgsRestDTO),
    Other(serde_json::Value),
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(LdpVcAlgs)]
pub struct LdpVcAlgsRestDTO {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub proof_type: Vec<String>,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(OpenID4VPAlgs)]
pub struct OpenID4VPAlgsRestDTO {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub alg: Vec<String>,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(OpenID4VPVcSdJwtAlgs)]
pub struct OpenID4VPVcSdJwtAlgsRestDTO {
    #[serde(skip_serializing_if = "Vec::is_empty", rename = "sd-jwt_alg_values")]
    pub sd_jwt_algorithms: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", rename = "kb-jwt_alg_values")]
    pub kb_jwt_algorithms: Vec<String>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(OpenID4VPClientMetadata)]
pub struct OpenID4VPClientMetadataResponseRestDTO {
    pub jwks: OpenID4VPClientMetadataJwksRestDTO,
    pub jwks_uri: Option<String>,
    pub id_token_ecrypted_response_enc: Option<String>,
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
pub struct OpenID4VPClientMetadataJwksRestDTO {
    #[from(with_fn = convert_inner)]
    pub keys: Vec<OpenID4VPClientMetadataJwkRestDTO>,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(OpenID4VPClientMetadataJwkDTO)]
pub struct OpenID4VPClientMetadataJwkRestDTO {
    #[serde(rename = "kid")]
    pub key_id: String,
    #[serde(flatten)]
    pub jwk: PublicKeyJwkRestDTO,
}

#[derive(Debug, Clone, Serialize, ToSchema, From)]
#[from(AuthorizationEncryptedResponseAlgorithm)]
pub enum OID4VPAuthorizationEncryptedResponseAlgorithm {
    #[serde(rename = "ECDH-ES")]
    EcdhEs,
}

#[derive(Debug, Clone, Serialize, PartialEq, ToSchema, Display, From)]
#[from(AuthorizationEncryptedResponseContentEncryptionAlgorithm)]
pub enum OID4VPAuthorizationEncryptedResponseContentEncryptionAlgorithm {
    A256GCM,
    #[serde(rename = "A128CBC-HS256")]
    #[strum(serialize = "A128CBC-HS256")]
    A128CBCHS256,
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

#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, PartialEq, ToSchema, From)]
#[from(GetTrustAnchorEntityListResponseDTO)]
#[serde(rename_all = "camelCase")]
pub struct GetTrustEntityResponseRestDTO {
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
pub struct SdJwtVcTypeMetadataResponseRestDTO {
    pub vct: String,
    pub name: Option<String>,
    #[serde(default)]
    #[from(with_fn = convert_inner)]
    pub display: Vec<SdJwtVcDisplayMetadataRestDTO>,
    #[serde(default)]
    #[from(with_fn = convert_inner)]
    pub claims: Vec<SdJwtVcClaimRestDTO>,
    #[from(with_fn = convert_inner)]
    pub layout_properties: Option<CredentialSchemaLayoutPropertiesRestDTO>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(SdJwtVcDisplayMetadataDTO)]
pub struct SdJwtVcDisplayMetadataRestDTO {
    pub lang: String,
    pub name: String,
    #[from(with_fn = convert_inner)]
    pub rendering: Option<SdJwtVcRenderingRestDTO>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(SdJwtVcRenderingDTO)]
pub struct SdJwtVcRenderingRestDTO {
    #[from(with_fn = convert_inner)]
    pub simple: Option<SdJwtVcSimpleRenderingRestDTO>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(SdJwtVcSimpleRenderingDTO)]
#[serde(rename_all = "camelCase")]
pub struct SdJwtVcSimpleRenderingRestDTO {
    #[from(with_fn = convert_inner)]
    pub logo: Option<SdJwtVcSimpleRenderingLogoRestDTO>,
    pub background_color: Option<String>,
    pub text_color: Option<String>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(SdJwtVcSimpleRenderingLogoDTO)]
#[serde(rename_all = "camelCase")]
pub struct SdJwtVcSimpleRenderingLogoRestDTO {
    pub uri: Url,
    pub alt_text: Option<String>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(SdJwtVcClaimDTO)]
pub struct SdJwtVcClaimRestDTO {
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
pub enum SdJwtVcClaimSdRestEnum {
    Always,
    Allowed,
    Never,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(SdJwtVcClaimDisplayDTO)]
pub struct SdJwtVcClaimDisplayRestDTO {
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
pub struct SSIPostTrustEntityRequestRestDTO {
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
