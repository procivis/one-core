use std::collections::HashMap;
use std::fmt;

use anyhow::Context;
use indexmap::IndexMap;
use one_dto_mapper::{convert_inner, Into};
use secrecy::{SecretSlice, SecretString};
use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_with::skip_serializing_none;
use shared_types::{
    ClaimSchemaId, CredentialId, CredentialSchemaId, DidId, DidValue, KeyId, OrganisationId,
};
use strum::Display;
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

use super::error::OpenID4VCIError;
use super::mapper::deserialize_with_serde_json;
use crate::common_mapper::opt_secret_string;
use crate::model::claim::Claim;
use crate::model::credential::{Credential, UpdateCredentialRequest};
use crate::model::credential_schema::{
    CredentialFormat, CredentialSchema, LayoutProperties, LayoutType, RevocationMethod,
    UpdateCredentialSchemaRequest, WalletStorageTypeEnum,
};
use crate::model::did::{Did, DidType};
use crate::model::interaction::InteractionId;
use crate::model::proof::{Proof, UpdateProofRequest};
use crate::model::proof_schema::ProofInputClaimSchema;
use crate::provider::credential_formatter::mdoc_formatter::mdoc::MobileSecurityObject;
use crate::provider::credential_formatter::model::DetailCredential;
use crate::provider::credential_formatter::vcdm::ContextType;
use crate::provider::exchange_protocol::dto::PresentationDefinitionRequestedCredentialResponseDTO;
use crate::service::credential_schema::dto::CredentialClaimSchemaDTO;
use crate::service::key::dto::PublicKeyJwkDTO;
use crate::util::params::deserialize_encryption_key;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BleOpenId4VpResponse {
    pub vp_token: String,
    pub presentation_submission: PresentationSubmissionMappingDTO,
}

#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HolderInteractionData {
    pub issuer_url: String,
    pub credential_endpoint: String,
    #[serde(default)]
    pub token_endpoint: Option<String>,
    #[serde(default)]
    pub grants: Option<OpenID4VCIGrants>,
    #[serde(default)]
    pub access_token: Option<Vec<u8>>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub access_token_expires_at: Option<OffsetDateTime>,
    #[serde(default)]
    pub refresh_token: Option<Vec<u8>>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub refresh_token_expires_at: Option<OffsetDateTime>,
    #[serde(default)]
    pub cryptographic_binding_methods_supported: Option<Vec<String>>,
    #[serde(default)]
    pub credential_signing_alg_values_supported: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JwePayload {
    pub aud: Url,
    #[serde(with = "unix_timestamp")]
    pub exp: OffsetDateTime,
    pub vp_token: String,
    pub presentation_submission: PresentationSubmissionMappingDTO,
    pub state: Option<String>,
}

impl JwePayload {
    pub(crate) fn try_from_json_base64_decode(payload: &[u8]) -> anyhow::Result<Self> {
        let payload =
            serde_json::from_slice(payload).context("MdocJwePayload deserialization failed")?;

        Ok(payload)
    }

    pub(crate) fn try_into_json_base64_encode(&self) -> anyhow::Result<Vec<u8>> {
        let payload = serde_json::to_vec(self).context("MdocJwePayload serialization failed")?;

        Ok(payload)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpenID4VCIIssuerMetadataCredentialSupportedDisplayDTO {
    pub name: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct OpenID4VCIIssuerMetadataResponseDTO {
    pub credential_issuer: String,
    pub credential_endpoint: String,
    pub credential_configurations_supported:
        IndexMap<String, OpenID4VCICredentialConfigurationData>,
}

#[derive(Clone, Debug, Deserialize, Default)]
pub struct OpenID4VCICredentialConfigurationData {
    pub format: String,
    #[serde(rename = "@context")]
    pub context: Option<Vec<ContextType>>,
    pub order: Option<Vec<String>>,
    pub credential_definition: Option<OpenID4VCICredentialDefinitionRequestDTO>,
    pub claims: Option<IndexMap<String, OpenID4VCICredentialSubjectItem>>,
    pub doctype: Option<String>,
    pub display: Option<Vec<OpenID4VCIIssuerMetadataCredentialSupportedDisplayDTO>>,
    pub wallet_storage_type: Option<WalletStorageTypeEnum>,
    pub vct: Option<String>,
    pub cryptographic_binding_methods_supported: Option<Vec<String>>,
    pub credential_signing_alg_values_supported: Option<Vec<String>>,
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct OpenID4VCIIssuerMetadataMdocClaimsValuesDTO {
    #[serde(default)]
    pub value: HashMap<String, OpenID4VCIIssuerMetadataMdocClaimsValuesDTO>,
    pub value_type: String,
    pub mandatory: Option<bool>,
    pub order: Option<Vec<String>>,
    pub array: Option<bool>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenID4VCIIssuerMetadataCredentialDefinitionResponseDTO {
    pub r#type: Vec<String>,
    pub credential_schema: Option<OpenID4VCIIssuerMetadataCredentialSchemaResponseDTO>,
    pub vct: Option<String>,
    pub cryptographic_binding_methods_supported: Option<Vec<String>>,
    pub credential_signing_alg_values_supported: Option<Vec<String>>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct OpenID4VCIIssuerMetadataCredentialSchemaResponseDTO {
    pub id: String,
    pub r#type: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(transparent)]
pub struct Timestamp(pub i64);

#[derive(Debug, Deserialize)]
pub struct OpenID4VCITokenResponseDTO {
    pub access_token: SecretString,
    pub token_type: String,
    pub expires_in: Timestamp,
    #[serde(default, with = "opt_secret_string")]
    pub refresh_token: Option<SecretString>,
    #[serde(default)]
    pub refresh_token_expires_in: Option<Timestamp>,
    pub c_nonce: Option<String>,
}

#[derive(Clone, Debug)]
pub struct OpenID4VCIErrorResponseDTO {
    pub error: OpenID4VCIError,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "grant_type")]
pub enum OpenID4VCITokenRequestDTO {
    #[serde(rename = "urn:ietf:params:oauth:grant-type:pre-authorized_code")]
    PreAuthorizedCode {
        #[serde(rename = "pre-authorized_code")]
        pre_authorized_code: String,
        tx_code: Option<String>,
    },
    #[serde(rename = "refresh_token")]
    RefreshToken { refresh_token: String },
}

impl OpenID4VCITokenRequestDTO {
    pub fn is_pre_authorized_code(&self) -> bool {
        matches!(self, Self::PreAuthorizedCode { .. })
    }

    pub fn is_refresh_token(&self) -> bool {
        matches!(self, Self::RefreshToken { .. })
    }
}

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpenID4VCIIssuerInteractionDataDTO {
    pub pre_authorized_code_used: bool,
    pub access_token_hash: Vec<u8>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub access_token_expires_at: Option<OffsetDateTime>,
    #[serde(default)]
    pub refresh_token_hash: Option<Vec<u8>>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub refresh_token_expires_at: Option<OffsetDateTime>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpenID4VCICredentialDefinitionRequestDTO {
    pub r#type: Vec<String>,
    #[serde(rename = "credentialSubject")]
    pub credential_subject: Option<OpenID4VCICredentialSubjectItem>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize)]
pub struct OpenID4VCICredentialRequestDTO {
    pub format: String,
    pub credential_definition: Option<OpenID4VCICredentialDefinitionRequestDTO>,
    pub doctype: Option<String>,
    pub proof: OpenID4VCIProofRequestDTO,
}

#[derive(Clone, Debug, Serialize)]
pub struct OpenID4VCIProofRequestDTO {
    pub proof_type: String,
    pub jwt: String,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OpenID4VPDirectPostRequestDTO {
    pub presentation_submission: Option<PresentationSubmissionMappingDTO>,
    pub vp_token: Option<String>,
    pub state: Option<Uuid>,
    pub response: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PresentationSubmissionMappingDTO {
    pub id: String,
    pub definition_id: String,
    pub descriptor_map: Vec<PresentationSubmissionDescriptorDTO>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PresentationSubmissionDescriptorDTO {
    pub id: String,
    pub format: String,
    pub path: String,
    pub path_nested: Option<NestedPresentationSubmissionDescriptorDTO>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NestedPresentationSubmissionDescriptorDTO {
    pub format: String,
    pub path: String,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OpenID4VPDirectPostResponseDTO {
    pub redirect_uri: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum PresentationToken {
    One(String),
    Multiple(Vec<String>),
}

// https://datatracker.ietf.org/doc/html/rfc7518#section-4.1
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Display)]
pub enum AuthorizationEncryptedResponseAlgorithm {
    // Elliptic Curve Diffie-Hellman Ephemeral Static key agreement using Concat KDF
    #[serde(rename = "ECDH-ES")]
    #[strum(serialize = "ECDH-ES")]
    EcdhEs,
}

// https://datatracker.ietf.org/doc/html/rfc7518#section-5.1
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Display)]
pub enum AuthorizationEncryptedResponseContentEncryptionAlgorithm {
    // AES GCM using 256-bit key
    A256GCM,
    #[serde(rename = "A128CBC-HS256")]
    #[strum(serialize = "A128CBC-HS256")]
    A128CBCHS256,
}

#[skip_serializing_none]
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Default)]
pub struct OpenID4VPClientMetadata {
    #[serde(default)]
    pub jwks: OpenID4VPClientMetadataJwks,
    #[serde(default)]
    pub jwks_uri: Option<String>,
    #[serde(default)]
    pub vp_formats: HashMap<String, OpenID4VpPresentationFormat>,
    #[serde(default)]
    pub authorization_encrypted_response_alg: Option<AuthorizationEncryptedResponseAlgorithm>,
    #[serde(default)]
    pub authorization_encrypted_response_enc:
        Option<AuthorizationEncryptedResponseContentEncryptionAlgorithm>,
    #[serde(default)]
    pub id_token_ecrypted_response_enc: Option<String>,
    #[serde(default)]
    pub id_token_encrypted_response_alg: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub subject_syntax_types_supported: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize, Debug, Default, PartialEq)]
pub struct OpenID4VPClientMetadataJwks {
    pub keys: Vec<OpenID4VPClientMetadataJwkDTO>,
}

#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct OpenID4VPAuthorizationRequestQueryParams {
    pub client_id: String,
    pub client_id_scheme: Option<ClientIdScheme>,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub response_type: Option<String>,
    pub response_mode: Option<String>,
    pub response_uri: Option<String>,
    pub client_metadata: Option<String>,
    pub client_metadata_uri: Option<String>,
    pub presentation_definition: Option<String>,
    pub presentation_definition_uri: Option<String>,

    // https://www.rfc-editor.org/rfc/rfc9101.html#name-authorization-request
    pub request: Option<String>,
    pub request_uri: Option<String>,

    pub redirect_uri: Option<String>,
}

#[skip_serializing_none]
#[derive(Clone, Deserialize, Serialize, Debug, Default)]
pub(crate) struct OpenID4VPAuthorizationRequestParams {
    pub client_id: String,
    #[serde(default)]
    pub client_id_scheme: Option<ClientIdScheme>,

    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub nonce: Option<String>,

    #[serde(default)]
    pub response_type: Option<String>,
    #[serde(default)]
    pub response_mode: Option<String>,
    #[serde(default)]
    pub response_uri: Option<Url>,

    #[serde(default, deserialize_with = "deserialize_with_serde_json")]
    pub client_metadata: Option<OpenID4VPClientMetadata>,
    #[serde(default)]
    pub client_metadata_uri: Option<Url>,

    #[serde(default, deserialize_with = "deserialize_with_serde_json")]
    pub presentation_definition: Option<OpenID4VPPresentationDefinition>,
    #[serde(default)]
    pub presentation_definition_uri: Option<Url>,

    #[serde(default)]
    pub redirect_uri: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OpenID4VCIDiscoveryResponseDTO {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    pub response_types_supported: Vec<String>,
    pub grant_types_supported: Vec<String>,
    pub subject_types_supported: Vec<String>,
    pub id_token_signing_alg_values_supported: Vec<String>,
}

#[derive(Clone, Debug)]
pub(super) struct ValidatedProofClaimDTO {
    pub proof_input_claim: ProofInputClaimSchema,
    pub credential: DetailCredential,
    pub credential_schema: CredentialSchema,
    pub value: serde_json::Value,
    pub mdoc_mso: Option<MobileSecurityObject>,
}

#[skip_serializing_none]
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct OpenID4VCICredential {
    pub format: String,
    #[serde(default)]
    pub credential_definition: Option<OpenID4VCICredentialDefinitionRequestDTO>,
    #[serde(default)]
    pub vct: Option<String>,
    #[serde(default)]
    pub doctype: Option<String>,
    pub proof: OpenID4VCIProof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpenID4VCIProof {
    pub proof_type: String,
    pub jwt: String,
}

/// Interaction data used for OpenID4VP on verifier side
/// - HTTP transport generates this
///
/// Important: This structure is used to deserialize
/// also from all the other verifier interaction data structures
/// during proof submission validation
#[skip_serializing_none]
#[derive(Clone, Deserialize, Serialize, Debug)]
pub struct OpenID4VPVerifierInteractionContent {
    pub nonce: String,
    #[serde(deserialize_with = "deserialize_with_serde_json")]
    pub presentation_definition: OpenID4VPPresentationDefinition,
    pub client_id: String,
    pub client_id_scheme: Option<ClientIdScheme>,
    pub response_uri: Option<String>,
}

#[derive(Clone, Deserialize, Serialize, Debug)]
pub struct OpenID4VPPresentationDefinition {
    pub id: String,
    pub input_descriptors: Vec<OpenID4VPPresentationDefinitionInputDescriptor>,
}

#[skip_serializing_none]
#[derive(Clone, Deserialize, Serialize, Debug)]
pub struct OpenID4VPPresentationDefinitionInputDescriptor {
    pub id: String,
    pub name: Option<String>,
    pub purpose: Option<String>,
    pub format: HashMap<String, OpenID4VPPresentationDefinitionInputDescriptorFormat>,
    pub constraints: OpenID4VPPresentationDefinitionConstraint,
}

#[derive(Clone, Deserialize, Serialize, Debug)]
pub struct OpenID4VPPresentationDefinitionInputDescriptorFormat {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alg: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proof_type: Vec<String>,
}

#[skip_serializing_none]
#[derive(Clone, Deserialize, Serialize, Debug)]
pub struct OpenID4VPPresentationDefinitionConstraint {
    pub fields: Vec<OpenID4VPPresentationDefinitionConstraintField>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub validity_credential_nbf: Option<OffsetDateTime>,
    #[serde(default)]
    pub limit_disclosure: Option<OpenID4VPPresentationDefinitionLimitDisclosurePreference>,
}

#[derive(Clone, Deserialize, Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub enum OpenID4VPPresentationDefinitionLimitDisclosurePreference {
    Required,
    Preferred,
}

#[skip_serializing_none]
#[derive(Clone, Deserialize, Serialize, Debug)]
pub struct OpenID4VPPresentationDefinitionConstraintField {
    pub id: Option<ClaimSchemaId>,
    pub name: Option<String>,
    pub purpose: Option<String>,
    pub path: Vec<String>,
    pub optional: Option<bool>,
    pub filter: Option<OpenID4VPPresentationDefinitionConstraintFieldFilter>,
    #[serde(default)]
    pub intent_to_retain: Option<bool>,
}

#[derive(Clone, Deserialize, Serialize, Debug)]
pub struct OpenID4VPPresentationDefinitionConstraintFieldFilter {
    pub r#type: String,
    pub r#const: String,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct OpenID4VPClientMetadataJwkDTO {
    #[serde(rename = "kid")]
    pub key_id: String,
    #[serde(flatten)]
    pub jwk: PublicKeyJwkDTO,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
#[serde(untagged)]
pub enum OpenID4VpPresentationFormat {
    GenericAlgList(OpenID4VPAlgs),
    SdJwtVcAlgs(OpenID4VPVcSdJwtAlgs),
    Other(serde_json::Value),
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct OpenID4VPVcSdJwtAlgs {
    #[serde(rename = "sd-jwt_alg_values")]
    pub sd_jwt_algorithms: Vec<String>,
    #[serde(rename = "kb-jwt_alg_values")]
    pub kb_jwt_algorithms: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct OpenID4VPAlgs {
    pub alg: Vec<String>,
}

#[derive(Debug)]
pub struct RequestData {
    pub presentation_submission: PresentationSubmissionMappingDTO,
    pub vp_token: String,
    pub state: Uuid,
    pub mdoc_generated_nonce: Option<String>,
    pub encryption_key: Option<KeyId>,
}

#[derive(Clone, Debug)]
pub struct ProvedCredential {
    pub credential: Credential,
    pub issuer_did_value: DidValue,
    pub holder_did_value: DidValue,
    pub mdoc_mso: Option<MobileSecurityObject>,
}

#[derive(Debug)]
pub struct AcceptProofResult {
    pub proved_credentials: Vec<ProvedCredential>,
    pub proved_claims: Vec<Claim>,
}

#[derive(Clone, Debug)]
pub enum InvitationResponseDTO {
    Credential {
        interaction_id: InteractionId,
        credentials: Vec<Credential>,
        tx_code: Option<OpenID4VCITxCode>,
    },
    ProofRequest {
        interaction_id: InteractionId,
        proof: Box<Proof>,
    },
}

#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Into)]
#[into(LayoutProperties)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSchemaLayoutPropertiesRequestDTO {
    #[into(with_fn = convert_inner)]
    pub background: Option<CredentialSchemaBackgroundPropertiesRequestDTO>,
    #[into(with_fn = convert_inner)]
    pub logo: Option<CredentialSchemaLogoPropertiesRequestDTO>,
    pub primary_attribute: Option<String>,
    pub secondary_attribute: Option<String>,
    pub picture_attribute: Option<String>,
    #[into(with_fn = convert_inner)]
    pub code: Option<CredentialSchemaCodePropertiesRequestDTO>,
}

#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSchemaLogoPropertiesRequestDTO {
    pub font_color: Option<String>,
    pub background_color: Option<String>,
    pub image: Option<String>,
}

#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSchemaBackgroundPropertiesRequestDTO {
    pub color: Option<String>,
    pub image: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSchemaCodePropertiesRequestDTO {
    pub attribute: String,
    pub r#type: CredentialSchemaCodeTypeEnum,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CredentialSchemaCodeTypeEnum {
    Barcode,
    Mrz,
    QrCode,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DidListItemResponseDTO {
    pub id: DidId,
    #[serde(with = "time::serde::rfc3339")]
    pub created_date: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub did: DidValue,
    #[serde(rename = "type")]
    pub did_type: DidType,
    #[serde(rename = "method")]
    pub did_method: String,
    pub deactivated: bool,
}

#[derive(Clone, Debug)]
pub struct PresentedCredential {
    pub presentation: String,
    pub credential_schema: CredentialSchema,
    pub request: PresentationDefinitionRequestedCredentialResponseDTO,
}

#[derive(Clone, Debug)]
pub struct ShareResponse<T> {
    pub url: String,
    pub interaction_id: Uuid,
    pub context: T,
}

#[derive(Clone, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SubmitIssuerResponse {
    pub credential: String,
    pub redirect_uri: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct UpdateResponse<T> {
    pub result: T,
    pub update_proof: Option<UpdateProofRequest>,
    pub create_did: Option<Did>,
    pub update_credential: Option<(CredentialId, UpdateCredentialRequest)>,
    pub update_credential_schema: Option<UpdateCredentialSchemaRequest>,
}

#[skip_serializing_none]
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct OpenID4VCICredentialOfferDTO {
    pub credential_issuer: String,
    pub credential_configuration_ids: Vec<String>,
    pub grants: OpenID4VCIGrants,

    // This is a custom field with credential values
    pub credential_subject: Option<ExtendedSubjectDTO>,
    // This is a custom field with the issuer did
    pub issuer_did: Option<DidValue>,
}

#[skip_serializing_none]
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ExtendedSubjectDTO {
    pub keys: Option<ExtendedSubjectClaimsDTO>,
    pub wallet_storage_type: Option<WalletStorageTypeEnum>,
}

#[derive(Clone, Serialize, Deserialize, Debug, Default)]
pub struct ExtendedSubjectClaimsDTO {
    #[serde(flatten)]
    pub claims: IndexMap<String, OpenID4VCICredentialValueDetails>,
}

#[skip_serializing_none]
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct OpenID4VCICredentialOfferCredentialDTO {
    pub format: String,
    #[serde(default)]
    pub credential_definition: Option<OpenID4VCICredentialDefinitionRequestDTO>,
    pub wallet_storage_type: Option<WalletStorageTypeEnum>,
    #[serde(default)]
    pub doctype: Option<String>,
    #[serde(default)]
    pub claims: Option<IndexMap<String, OpenID4VCICredentialSubjectItem>>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct OpenID4VCIGrants {
    #[serde(rename = "urn:ietf:params:oauth:grant-type:pre-authorized_code")]
    pub code: OpenID4VCIGrant,
}

#[skip_serializing_none]
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct OpenID4VCIGrant {
    #[serde(rename = "pre-authorized_code")]
    pub pre_authorized_code: String,
    #[serde(default)]
    pub tx_code: Option<OpenID4VCITxCode>,
}

#[skip_serializing_none]
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct OpenID4VCITxCode {
    #[serde(default)]
    pub input_mode: OpenID4VCITxCodeInputMode,
    #[serde(default)]
    pub length: Option<i64>,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Display, Default)]
pub enum OpenID4VCITxCodeInputMode {
    #[serde(rename = "numeric")]
    #[strum(serialize = "numeric")]
    #[default]
    Numeric,
    #[serde(rename = "text")]
    #[strum(serialize = "text")]
    Text,
}

#[skip_serializing_none]
#[derive(Clone, Serialize, Debug, Default, PartialEq, Eq)]
pub struct OpenID4VCICredentialSubjectItem {
    // Rest of the keys as objects
    #[serde(flatten, deserialize_with = "empty_is_none")]
    pub claims: Option<IndexMap<String, OpenID4VCICredentialSubjectItem>>,

    // Array of objects descritpion
    #[serde(flatten, deserialize_with = "empty_is_none")]
    pub arrays: Option<IndexMap<String, Vec<OpenID4VCICredentialSubjectItem>>>,

    // Additional unexpected keys with just string values
    #[serde(flatten, deserialize_with = "empty_is_none")]
    pub additional_values: Option<IndexMap<String, serde_json::Value>>,

    #[serde(default)]
    pub display: Option<Vec<CredentialSubjectDisplay>>,
    #[serde(default)]
    pub value_type: Option<String>,
    #[serde(default)]
    pub mandatory: Option<bool>,

    // This is custom and optional - keeps the presentation order of claims
    #[serde(default)]
    pub order: Option<Vec<String>>,
}

impl<'de> Deserialize<'de> for OpenID4VCICredentialSubjectItem {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Create a custom visitor for handling dynamic keys
        struct OpenID4VCICredentialSubjectItemVisitor;

        impl<'de> Visitor<'de> for OpenID4VCICredentialSubjectItemVisitor {
            type Value = OpenID4VCICredentialSubjectItem;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a map representing OpenID4VCICredentialSubjectItem")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut claims = IndexMap::new();
                let mut arrays = IndexMap::new();
                let mut additional_values = IndexMap::new();
                let mut display = None;
                let mut value_type = None;
                let mut mandatory = None;
                let mut order = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        // Predefined keys
                        "display" => {
                            display = Some(map.next_value()?);
                        }
                        "value_type" => {
                            value_type = Some(map.next_value::<String>()?.to_uppercase());
                        }
                        "mandatory" => {
                            mandatory = Some(map.next_value()?);
                        }
                        "order" => {
                            order = Some(map.next_value()?);
                        }
                        _ => {
                            // Dynamic keys
                            let next_value = map.next_value::<serde_json::Value>()?;

                            // Classify the field by inspecting its type
                            if next_value.is_object() {
                                match serde_json::from_value::<OpenID4VCICredentialSubjectItem>(
                                    next_value.clone(),
                                ) {
                                    Ok(obj) => {
                                        // Check if array
                                        if let Some(value_type) = obj
                                            .value_type
                                            .as_ref()
                                            .and_then(|vt| vt.strip_suffix("[]"))
                                        {
                                            arrays.insert(
                                                key,
                                                vec![OpenID4VCICredentialSubjectItem {
                                                    value_type: Some(value_type.to_string()),
                                                    ..Default::default()
                                                }],
                                            );
                                        } else {
                                            claims.insert(key, obj);
                                        }
                                    }
                                    Err(_) => {
                                        // If it fails to deserialize, add it to additional_values
                                        additional_values.insert(key, next_value);
                                    }
                                }
                            } else if next_value.is_array() {
                                // Handle arrays
                                // First try to deserialize as our custom array
                                match serde_json::from_value::<Vec<OpenID4VCICredentialSubjectItem>>(
                                    next_value.clone(),
                                ) {
                                    Ok(arr) => {
                                        arrays.insert(key, arr);
                                    }
                                    Err(_) => {
                                        // If it fails, add as additional value
                                        additional_values.insert(key, next_value);
                                    }
                                }
                            } else if next_value.is_string()
                                || next_value.is_boolean()
                                || next_value.is_number()
                            {
                                additional_values.insert(key, next_value);
                            } else {
                                // For any other type, add to additional values
                                additional_values.insert(key, next_value);
                            }
                        }
                    }
                }

                Ok(OpenID4VCICredentialSubjectItem {
                    claims: if claims.is_empty() {
                        None
                    } else {
                        Some(claims)
                    },
                    arrays: if arrays.is_empty() {
                        None
                    } else {
                        Some(arrays)
                    },
                    additional_values: if additional_values.is_empty() {
                        None
                    } else {
                        Some(additional_values)
                    },
                    display,
                    value_type,
                    mandatory,
                    order,
                })
            }
        }

        deserializer.deserialize_map(OpenID4VCICredentialSubjectItemVisitor)
    }
}

pub fn empty_is_none<'de, D>(
    deserializer: D,
) -> Result<Option<IndexMap<String, OpenID4VCICredentialSubjectItem>>, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    let s = IndexMap::deserialize(deserializer)?;
    Ok((!s.is_empty()).then_some(s))
}

#[skip_serializing_none]
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct CredentialSubjectDisplay {
    pub name: Option<String>,
    pub locale: Option<String>,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct OpenID4VCICredentialValueDetails {
    pub value: String,
    pub value_type: String,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct OpenID4VCICredentialOfferClaim {
    pub value: OpenID4VCICredentialOfferClaimValue,
    pub value_type: String,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
#[serde(untagged)]
pub enum OpenID4VCICredentialOfferClaimValue {
    Nested(IndexMap<String, OpenID4VCICredentialOfferClaim>),
    String(String),
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSchemaDetailResponseDTO {
    pub id: CredentialSchemaId,
    #[serde(with = "time::serde::rfc3339")]
    pub created_date: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub format: CredentialFormat,
    pub revocation_method: RevocationMethod,
    pub organisation_id: OrganisationId,
    pub claims: Vec<CredentialClaimSchemaDTO>,
    #[serde(default)]
    pub external_schema: bool,
    pub wallet_storage_type: Option<WalletStorageTypeEnum>,
    pub schema_id: String,
    pub schema_type: String,
    pub layout_type: Option<LayoutType>,
    pub layout_properties: Option<CredentialSchemaLayoutPropertiesRequestDTO>,
}

/// Interaction data used for OpenID4VP (HTTP) on holder side
#[skip_serializing_none]
#[derive(Clone, Deserialize, Serialize, Debug)]
pub struct OpenID4VPHolderInteractionData {
    pub response_type: Option<String>,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub client_id_scheme: ClientIdScheme,
    pub client_id: String,
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_with_serde_json")]
    pub client_metadata: Option<OpenID4VPClientMetadata>,
    pub client_metadata_uri: Option<Url>,
    pub response_mode: Option<String>,
    pub response_uri: Option<Url>,
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_with_serde_json")]
    pub presentation_definition: Option<OpenID4VPPresentationDefinition>,
    pub presentation_definition_uri: Option<Url>,

    #[serde(default, skip_serializing)]
    pub redirect_uri: Option<String>,

    #[serde(default)]
    pub verifier_did: Option<String>,
}

#[derive(Clone, Debug)]
pub struct CreateCredentialSchemaRequestDTO {
    pub name: String,
    pub format: String,
    pub revocation_method: String,
    pub organisation_id: OrganisationId,
    pub claims: Vec<CredentialClaimSchemaRequestDTO>,
    pub wallet_storage_type: Option<WalletStorageTypeEnum>,
    pub layout_type: LayoutType,
    pub external_schema: bool,
    pub layout_properties: Option<CredentialSchemaLayoutPropertiesRequestDTO>,
    pub schema_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CredentialClaimSchemaRequestDTO {
    pub key: String,
    pub datatype: String,
    pub required: bool,
    pub array: Option<bool>,
    pub claims: Vec<CredentialClaimSchemaRequestDTO>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
/// deserializes matching `ProofRequestClaimRestDTO`
pub struct ProofClaimSchema {
    pub id: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_date: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub last_modified: OffsetDateTime,
    pub key: String,
    pub datatype: String,
    pub required: bool,
    pub credential_schema: ProofCredentialSchema,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// deserializes matching `CredentialSchemaListValueResponseRestDTO`
pub struct ProofCredentialSchema {
    pub id: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_date: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub format: String,
    pub revocation_method: String,
    pub wallet_storage_type: Option<WalletStorageTypeEnum>,
    pub schema_type: String,
    pub schema_id: String,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum DatatypeType {
    String,
    Number,
    Date,
    File,
    Object,
    Array,
    Boolean,
}

mod unix_timestamp {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use time::OffsetDateTime;

    pub fn serialize<S>(datetime: &OffsetDateTime, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        datetime.unix_timestamp().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<OffsetDateTime, D::Error>
    where
        D: Deserializer<'de>,
    {
        let timestamp = i64::deserialize(deserializer)?;

        OffsetDateTime::from_unix_timestamp(timestamp).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenID4VCParams {
    pub pre_authorized_code_expires_in: u64,
    pub token_expires_in: u64,
    pub refresh_expires_in: u64,
    #[serde(default)]
    pub credential_offer_by_value: bool,
    #[serde(default)]
    pub client_metadata_by_value: bool,
    #[serde(default)]
    pub presentation_definition_by_value: bool,
    #[serde(default)]
    pub allow_insecure_http_transport: bool,
    #[serde(default)]
    pub use_request_uri: bool,
    #[serde(deserialize_with = "deserialize_encryption_key")]
    pub encryption: SecretSlice<u8>,

    pub issuance: OpenID4VCIssuanceParams,
    pub presentation: OpenID4VCPresentationParams,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenID4VCIssuanceParams {
    #[serde(default)]
    pub disabled: bool,
    #[serde(default = "default_issuance_url_scheme")]
    pub url_scheme: String,

    pub redirect_uri: OpenID4VCRedirectUriParams,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenID4VCPresentationParams {
    #[serde(default)]
    pub disabled: bool,
    #[serde(default = "default_presentation_url_scheme")]
    pub url_scheme: String,
    #[serde(default)]
    pub x509_ca_certificate: Option<String>,
    pub holder: OpenID4VCPresentationHolderParams,
    pub verifier: OpenID4VCPresentationVerifierParams,
    pub redirect_uri: OpenID4VCRedirectUriParams,
}

// Apparently the indirection via functions is required: https://github.com/serde-rs/serde/issues/368
fn default_issuance_url_scheme() -> String {
    "openid-credential-offer".to_string()
}

fn default_presentation_url_scheme() -> String {
    "openid4vp".to_string()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenID4VCPresentationHolderParams {
    pub supported_client_id_schemes: Vec<ClientIdScheme>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenID4VCPresentationVerifierParams {
    pub default_client_id_scheme: ClientIdScheme,
    pub supported_client_id_schemes: Vec<ClientIdScheme>,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Deserialize, Serialize, Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum ClientIdScheme {
    RedirectUri,
    VerifierAttestation,
    Did,
    X509SanDns,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenID4VCRedirectUriParams {
    pub disabled: bool,
    pub allowed_schemes: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OpenID4VCVerifierAttestationPayload {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redirect_uris: Vec<String>,
}
