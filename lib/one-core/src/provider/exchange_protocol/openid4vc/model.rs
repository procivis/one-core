use std::collections::HashMap;

use anyhow::Context;
use ct_codecs::{Base64UrlSafeNoPadding, Decoder, Encoder};
use dto_mapper::{convert_inner, Into};
use serde::{Deserialize, Serialize};
use shared_types::{ClaimSchemaId, CredentialSchemaId, DidId, DidValue, KeyId, OrganisationId};
use strum::Display;
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

use super::error::OpenID4VCIError;
use super::mapper::deserialize_with_serde_json;
use super::openidvc_ble::BLEPeer;
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
use crate::provider::credential_formatter::model::DetailCredential;
use crate::provider::exchange_protocol::dto::PresentationDefinitionRequestedCredentialResponseDTO;
use crate::service::credential_schema::dto::CredentialClaimSchemaDTO;
use crate::service::key::dto::PublicKeyJwkDTO;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BleOpenId4VpResponse {
    pub vp_token: String,
    pub presentation_submission: PresentationSubmissionMappingDTO,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct OpenID4VCInteractionContent {
    pub pre_authorized_code_used: bool,
    pub access_token: String,
    #[serde(with = "time::serde::rfc3339::option")]
    pub access_token_expires_at: Option<OffsetDateTime>,
    pub refresh_token: Option<String>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub refresh_token_expires_at: Option<OffsetDateTime>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HolderInteractionData {
    pub issuer_url: String,
    pub credential_endpoint: String,
    pub access_token: String,
    #[serde(with = "time::serde::rfc3339::option")]
    pub access_token_expires_at: Option<OffsetDateTime>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub refresh_token: Option<String>,
    #[serde(
        with = "time::serde::rfc3339::option",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub refresh_token_expires_at: Option<OffsetDateTime>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BLEOpenID4VPInteractionData {
    pub task_id: Uuid,
    pub peer: BLEPeer,
    pub nonce: Option<String>,
    pub presentation_definition: Option<OpenID4VPPresentationDefinition>,
    pub presentation_submission: Option<BleOpenId4VpResponse>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JwePayload {
    pub aud: Url,
    #[serde(with = "unix_timestamp")]
    pub exp: OffsetDateTime,
    pub vp_token: String,
    pub presentation_submission: PresentationSubmissionMappingDTO,
    pub state: String,
}

impl JwePayload {
    pub(crate) fn try_from_json_base64_decode(payload: &[u8]) -> anyhow::Result<Self> {
        let payload = Base64UrlSafeNoPadding::decode_to_vec(payload, None)
            .context("MdocJwePayload base64 decoding failed")?;

        let payload =
            serde_json::from_slice(&payload).context("MdocJwePayload deserialization failed")?;

        Ok(payload)
    }

    pub(crate) fn try_into_json_base64_encode(&self) -> anyhow::Result<String> {
        let payload = serde_json::to_vec(self).context("MdocJwePayload serialization failed")?;
        let payload = Base64UrlSafeNoPadding::encode_to_string(payload)
            .context("MdocJwePayload base64 encoding failed")?;

        Ok(payload)
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct OpenID4VCIIssuerMetadataResponseDTO {
    pub credential_issuer: String,
    pub credential_endpoint: String,
    pub credentials_supported: Vec<OpenID4VCIIssuerMetadataCredentialSupportedResponseDTO>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct OpenID4VCIIssuerMetadataCredentialSupportedResponseDTO {
    pub format: String,
    pub claims:
        Option<HashMap<String, HashMap<String, OpenID4VCIIssuerMetadataMdocClaimsValuesDTO>>>,
    pub order: Option<Vec<String>>,
    pub credential_definition: Option<OpenID4VCIIssuerMetadataCredentialDefinitionResponseDTO>,
    pub doctype: Option<String>,
    pub display: Option<Vec<OpenID4VCIIssuerMetadataCredentialSupportedDisplayDTO>>,
    pub wallet_storage_type: Option<WalletStorageTypeEnum>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct OpenID4VCIIssuerMetadataCredentialSupportedDisplayDTO {
    pub name: String,
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct OpenID4VCIIssuerMetadataMdocClaimsValuesDTO {
    #[serde(default)]
    pub value: HashMap<String, OpenID4VCIIssuerMetadataMdocClaimsValuesDTO>,
    pub value_type: String,
    pub mandatory: Option<bool>,
    pub order: Option<Vec<String>>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenID4VCIIssuerMetadataCredentialDefinitionResponseDTO {
    pub r#type: Vec<String>,
    pub credential_schema: Option<OpenID4VCIIssuerMetadataCredentialSchemaResponseDTO>,
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
    pub access_token: String,
    pub token_type: String,
    pub expires_in: Timestamp,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub refresh_token_expires_in: Option<Timestamp>,
}

#[derive(Clone, Debug)]
pub struct OpenID4VCIErrorResponseDTO {
    pub error: OpenID4VCIError,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "grant_type")]
pub enum OpenID4VCITokenRequestDTO {
    #[serde(rename = "urn:ietf:params:oauth:grant-type:pre-authorized_code")]
    PreAuthorizedCode {
        #[serde(rename = "pre-authorized_code")]
        pre_authorized_code: String,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpenID4VCIInteractionDataDTO {
    pub pre_authorized_code_used: bool,
    pub access_token: String,
    #[serde(with = "time::serde::rfc3339::option")]
    pub access_token_expires_at: Option<OffsetDateTime>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub refresh_token: Option<String>,
    #[serde(
        with = "time::serde::rfc3339::option",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub refresh_token_expires_at: Option<OffsetDateTime>,
}

#[derive(Clone, Debug, Serialize)]
pub struct OpenID4VCICredentialDefinitionRequestDTO {
    pub r#type: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct OpenID4VCICredentialRequestDTO {
    pub format: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_definition: Option<OpenID4VCICredentialDefinitionRequestDTO>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub doctype: Option<String>,
    pub proof: OpenID4VCIProofRequestDTO,
}

#[derive(Clone, Debug, Serialize)]
pub struct OpenID4VCIProofRequestDTO {
    pub proof_type: String,
    pub jwt: String,
}

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
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct OpenID4VPClientMetadata {
    #[serde(default)]
    pub jwks: Vec<OpenID4VPClientMetadataJwkDTO>,
    pub vp_formats: HashMap<String, OpenID4VPFormat>,
    pub client_id_scheme: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_encrypted_response_alg: Option<AuthorizationEncryptedResponseAlgorithm>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_encrypted_response_enc:
        Option<AuthorizationEncryptedResponseContentEncryptionAlgorithm>,
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
}

#[derive(Clone, Serialize, Deserialize)]
pub struct OpenID4VCICredential {
    pub format: String,
    pub credential_definition: Option<OpenID4VCICredentialDefinition>,
    pub doctype: Option<String>,
    pub proof: OpenID4VCIProof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpenID4VCIProof {
    pub proof_type: String,
    pub jwt: String,
}

#[derive(Clone, Deserialize, Serialize, Debug)]
pub struct OpenID4VPInteractionContent {
    pub nonce: String,
    #[serde(deserialize_with = "deserialize_with_serde_json")]
    pub presentation_definition: OpenID4VPPresentationDefinition,
}

#[derive(Clone, Deserialize, Serialize, Debug)]
pub struct OpenID4VPPresentationDefinition {
    pub id: Uuid,
    pub input_descriptors: Vec<OpenID4VPPresentationDefinitionInputDescriptor>,
}

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

#[derive(Clone, Deserialize, Serialize, Debug)]
pub struct OpenID4VPPresentationDefinitionConstraint {
    pub fields: Vec<OpenID4VPPresentationDefinitionConstraintField>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub validity_credential_nbf: Option<OffsetDateTime>,
}

#[derive(Clone, Deserialize, Serialize, Debug)]
pub struct OpenID4VPPresentationDefinitionConstraintField {
    pub id: Option<ClaimSchemaId>,
    pub name: Option<String>,
    pub purpose: Option<String>,
    pub path: Vec<String>,
    pub optional: Option<bool>,
    pub filter: Option<OpenID4VPPresentationDefinitionConstraintFieldFilter>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
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
    pub key_id: KeyId,
    #[serde(flatten)]
    pub jwk: PublicKeyJwkDTO,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct OpenID4VPFormat {
    pub alg: Vec<String>,
}

#[derive(Debug)]
pub struct RequestData {
    pub presentation_submission: PresentationSubmissionMappingDTO,
    pub vp_token: String,
    pub state: Uuid,
    pub mdoc_generated_nonce: Option<String>,
}

#[derive(Clone, Debug)]
pub struct ProvedCredential {
    pub credential: Credential,
    pub issuer_did_value: DidValue,
    pub holder_did_value: DidValue,
}

pub struct AcceptProofResult {
    pub proved_credentials: Vec<ProvedCredential>,
    pub proved_claims: Vec<Claim>,
}

#[derive(Clone, Debug)]
pub enum InvitationResponseDTO {
    Credential {
        interaction_id: InteractionId,
        credentials: Vec<Credential>,
    },
    ProofRequest {
        interaction_id: InteractionId,
        proof: Box<Proof>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Into)]
#[into(LayoutProperties)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSchemaLayoutPropertiesRequestDTO {
    #[into(with_fn = convert_inner)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub background: Option<CredentialSchemaBackgroundPropertiesRequestDTO>,
    #[into(with_fn = convert_inner)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo: Option<CredentialSchemaLogoPropertiesRequestDTO>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary_attribute: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secondary_attribute: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub picture_attribute: Option<String>,
    #[into(with_fn = convert_inner)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<CredentialSchemaCodePropertiesRequestDTO>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSchemaLogoPropertiesRequestDTO {
    pub font_color: Option<String>,
    pub background_color: Option<String>,
    pub image: Option<String>,
}

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
    pub id: Uuid,
    pub context: T,
}

#[derive(Clone, Deserialize, Debug)]
pub struct SubmitIssuerResponse {
    pub credential: String,
    pub format: String,
    pub redirect_uri: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct UpdateResponse<T> {
    pub result: T,
    pub update_proof: Option<UpdateProofRequest>,
    pub create_did: Option<Did>,
    pub update_credential: Option<UpdateCredentialRequest>,
    pub update_credential_schema: Option<UpdateCredentialSchemaRequest>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct OpenID4VCICredentialOfferDTO {
    pub credential_issuer: String,
    pub credentials: Vec<OpenID4VCICredentialOfferCredentialDTO>,
    pub grants: OpenID4VCIGrants,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct OpenID4VCICredentialOfferCredentialDTO {
    pub format: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_definition: Option<OpenID4VCICredentialDefinition>,
    pub wallet_storage_type: Option<WalletStorageTypeEnum>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doctype: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claims: Option<HashMap<String, OpenID4VCICredentialOfferClaim>>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct OpenID4VCIGrants {
    #[serde(rename = "urn:ietf:params:oauth:grant-type:pre-authorized_code")]
    pub code: OpenID4VCIGrant,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct OpenID4VCIGrant {
    #[serde(rename = "pre-authorized_code")]
    pub pre_authorized_code: String,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct OpenID4VCICredentialDefinition {
    pub r#type: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "credentialSubject")]
    pub credential_subject: Option<OpenID4VCICredentialSubject>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct OpenID4VCICredentialSubject {
    #[serde(flatten)]
    pub keys: HashMap<String, OpenID4VCICredentialValueDetails>,
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
    Nested(HashMap<String, OpenID4VCICredentialOfferClaim>),
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
    pub wallet_storage_type: Option<WalletStorageTypeEnum>,
    pub schema_id: String,
    pub schema_type: String,
    pub layout_type: Option<LayoutType>,
    pub layout_properties: Option<CredentialSchemaLayoutPropertiesRequestDTO>,
}

#[derive(Clone, Deserialize, Serialize, Debug)]
pub struct OpenID4VPInteractionData {
    pub response_type: String,
    pub state: Option<String>,
    pub nonce: String,
    pub client_id_scheme: String,
    pub client_id: Url,
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_with_serde_json")]
    pub client_metadata: Option<OpenID4VPClientMetadata>,
    pub client_metadata_uri: Option<Url>,
    pub response_mode: String,
    pub response_uri: Url,
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_with_serde_json")]
    pub presentation_definition: Option<OpenID4VPPresentationDefinition>,
    pub presentation_definition_uri: Option<Url>,

    #[serde(skip_serializing)]
    pub redirect_uri: Option<String>,
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
