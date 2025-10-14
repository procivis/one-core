use std::collections::HashMap;

use anyhow::Context;
use dcql::DcqlQuery;
use one_crypto::jwe::EncryptionAlgorithm;
use one_dto_mapper::Into;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use shared_types::{ClaimSchemaId, KeyId};
use strum::{Display, EnumString};
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

use super::mapper::{deserialize_with_serde_json, unix_timestamp_option};
use crate::model::claim::Claim;
use crate::model::credential::Credential;
use crate::model::credential_schema::CredentialSchema;
use crate::model::proof_schema::ProofInputClaimSchema;
use crate::provider::credential_formatter::model::{
    CredentialClaim, DetailCredential, IdentifierDetails,
};
use crate::provider::verification_protocol::openid4vp::final1_0::model::OpenID4VPFinal1_0ClientMetadata;
use crate::service::key::dto::PublicKeyJwkDTO;
use crate::util::mdoc::MobileSecurityObject;

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct JwePayload {
    pub aud: Option<Url>,
    #[serde(default, with = "unix_timestamp_option")]
    pub exp: Option<OffsetDateTime>,
    #[serde(flatten)]
    pub submission_data: VpSubmissionData,
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

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DcqlSubmission {
    pub vp_token: HashMap<String, Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DcqlSubmissionEudi {
    pub vp_token: HashMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PexSubmission {
    pub vp_token: String,
    pub presentation_submission: PresentationSubmissionMappingDTO,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ResponseSubmission {
    pub response: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum VpSubmissionData {
    Dcql(DcqlSubmission),
    DcqlEudi(DcqlSubmissionEudi),
    Pex(PexSubmission),
    EncryptedResponse(ResponseSubmission),
}

#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OpenID4VPDirectPostRequestDTO {
    #[serde(flatten)]
    pub submission_data: VpSubmissionData,
    pub state: Option<Uuid>,
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

// https://datatracker.ietf.org/doc/html/rfc7518#section-4.1
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Display)]
pub enum AuthorizationEncryptedResponseAlgorithm {
    // Elliptic Curve Diffie-Hellman Ephemeral Static key agreement using Concat KDF
    #[serde(rename = "ECDH-ES")]
    #[strum(serialize = "ECDH-ES")]
    EcdhEs,
}

// https://datatracker.ietf.org/doc/html/rfc7518#section-5.1
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Display, Into)]
#[into(EncryptionAlgorithm)]
pub enum AuthorizationEncryptedResponseContentEncryptionAlgorithm {
    A128GCM,
    // AES GCM using 256-bit key
    A256GCM,
    #[serde(rename = "A128CBC-HS256")]
    #[strum(serialize = "A128CBC-HS256")]
    A128CBCHS256,
}

#[skip_serializing_none]
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Default)]
pub struct OpenID4VPDraftClientMetadata {
    #[serde(default)]
    pub jwks: Option<OpenID4VPClientMetadataJwks>,
    #[serde(default)]
    pub jwks_uri: Option<String>,
    pub vp_formats: HashMap<String, OpenID4VpPresentationFormat>,
    #[serde(default)]
    pub authorization_encrypted_response_alg: Option<AuthorizationEncryptedResponseAlgorithm>,
    #[serde(default)]
    pub authorization_encrypted_response_enc:
        Option<AuthorizationEncryptedResponseContentEncryptionAlgorithm>,
    #[serde(default)]
    pub id_token_encrypted_response_enc: Option<String>,
    #[serde(default)]
    pub id_token_encrypted_response_alg: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub subject_syntax_types_supported: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
#[serde(untagged)]
pub(crate) enum OpenID4VPClientMetadata {
    Draft(OpenID4VPDraftClientMetadata),
    Final1_0(OpenID4VPFinal1_0ClientMetadata),
}

#[derive(Clone, Serialize, Deserialize, Debug, Default, PartialEq)]
pub struct OpenID4VPClientMetadataJwks {
    pub keys: Vec<OpenID4VPClientMetadataJwkDTO>,
}
#[derive(Clone, Debug)]
pub(super) struct ValidatedProofClaimDTO {
    pub proof_input_claim: ProofInputClaimSchema,
    pub credential: DetailCredential,
    pub credential_schema: CredentialSchema,
    pub value: CredentialClaim,
    pub mdoc_mso: Option<MobileSecurityObject>,
}

/// Interaction data used for OpenID4VP on verifier side
/// - HTTP transport generates this
///
/// Important: This structure is used to deserialize
/// also from all the other verifier interaction data structures
/// during proof submission validation
#[skip_serializing_none]
#[derive(Clone, Deserialize, Serialize, Debug)]
pub(crate) struct OpenID4VPVerifierInteractionContent {
    pub nonce: String,
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_with_serde_json")]
    pub presentation_definition: Option<OpenID4VPPresentationDefinition>,
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_with_serde_json")]
    pub dcql_query: Option<DcqlQuery>,
    /// with client_id_scheme prefix (for Draft 25 and later)
    pub client_id: String,
    pub client_id_scheme: Option<ClientIdScheme>,
    pub response_uri: Option<String>,
    pub encryption_key: Option<OpenID4VPClientMetadataJwkDTO>,
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
    pub format: HashMap<String, OpenID4VpPresentationFormat>,
    pub constraints: OpenID4VPPresentationDefinitionConstraint,
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

// All vp_formats_supported fields are optional,
// this variant is matched first
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct OpenID4VpEmptyEntry {}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
#[serde(untagged)]
pub enum OpenID4VpPresentationFormat {
    Empty(OpenID4VpEmptyEntry),
    SdJwtVcAlgs(OpenID4VPVcSdJwtAlgs),
    LdpVcAlgs(LdpVcAlgs),
    W3CJwtAlgs(OpenID4VPW3CJwtAlgs),
    W3CLdpAlgs(OpenID4VPW3CLdpAlgs),
    MdocAlgs(OpenID4VPMdocAlgs),
    GenericAlgList(OpenID4VPAlgs),
    Other(serde_json::Value),
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct OpenID4VPVcSdJwtAlgs {
    #[serde(
        rename = "sd-jwt_alg_values",
        skip_serializing_if = "Vec::is_empty",
        default
    )]
    pub sd_jwt_alg_values: Vec<String>,
    #[serde(
        rename = "kb-jwt_alg_values",
        skip_serializing_if = "Vec::is_empty",
        default
    )]
    pub kb_jwt_alg_values: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct OpenID4VPAlgs {
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub alg: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct OpenID4VPW3CJwtAlgs {
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub alg_values: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct OpenID4VPW3CLdpAlgs {
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub proof_type_values: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub cryptosuite_values: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct OpenID4VPMdocAlgs {
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub issuerauth_alg_values: Vec<i32>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub deviceauth_alg_values: Vec<i32>,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct LdpVcAlgs {
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub proof_type: Vec<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct SubmissionRequestData {
    pub submission_data: VpSubmissionData,
    pub state: Uuid,
    pub mdoc_generated_nonce: Option<String>,
    pub encryption_key: Option<KeyId>,
}

#[derive(Clone, Debug)]
pub(crate) struct ProvedCredential {
    pub credential: Credential,
    pub issuer_details: IdentifierDetails,
    pub holder_details: IdentifierDetails,
    pub mdoc_mso: Option<MobileSecurityObject>,
}

#[derive(Debug)]
pub(crate) struct AcceptProofResult {
    pub proved_credentials: Vec<ProvedCredential>,
    pub proved_claims: Vec<Claim>,
}

/// Interaction data used for OpenID4VP (HTTP) on holder side
#[skip_serializing_none]
#[derive(Clone, Deserialize, Serialize, Debug)]
pub(crate) struct OpenID4VPHolderInteractionData {
    pub response_type: Option<String>,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub client_id_scheme: ClientIdScheme,

    /// without client_id_scheme prefix (in case of Draft 25 and later)
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
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_with_serde_json")]
    pub dcql_query: Option<DcqlQuery>,

    #[serde(default, skip_serializing)]
    pub redirect_uri: Option<String>,

    #[serde(default)]
    pub verifier_details: Option<IdentifierDetails>,
}

// Apparently the indirection via functions is required: https://github.com/serde-rs/serde/issues/368
pub(crate) fn default_presentation_url_scheme() -> String {
    "openid4vp".to_string()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OpenID4VCPresentationHolderParams {
    pub supported_client_id_schemes: Vec<ClientIdScheme>,
    /// EUDI compatibility flag for non-standard compliant vp_token formatting
    #[serde(default)]
    pub dcql_vp_token_single_presentation: bool,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Deserialize, Serialize, Display, EnumString)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum ClientIdScheme {
    RedirectUri,
    VerifierAttestation,
    #[serde(alias = "decentralized_identifier")]
    Did,
    X509SanDns,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OpenID4VCRedirectUriParams {
    pub enabled: bool,
    pub allowed_schemes: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub(crate) struct OpenID4VCVerifierAttestationPayload {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redirect_uris: Vec<String>,
}
