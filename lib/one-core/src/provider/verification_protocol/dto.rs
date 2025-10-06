use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use shared_types::{CredentialId, DidValue};
use time::OffsetDateTime;

use crate::config::core_config::{DidType, IdentifierType, TransportType};
use crate::model::credential::Credential;
use crate::model::credential_schema::{
    CredentialSchema, CredentialSchemaType, WalletStorageTypeEnum,
};
use crate::model::did::Did;
use crate::model::interaction::InteractionId;
use crate::model::key::Key;
use crate::model::proof::{Proof, UpdateProofRequest};
use crate::service::credential::dto::{
    CredentialDetailResponseDTO, DetailCredentialClaimResponseDTO,
    DetailCredentialClaimValueResponseDTO,
};
use crate::service::credential_schema::dto::{
    CredentialClaimSchemaDTO, CredentialSchemaDetailResponseDTO,
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// deserializes matching `ConnectVerifierResponseRestDTO`
pub(crate) struct ConnectVerifierResponse {
    pub claims: Vec<ProofClaimSchema>,
    pub verifier_did: DidValue,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
/// deserializes matching `ProofRequestClaimRestDTO`
pub(crate) struct ProofClaimSchema {
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
pub(crate) struct ProofCredentialSchema {
    pub id: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_date: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub format: String,
    pub revocation_method: String,
    pub wallet_storage_type: Option<WalletStorageTypeEnum>,
    pub schema_type: CredentialSchemaType,
    pub schema_id: String,
}

#[derive(Clone, Debug)]
pub struct PresentationDefinitionResponseDTO {
    pub request_groups: Vec<PresentationDefinitionRequestGroupResponseDTO>,
    pub credentials: Vec<CredentialDetailResponseDTO<DetailCredentialClaimResponseDTO>>,
}

#[derive(Clone, Debug)]
pub struct PresentationDefinitionRequestGroupResponseDTO {
    pub id: String,
    pub name: Option<String>,
    pub purpose: Option<String>,
    pub rule: PresentationDefinitionRuleDTO,
    pub requested_credentials: Vec<PresentationDefinitionRequestedCredentialResponseDTO>,
}

#[derive(Clone, Debug)]
pub struct PresentationDefinitionRequestedCredentialResponseDTO {
    pub id: String,
    pub name: Option<String>,
    pub purpose: Option<String>,
    pub fields: Vec<PresentationDefinitionFieldDTO>,
    pub multiple: Option<bool>,
    pub applicable_credentials: Vec<CredentialId>,
    pub inapplicable_credentials: Vec<CredentialId>,
    pub validity_credential_nbf: Option<OffsetDateTime>,
}

#[derive(Clone, Debug)]
pub struct PresentationDefinitionFieldDTO {
    pub id: String,
    pub name: Option<String>,
    pub purpose: Option<String>,
    pub required: Option<bool>,
    pub key_map: HashMap<CredentialId, String>,
}

#[derive(Clone, Debug)]
pub enum PresentationDefinitionRuleTypeEnum {
    All,
    Pick,
}

#[derive(Clone, Debug)]
pub struct PresentationDefinitionRuleDTO {
    pub r#type: PresentationDefinitionRuleTypeEnum,
    pub min: Option<u32>,
    pub max: Option<u32>,
    pub count: Option<u32>,
}

#[derive(Clone, Debug)]
pub(crate) struct CredentialGroup {
    pub id: String,
    pub name: Option<String>,
    pub purpose: Option<String>,
    pub claims: Vec<CredentialGroupItem>,
    pub applicable_credentials: Vec<Credential>,
    pub inapplicable_credentials: Vec<Credential>,
    pub validity_credential_nbf: Option<OffsetDateTime>,
}

#[derive(Clone, Debug)]
pub(crate) struct CredentialGroupItem {
    pub id: String,
    pub key: String,
    pub required: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct VerificationProtocolCapabilities {
    pub supported_transports: Vec<TransportType>,
    pub did_methods: Vec<DidType>,
    pub verifier_identifier_types: Vec<IdentifierType>,
}

#[derive(Clone, Debug)]
pub(crate) struct InvitationResponseDTO {
    pub interaction_id: InteractionId,
    pub proof: Proof,
}

#[derive(Clone, Debug)]
pub(crate) struct FormattedCredentialPresentation {
    pub presentation: String,
    pub validity_credential_presentation: Option<String>,
    pub credential_schema: CredentialSchema,
    pub reference: PresentationReference,
    pub holder_did: Did,
    pub key: Key,
    pub jwk_key_id: Option<String>,
}

/// Information required for the provider to include the credential presentation in the submission.
#[derive(Clone, Debug)]
pub(crate) enum PresentationReference {
    PresentationExchange(PresentationDefinitionRequestedCredentialResponseDTO),
    Dcql { credential_query_id: String },
}

#[derive(Clone, Debug)]
pub(crate) struct ShareResponse<T> {
    pub url: String,
    pub interaction_id: InteractionId,
    pub context: T,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct UpdateResponse {
    pub update_proof: Option<UpdateProofRequest>,
}

#[derive(Clone, Debug)]
pub struct PresentationDefinitionV2ResponseDTO {
    pub credential_queries: HashMap<String, CredentialQueryResponseDTO>,
    pub credential_sets: Vec<CredentialSetResponseDTO>,
}

#[derive(Clone, Debug)]
pub struct CredentialQueryResponseDTO {
    pub multiple: bool,
    pub credential_or_failure_hint: ApplicableCredentialOrFailureHintEnum,
}

#[derive(Clone, Debug)]
pub enum ApplicableCredentialOrFailureHintEnum {
    ApplicableCredentials {
        applicable_credentials:
            Vec<CredentialDetailResponseDTO<CredentialDetailClaimExtResponseDTO>>,
    },
    FailureHint {
        // boxed because of large size difference
        failure_hint: Box<CredentialQueryFailureHintResponseDTO>,
    },
}

#[derive(Clone, Debug)]
pub struct CredentialQueryFailureHintResponseDTO {
    pub reason: CredentialQueryFailureReasonEnum,
    pub credential_schema: Option<CredentialSchemaDetailResponseDTO>,
}

#[derive(Clone, Debug)]
pub enum CredentialQueryFailureReasonEnum {
    NoCredential,
    Validity,
    Constraint,
}

#[derive(Clone, Debug)]
pub struct CredentialDetailClaimExtResponseDTO {
    pub path: String,
    pub schema: CredentialClaimSchemaDTO,
    pub value: DetailCredentialClaimValueResponseDTO<Self>,
    pub user_selection: bool,
    pub required: bool,
}

#[derive(Clone, Debug)]
pub struct CredentialSetResponseDTO {
    pub required: bool,
    pub options: Vec<Vec<String>>,
}
