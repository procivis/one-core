use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use serde::Serialize;
use shared_types::i18n::I18nString;
use shared_types::{CredentialId, InteractionId, TransactionDataId, TransactionDataType};
use standardized_types::iana::EncryptionAlgorithm;
use standardized_types::openid4vp::dcql::CredentialQueryId;
use strum::{AsRefStr, Display, EnumString};
use time::OffsetDateTime;
use url::Url;

use crate::config::core_config::{DidType, IdentifierType, TransportType};
use crate::model::credential_schema_format::CredentialSchemaFormat;
use crate::model::did::Did;
use crate::model::key::Key;
use crate::model::proof::Proof;
use crate::proto::native_credential_manager::NativeDcApiResponseHandler;
use crate::provider::ecosystem::model::ProtocolArtifact;
use crate::service::credential::dto::{
    CredentialDetailResponseDTO, DetailCredentialClaimValueResponseDTO,
};
use crate::service::credential_schema::dto::{
    CredentialClaimSchemaDTO, CredentialSchemaDetailResponseDTO,
};

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct VerificationProtocolCapabilities {
    pub features: Vec<Feature>,
    pub supported_transports: Vec<TransportType>,
    pub did_methods: Vec<DidType>,
    pub verifier_identifier_types: Vec<IdentifierType>,
    pub supported_presentation_definition: Vec<PresentationDefinitionVersion>,
    pub supported_encryption_algorithms: Vec<EncryptionAlgorithm>,
}

#[derive(Debug, Serialize, Clone, Eq, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum Feature {
    SupportsWebhooks,
}

#[derive(Debug, Copy, Clone, Display, EnumString, Serialize, AsRefStr, Eq, PartialEq)]
pub enum PresentationDefinitionVersion {
    #[serde(rename = "V2")]
    #[strum(serialize = "V2")]
    V2,
}

#[derive(Clone, Debug)]
pub(crate) enum InvitationRequest {
    Url(Url),
    IsoDcApi {
        origin: String,
        encryption_info: String,
        device_request: String,
        response_handler: Arc<dyn NativeDcApiResponseHandler>,
    },
}

#[derive(Clone, Debug)]
pub(crate) struct InvitationResponseDTO<'a> {
    pub interaction_id: InteractionId,
    pub proof: Proof,
    pub ecosystem_artifact: ProtocolArtifact<'a>,
}

#[derive(Clone, Debug)]
pub(crate) struct FormattedCredentialPresentation {
    pub presentation: String,
    pub credential_format: CredentialSchemaFormat,
    pub credential_query_id: CredentialQueryId,
    pub holder_did: Option<Did>,
    pub key: Key,
    pub jwk_key_id: Option<String>,
    pub transaction_data_ids: Vec<TransactionDataId>,
}

#[derive(Clone, Debug)]
pub(crate) struct ShareResponse {
    pub url: String,
    pub interaction_id: InteractionId,
    pub interaction_data: Option<Vec<u8>>,
    pub expires_at: Option<OffsetDateTime>,
}

#[derive(Clone, Debug)]
pub struct PresentationDefinitionV2ResponseDTO {
    /// Map of credential query id to batch parent credential id.
    /// Used to distinguish exhausted batches from those that do not satisfy the query at all.
    pub(crate) matching_batches_with_unavailable_items: HashMap<String, HashSet<CredentialId>>,
    pub credential_queries: HashMap<String, CredentialQueryResponseDTO>,
    pub credential_sets: Vec<CredentialSetResponseDTO>,
    pub transaction_data: Vec<PresentationDefinitionTransactionDataDTO>,
}

#[derive(Clone, Debug)]
pub struct PresentationDefinitionTransactionDataDTO {
    pub id: TransactionDataId,
    pub r#type: TransactionDataType,
    pub credential_query_ids: Vec<CredentialQueryId>,
}

#[derive(Clone, Debug)]
pub struct CredentialQueryResponseDTO {
    pub multiple: bool,
    pub credential_or_failure_hint: ApplicableCredentialOrFailureHintEnum,
}

#[derive(Clone, Debug)]
pub enum ApplicableCredentialOrFailureHintEnum {
    ApplicableCredentials {
        purpose: Option<I18nString>,
        applicable_credentials: Vec<ApplicableCredential>,
    },
    FailureHint {
        // boxed because of large size difference
        failure_hint: Box<CredentialQueryFailureHintResponseDTO>,
    },
}

#[derive(Clone, Debug)]
pub struct ApplicableCredential {
    pub credential: CredentialDetailResponseDTO<CredentialDetailClaimExtResponseDTO>,
    pub embedded_disclosure_policy_violation: Option<DisclosurePolicyViolation>,
}

#[derive(Clone, Debug)]
pub struct DisclosurePolicyViolation {
    pub id: String,
    pub description: Option<String>,
    pub url: Option<String>,
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
    pub require_biometric_data_user_consent: bool,
}

#[derive(Clone, Debug)]
pub struct CredentialSetResponseDTO {
    pub required: bool,
    pub options: Vec<Vec<String>>,
}
