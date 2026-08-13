use serde::{Deserialize, Serialize};
use shared_types::{
    CertificateId, CredentialSchemaId, DidId, EcosystemId, IdentifierId, InteractionId, KeyId,
    OrganisationId, ProofId, ProofSchemaId, TransactionDataId, TransactionDataType,
};
use standardized_types::openid4vp::ClientIdPrefix;
use standardized_types::openid4vp::dcql::CredentialQueryId;
use time::OffsetDateTime;

use crate::model::common::GetListResponse;
use crate::model::list_filter::{ListFilterValue, StringMatch, ValueComparison};
use crate::model::list_query::ListQuery;
use crate::model::proof::{ExactProofFilterColumn, ProofRole, ProofStateEnum, SortableProofColumn};
use crate::proto::trust_information::dto::TrustInformation;
use crate::provider::transaction_data::TransactionDataDisplayValue;
use crate::provider::verification_protocol::openid4vp::model::CommonVerifierInteractionContent;
use crate::service::certificate::dto::CertificateResponseDTO;
use crate::service::credential::dto::{
    CredentialDetailResponseDTO, DetailCredentialClaimResponseDTO,
};
use crate::service::credential_schema::dto::CredentialSchemaListItemResponseDTO;
use crate::service::identifier::dto::GetIdentifierListItemResponseDTO;
use crate::service::proof_schema::dto::{GetProofSchemaListItemDTO, ProofClaimSchemaResponseDTO};

#[derive(Clone, Debug)]
pub struct CreateProofRequestDTO {
    pub proof_schema_id: ProofSchemaId,
    pub verifier_did_id: Option<DidId>,
    pub verifier_identifier_id: Option<IdentifierId>,
    pub protocol: String,
    pub redirect_uri: Option<String>,
    pub verifier_key: Option<KeyId>,
    pub verifier_certificate: Option<CertificateId>,
    pub iso_mdl_engagement: Option<String>,
    pub transport: Option<Vec<String>>,
    pub profile: Option<String>,
    pub engagement: Option<String>,
    pub webhook_destination_url: Option<String>,
    pub subscriber_information: Option<String>,
    pub transaction_data: Vec<CreateProofRequestTransactionDataDTO>,
    pub ecosystem: Option<EcosystemId>,
}

/// Transaction data supplied at proof-request creation. Turned into an OpenID4VP
/// `transaction_data` entry by the transaction data provider named by `r#type`.
#[derive(Clone, Debug)]
pub struct CreateProofRequestTransactionDataDTO {
    /// Config name of the transaction data provider.
    pub r#type: TransactionDataType,
    /// Credential schemas (of the proof schema) the transaction data applies to.
    pub credential_schema_ids: Vec<CredentialSchemaId>,
    /// Type-specific transaction data content.
    pub data: Option<serde_json::Value>,
}

#[derive(Clone, Debug)]
pub struct CreateProofResponseDTO {
    pub id: ProofId,
}

/// Details of a single (holder-side) transaction data entry of a proof request.
#[derive(Clone, Debug)]
pub struct ProofTransactionDataResponseDTO {
    pub id: TransactionDataId,
    /// Config name of the transaction data provider that validated this entry.
    pub r#type: TransactionDataType,
    /// Credential query ids the transaction data is bound to.
    pub credential_query_ids: Vec<CredentialQueryId>,
    /// Grouped key-value data for displaying the transaction to the user.
    pub transaction_data_display: Vec<TransactionDataDisplayValue>,
    /// Base64url-decoded raw transaction data entry received from the verifier.
    pub raw_transaction_data: Option<serde_json::Value>,
}

#[derive(Clone, Debug)]
pub struct ProofDetailResponseDTO {
    pub id: ProofId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub requested_date: Option<OffsetDateTime>,
    pub retain_until_date: Option<OffsetDateTime>,
    pub completed_date: Option<OffsetDateTime>,
    pub verifier: Option<GetIdentifierListItemResponseDTO>,
    pub verifier_certificate: Option<CertificateResponseDTO>,
    pub protocol: String,
    pub transport: String,
    pub engagement: Option<String>,
    pub state: ProofStateEnum,
    pub role: ProofRole,
    pub organisation_id: OrganisationId,
    pub schema: Option<GetProofSchemaListItemDTO>,
    pub redirect_uri: Option<String>,
    pub proof_inputs: Vec<ProofInputDTO>,
    pub claims_removed_at: Option<OffsetDateTime>,
    pub profile: Option<String>,
    pub webhook_destination_url: Option<String>,
    pub trust_information: Option<TrustInformation>,
    pub subscriber_information: Option<String>,
    /// Transaction data attached to this proof request (verifier proofs only).
    pub transaction_data: Vec<TransactionDataResponseDTO>,
    pub ecosystem: Option<EcosystemId>,
}

/// Transaction data as attached to a proof request at creation time. Mirrors
/// [`CreateProofRequestTransactionDataDTO`] for the response side.
#[derive(Clone, Debug)]
pub struct TransactionDataResponseDTO {
    pub r#type: TransactionDataType,
    pub credential_schema_ids: Vec<CredentialSchemaId>,
    pub data: Option<serde_json::Value>,
}

#[derive(Clone, Debug)]
pub struct ProofListItemResponseDTO {
    pub id: ProofId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub requested_date: Option<OffsetDateTime>,
    pub completed_date: Option<OffsetDateTime>,
    pub retain_until_date: Option<OffsetDateTime>,
    pub verifier: Option<GetIdentifierListItemResponseDTO>,
    pub protocol: String,
    pub engagement: Option<String>,
    pub transport: String,
    pub state: ProofStateEnum,
    pub role: ProofRole,
    pub schema: Option<GetProofSchemaListItemDTO>,
    pub profile: Option<String>,
    pub webhook_destination_url: Option<String>,
    pub redirect_uri: Option<String>,
    pub ecosystem: Option<EcosystemId>,
}

#[derive(Clone, Debug)]
pub struct ProofClaimDTO {
    pub schema: ProofClaimSchemaResponseDTO,
    pub path: String,
    pub value: Option<ProofClaimValueDTO>,
}

#[derive(Clone, Debug)]
pub enum ProofClaimValueDTO {
    Value(String),
    Claims(Vec<ProofClaimDTO>),
}

#[derive(Clone, Debug)]
pub struct ProofInputDTO {
    pub claims: Vec<ProofClaimDTO>,
    pub credential: Option<CredentialDetailResponseDTO<DetailCredentialClaimResponseDTO>>,
    pub credential_schema: CredentialSchemaListItemResponseDTO,
}

pub type GetProofListResponseDTO = GetListResponse<ProofListItemResponseDTO>;

#[derive(Debug, Clone)]
pub enum ProofFilterValue {
    Name(StringMatch),
    OrganisationId(OrganisationId),
    States(Vec<ProofStateEnum>),
    Roles(Vec<ProofRole>),
    ProofIds(Vec<ProofId>),
    ProofIdsNot(Vec<ProofId>),
    ProofSchemaIds(Vec<ProofSchemaId>),
    VerifierIds(Vec<IdentifierId>),
    Profiles(Vec<String>),
    Ecosystems(Vec<EcosystemId>),
    ValidForDeletion,
    CreatedDate(ValueComparison<OffsetDateTime>),
    LastModified(ValueComparison<OffsetDateTime>),
    RequestedDate(ValueComparison<OffsetDateTime>),
    CompletedDate(ValueComparison<OffsetDateTime>),
}

impl ListFilterValue for ProofFilterValue {}

pub type GetProofQueryDTO = ListQuery<SortableProofColumn, ProofFilterValue>;

#[derive(Clone, Debug)]
pub struct ProofFilterParamsDTO {
    pub name: Option<String>,
    pub exact: Option<Vec<ExactProofFilterColumn>>,
    pub states: Option<Vec<ProofStateEnum>>,
    pub roles: Option<Vec<ProofRole>>,
    pub ids: Option<Vec<ProofId>>,
    pub proof_schema_ids: Option<Vec<ProofSchemaId>>,
    pub verifier_ids: Option<Vec<IdentifierId>>,
    pub profiles: Option<Vec<String>>,
    pub organisation_id: OrganisationId,
    pub ecosystems: Option<Vec<EcosystemId>>,
    pub created_date_after: Option<OffsetDateTime>,
    pub created_date_before: Option<OffsetDateTime>,
    pub last_modified_after: Option<OffsetDateTime>,
    pub last_modified_before: Option<OffsetDateTime>,
    pub requested_date_after: Option<OffsetDateTime>,
    pub requested_date_before: Option<OffsetDateTime>,
    pub completed_date_after: Option<OffsetDateTime>,
    pub completed_date_before: Option<OffsetDateTime>,
}

#[derive(Clone, Debug)]
pub struct ProposeProofResponseDTO {
    pub proof_id: ProofId,
    pub interaction_id: InteractionId,
    pub url: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct CreateProofInteractionData {
    pub transport: Vec<String>,
    #[serde(flatten)]
    pub common: CommonVerifierInteractionContent,
}

#[derive(Clone, Debug, Default)]
pub struct ShareProofRequestDTO {
    pub params: Option<ShareProofRequestParamsDTO>,
}

#[derive(Clone, Debug, Default)]
pub struct ShareProofRequestParamsDTO {
    pub client_id_scheme: Option<ClientIdPrefix>,
}

#[derive(Clone, Debug)]
pub struct ProposeProofRequestDTO {
    pub protocol: String,
    pub organisation_id: OrganisationId,
    pub engagement: Vec<String>,
    pub ui_message: Option<String>,
    pub ecosystem: Option<EcosystemId>,
}

#[derive(Clone, Debug)]
pub struct ShareProofResponseDTO {
    pub url: String,
    pub expires_at: Option<OffsetDateTime>,
}
