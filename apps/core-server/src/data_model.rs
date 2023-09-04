use one_core::{
    data_model::{ConnectIssuerResponse, ConnectVerifierResponse, ProofClaimSchema},
    repository::data_provider::{
        ClaimProofSchemaRequest, CreateCredentialRequest, CreateCredentialRequestClaim,
        CreateProofRequest, CreateProofSchemaRequest, CreateProofSchemaResponse,
        CredentialClaimSchemaResponse, CredentialShareResponse, DetailCredentialClaimResponse,
        DetailCredentialResponse, DetailProofClaim, DetailProofClaimSchema, DetailProofSchema,
        EntityResponse, ListCredentialSchemaResponse, ProofClaimSchemaResponse,
        ProofDetailsResponse, ProofSchemaResponse, ProofShareResponse, ProofsDetailResponse,
    },
};

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;
use validator::Validate;

use crate::endpoint::credential_schema::dto::CredentialClaimSchemaResponseRestDTO;
use crate::{
    dto::common::GetListQueryParams,
    serialize::{front_time, front_time_option},
};

pub type GetProofSchemaQuery = GetListQueryParams<SortableProofSchemaColumn>;

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub enum SortableProofSchemaColumn {
    Name,
    CreatedDate,
}

impl From<SortableProofSchemaColumn>
    for one_core::repository::data_provider::SortableProofSchemaColumn
{
    fn from(value: SortableProofSchemaColumn) -> Self {
        match value {
            SortableProofSchemaColumn::Name => {
                one_core::repository::data_provider::SortableProofSchemaColumn::Name
            }
            SortableProofSchemaColumn::CreatedDate => {
                one_core::repository::data_provider::SortableProofSchemaColumn::CreatedDate
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ProofSchemaResponseDTO {
    pub id: String,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub expire_duration: u32,
    pub organisation_id: String,
    pub claim_schemas: Vec<ProofClaimSchemaResponseDTO>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ProofClaimSchemaResponseDTO {
    pub id: String,
    pub is_required: bool,
    pub key: String,
    pub credential_schema: ListCredentialSchemaResponseDTO,
}

impl From<ProofSchemaResponse> for ProofSchemaResponseDTO {
    fn from(value: ProofSchemaResponse) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            name: value.name,
            organisation_id: value.organisation_id,
            expire_duration: value.expire_duration,
            claim_schemas: value
                .claim_schemas
                .into_iter()
                .map(|claim| claim.into())
                .collect(),
        }
    }
}

impl From<ProofClaimSchemaResponse> for ProofClaimSchemaResponseDTO {
    fn from(value: ProofClaimSchemaResponse) -> Self {
        Self {
            id: value.id,
            is_required: value.is_required,
            key: value.key,
            credential_schema: value.credential_schema.into(),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, ToSchema, Validate)]
#[serde(rename_all = "camelCase")]
pub struct CreateProofSchemaRequestDTO {
    #[validate(length(min = 1))]
    pub name: String,
    pub organisation_id: Uuid,
    pub expire_duration: u32,
    #[validate(length(min = 1))]
    pub claim_schemas: Vec<ClaimProofSchemaRequestDTO>,
}

impl From<CreateProofSchemaRequestDTO> for CreateProofSchemaRequest {
    fn from(value: CreateProofSchemaRequestDTO) -> Self {
        Self {
            name: value.name,
            organisation_id: value.organisation_id,
            expire_duration: value.expire_duration,
            claim_schemas: value
                .claim_schemas
                .into_iter()
                .map(|claim| claim.into())
                .collect(),
        }
    }
}

impl From<ClaimProofSchemaRequestDTO> for ClaimProofSchemaRequest {
    fn from(value: ClaimProofSchemaRequestDTO) -> Self {
        Self { id: value.id }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ClaimProofSchemaRequestDTO {
    pub id: Uuid,
    //pub is_required: bool, // Todo: Bring it back later
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateProofSchemaResponseDTO {
    pub id: String,
}

impl From<CreateProofSchemaResponse> for CreateProofSchemaResponseDTO {
    fn from(value: CreateProofSchemaResponse) -> Self {
        Self { id: value.id }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CredentialRequestDTO {
    pub credential_schema_id: Uuid,
    pub issuer_did: Uuid,
    pub transport: String,
    pub claim_values: Vec<CredentialRequestClaimDTO>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Transport {
    #[default]
    ProcivisTemporary,
    #[serde(rename = "OPENID4VC")]
    OpenId4Vc,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CredentialRequestClaimDTO {
    pub claim_id: Uuid,
    pub value: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
pub struct EntityResponseDTO {
    pub id: String,
}

impl From<CredentialRequestDTO> for CreateCredentialRequest {
    fn from(value: CredentialRequestDTO) -> Self {
        Self {
            credential_id: None,
            credential_schema_id: value.credential_schema_id,
            issuer_did: value.issuer_did,
            transport: value.transport,
            claim_values: value
                .claim_values
                .into_iter()
                .map(|claim| claim.into())
                .collect(),
            receiver_did_id: None,
            credential: None,
        }
    }
}

impl From<CredentialRequestClaimDTO> for CreateCredentialRequestClaim {
    fn from(value: CredentialRequestClaimDTO) -> Self {
        Self {
            claim_id: value.claim_id,
            value: value.value,
        }
    }
}

impl From<one_core::repository::data_provider::EntityResponse> for EntityResponseDTO {
    fn from(value: EntityResponse) -> Self {
        Self { id: value.id }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
pub struct EntityShareResponseDTO {
    pub url: String,
}

pub(crate) fn share_credentials_to_entity_share_response(
    value: CredentialShareResponse,
    base_url: &String,
) -> EntityShareResponseDTO {
    let protocol = &value.transport;
    EntityShareResponseDTO {
        url: format!(
            "{}/ssi/temporary-issuer/v1/connect?protocol={}&credential={}",
            base_url, protocol, value.credential_id
        ),
    }
}

pub(crate) fn share_proof_to_entity_share_response(
    value: ProofShareResponse,
    base_url: &String,
) -> EntityShareResponseDTO {
    let protocol = &value.transport;
    EntityShareResponseDTO {
        url: format!(
            "{}/ssi/temporary-verifier/v1/connect?protocol={}&proof={}",
            base_url, protocol, value.proof_id
        ),
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DetailCredentialResponseDTO {
    pub id: String,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub issuance_date: OffsetDateTime,
    pub state: CredentialState,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,
    pub schema: ListCredentialSchemaResponseDTO,
    pub issuer_did: Option<String>,
    pub claims: Vec<DetailCredentialClaimResponseDTO>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ListCredentialSchemaResponseDTO {
    pub id: String,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub format: String,
    pub revocation_method: String,
    pub organisation_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DetailCredentialClaimResponseDTO {
    pub schema: crate::endpoint::credential_schema::dto::CredentialClaimSchemaResponseRestDTO,
    pub value: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CredentialState {
    Created,
    Pending,
    Offered,
    Accepted,
    Rejected,
    Revoked,
    Error,
}

impl From<DetailCredentialResponse> for DetailCredentialResponseDTO {
    fn from(value: DetailCredentialResponse) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            issuance_date: value.issuance_date,
            state: value.state.into(),
            last_modified: value.last_modified,
            schema: value.schema.into(),
            issuer_did: value.issuer_did,
            claims: value.claims.into_iter().map(|claim| claim.into()).collect(),
        }
    }
}

impl From<ListCredentialSchemaResponse> for ListCredentialSchemaResponseDTO {
    fn from(value: ListCredentialSchemaResponse) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            name: value.name,
            format: value.format,
            revocation_method: value.revocation_method,
            organisation_id: value.organisation_id,
        }
    }
}

impl From<CredentialClaimSchemaResponse> for CredentialClaimSchemaResponseRestDTO {
    fn from(value: CredentialClaimSchemaResponse) -> Self {
        Self {
            id: value.id.parse().unwrap(),
            created_date: value.created_date,
            last_modified: value.last_modified,
            key: value.key,
            datatype: value.datatype,
        }
    }
}

impl From<DetailCredentialClaimResponse> for DetailCredentialClaimResponseDTO {
    fn from(value: DetailCredentialClaimResponse) -> Self {
        Self {
            schema: value.schema.into(),
            value: value.value,
        }
    }
}

impl From<one_core::repository::data_provider::CredentialState> for CredentialState {
    fn from(value: one_core::repository::data_provider::CredentialState) -> Self {
        use one_core::repository::data_provider::CredentialState as cs;
        match value {
            cs::Created => CredentialState::Created,
            cs::Pending => CredentialState::Pending,
            cs::Offered => CredentialState::Offered,
            cs::Accepted => CredentialState::Accepted,
            cs::Rejected => CredentialState::Rejected,
            cs::Revoked => CredentialState::Revoked,
            cs::Error => CredentialState::Error,
        }
    }
}

pub type GetCredentialQuery = GetListQueryParams<SortableCredentialColumn>;

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub enum SortableCredentialColumn {
    CreatedDate,
    #[serde(rename = "schema.name")]
    SchemaName,
    IssuerDid,
    State,
}

impl From<SortableCredentialColumn>
    for one_core::repository::data_provider::SortableCredentialColumn
{
    fn from(value: SortableCredentialColumn) -> Self {
        match value {
            SortableCredentialColumn::CreatedDate => {
                one_core::repository::data_provider::SortableCredentialColumn::CreatedDate
            }
            SortableCredentialColumn::SchemaName => {
                one_core::repository::data_provider::SortableCredentialColumn::SchemaName
            }
            SortableCredentialColumn::IssuerDid => {
                one_core::repository::data_provider::SortableCredentialColumn::IssuerDid
            }
            SortableCredentialColumn::State => {
                one_core::repository::data_provider::SortableCredentialColumn::State
            }
        }
    }
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(rename_all = "camelCase")]
pub struct PostSsiIssuerConnectQuery {
    pub protocol: String,
    pub credential: Uuid,
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(rename_all = "camelCase")]
pub struct PostSsiVerifierConnectQuery {
    pub protocol: String,
    pub proof: Uuid,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConnectRequestDTO {
    pub did: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConnectIssuerResponseDTO {
    pub credential: String,
    pub format: String,
}

impl From<ConnectIssuerResponse> for ConnectIssuerResponseDTO {
    fn from(value: ConnectIssuerResponse) -> Self {
        Self {
            credential: value.credential,
            format: value.format,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConnectVerifierResponseDTO {
    pub claims: Vec<ProofClaimResponseDTO>,
}

impl From<ConnectVerifierResponse> for ConnectVerifierResponseDTO {
    fn from(value: ConnectVerifierResponse) -> Self {
        Self {
            claims: value.claims.into_iter().map(|item| item.into()).collect(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ProofClaimResponseDTO {
    pub id: String,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,
    pub key: String,
    pub datatype: String,
    pub required: bool,
    pub credential_schema: ListCredentialSchemaResponseDTO,
}

impl From<ProofClaimSchema> for ProofClaimResponseDTO {
    fn from(value: ProofClaimSchema) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            key: value.key,
            datatype: value.datatype,
            required: value.required,
            credential_schema: value.credential_schema.into(),
        }
    }
}

#[derive(Deserialize, ToSchema)]
pub(crate) struct ProofRequestQueryParams {
    pub proof: Uuid,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, ToSchema, Validate)]
#[serde(rename_all = "camelCase")]
pub struct CreateProofRequestDTO {
    pub proof_schema_id: Uuid,
    pub verifier_did: Uuid,
    pub transport: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, ToSchema, Validate)]
#[serde(rename_all = "camelCase")]
pub struct CreateProofResponseDTO {
    pub id: String,
}

impl From<CreateProofRequestDTO> for CreateProofRequest {
    fn from(value: CreateProofRequestDTO) -> Self {
        Self {
            proof_schema_id: value.proof_schema_id,
            verifier_did_id: value.verifier_did,
            transport: value.transport,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
pub struct HandleInvitationRequestDTO {
    pub url: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, Validate)]
#[serde(rename_all = "camelCase")]
pub struct ProofDetailsResponseDTO {
    pub id: String,

    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,

    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,

    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub issuance_date: OffsetDateTime,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(serialize_with = "front_time_option")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub requested_date: Option<OffsetDateTime>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(serialize_with = "front_time_option")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub completed_date: Option<OffsetDateTime>,

    pub verifier_did: String,
    pub transport: String,
    pub state: ProofRequestState,
    pub organisation_id: String,
    pub claims: Vec<DetailProofClaimDTO>,
    pub schema: DetailProofSchemaDTO,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, Validate)]
#[serde(rename_all = "camelCase")]
pub struct DetailProofSchemaDTO {
    pub id: String,
    pub name: String,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, Validate)]
#[serde(rename_all = "camelCase")]
pub struct DetailProofClaimDTO {
    pub schema: DetailProofClaimSchemaDTO,
    pub value: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, Validate)]
#[serde(rename_all = "camelCase")]
pub struct DetailProofClaimSchemaDTO {
    pub id: String,
    pub key: String,
    pub datatype: String,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,
    pub credential_schema: ListCredentialSchemaResponseDTO,
}

impl From<ProofDetailsResponse> for ProofDetailsResponseDTO {
    fn from(value: ProofDetailsResponse) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            issuance_date: value.issuance_date,
            requested_date: value.requested_date,
            completed_date: value.completed_date,
            verifier_did: value.verifier_did,
            transport: value.transport,
            state: value.state.into(),
            organisation_id: value.organisation_id,
            claims: value.claims.iter().map(|i| i.clone().into()).collect(),
            schema: value.schema.into(),
        }
    }
}

impl From<DetailProofSchema> for DetailProofSchemaDTO {
    fn from(value: DetailProofSchema) -> Self {
        Self {
            id: value.id,
            name: value.name,
            created_date: value.created_date,
            last_modified: value.last_modified,
        }
    }
}

impl From<DetailProofClaim> for DetailProofClaimDTO {
    fn from(value: DetailProofClaim) -> Self {
        Self {
            schema: value.schema.into(),
            value: value.value,
        }
    }
}

impl From<DetailProofClaimSchema> for DetailProofClaimSchemaDTO {
    fn from(value: DetailProofClaimSchema) -> Self {
        Self {
            id: value.id,
            key: value.key,
            datatype: value.datatype,
            created_date: value.created_date,
            last_modified: value.last_modified,
            credential_schema: value.credential_schema.into(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProofRequestState {
    Created,
    Pending,
    Offered,
    Accepted,
    Rejected,
    Revoked,
    Error,
}

impl From<one_core::repository::data_provider::ProofRequestState> for ProofRequestState {
    fn from(value: one_core::repository::data_provider::ProofRequestState) -> Self {
        use one_core::repository::data_provider::ProofRequestState as cs;
        match value {
            cs::Created => ProofRequestState::Created,
            cs::Pending => ProofRequestState::Pending,
            cs::Offered => ProofRequestState::Offered,
            cs::Accepted => ProofRequestState::Accepted,
            cs::Rejected => ProofRequestState::Rejected,
            cs::Error => ProofRequestState::Error,
        }
    }
}

pub type GetProofQuery = GetListQueryParams<SortableProofColumn>;

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub enum SortableProofColumn {
    #[serde(rename = "schema.name")]
    ProofSchemaName,
    VerifierDid,
    CreatedDate,
    State,
}

impl From<SortableProofColumn> for one_core::repository::data_provider::SortableProofColumn {
    fn from(value: SortableProofColumn) -> Self {
        match value {
            SortableProofColumn::CreatedDate => {
                one_core::repository::data_provider::SortableProofColumn::CreatedDate
            }
            SortableProofColumn::ProofSchemaName => {
                one_core::repository::data_provider::SortableProofColumn::ProofSchemaName
            }
            SortableProofColumn::VerifierDid => {
                one_core::repository::data_provider::SortableProofColumn::VerifierDid
            }
            SortableProofColumn::State => {
                one_core::repository::data_provider::SortableProofColumn::State
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ProofsDetailResponseDTO {
    pub id: String,

    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,

    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,

    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub issuance_date: OffsetDateTime,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(serialize_with = "front_time_option")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub requested_date: Option<OffsetDateTime>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(serialize_with = "front_time_option")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub completed_date: Option<OffsetDateTime>,

    pub state: ProofRequestState,
    pub organisation_id: String,
    pub verifier_did: String,
    pub schema: DetailProofSchemaDTO,
}

impl From<ProofsDetailResponse> for ProofsDetailResponseDTO {
    fn from(value: ProofsDetailResponse) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            issuance_date: value.issuance_date,
            requested_date: value.requested_date,
            completed_date: value.completed_date,
            state: value.state.into(),
            organisation_id: value.organisation_id,
            verifier_did: value.verifier_did,
            schema: value.schema.into(),
        }
    }
}
