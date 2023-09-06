use one_core::{
    data_model::{ConnectIssuerResponse, ConnectVerifierResponse, ProofClaimSchema},
    repository::data_provider::{
        CreateCredentialRequest, CreateCredentialRequestClaim, CredentialClaimSchemaResponse,
        CredentialShareResponse, DetailCredentialClaimResponse, DetailCredentialResponse,
        EntityResponse, ListCredentialSchemaResponse,
    },
};

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::endpoint::credential_schema::dto::CredentialClaimSchemaResponseRestDTO;
use crate::{dto::common::GetListQueryParams, serialize::front_time};

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CredentialRequestDTO {
    pub credential_schema_id: Uuid,
    pub issuer_did: Uuid,
    pub transport: String,
    pub claim_values: Vec<CredentialRequestClaimDTO>,
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

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
pub struct HandleInvitationRequestDTO {
    pub url: String,
}
