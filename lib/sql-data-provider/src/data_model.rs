use one_core::{
    model::common::SortDirection,
    repository::{
        data_provider::{
            CredentialClaimSchemaResponse, CredentialState, DetailCredentialClaimResponse,
            DetailCredentialResponse, GetDidDetailsResponse, ListCredentialSchemaResponse,
        },
        error::DataLayerError,
    },
};
use sea_orm::{FromQueryResult, Order};

use time::OffsetDateTime;

use crate::entity;

use super::entity::{credential_state, did};

pub fn order_from_sort_direction(direction: SortDirection) -> Order {
    match direction {
        SortDirection::Ascending => Order::Asc,
        SortDirection::Descending => Order::Desc,
    }
}

#[derive(Clone, Debug)]
pub struct GetListQueryParams<SortableColumn> {
    // pagination
    pub page: u32,
    pub page_size: u32,

    // sorting
    pub sort: Option<SortableColumn>,
    pub sort_direction: Option<SortDirection>,

    // filtering
    pub name: Option<String>,
    pub organisation_id: String,
}

#[derive(Debug, Clone, FromQueryResult)]
pub(crate) struct CredentialSchemaClaimSchemaCombined {
    pub id: String,
    pub datatype: String,
}

impl From<did::Model> for GetDidDetailsResponse {
    fn from(value: did::Model) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            name: value.name,
            organisation_id: value.organisation_id,
            did: value.did,
            did_type: value.type_field.into(),
            did_method: value.method,
        }
    }
}

pub fn convert_credential_state(
    state: entity::credential_state::CredentialState,
) -> CredentialState {
    match state {
        entity::credential_state::CredentialState::Created => CredentialState::Created,
        entity::credential_state::CredentialState::Pending => CredentialState::Pending,
        entity::credential_state::CredentialState::Offered => CredentialState::Offered,
        entity::credential_state::CredentialState::Accepted => CredentialState::Accepted,
        entity::credential_state::CredentialState::Rejected => CredentialState::Rejected,
        entity::credential_state::CredentialState::Revoked => CredentialState::Revoked,
        entity::credential_state::CredentialState::Error => CredentialState::Error,
    }
}

impl From<CredentialState> for entity::credential_state::CredentialState {
    fn from(value: CredentialState) -> Self {
        match value {
            CredentialState::Created => entity::credential_state::CredentialState::Created,
            CredentialState::Pending => entity::credential_state::CredentialState::Pending,
            CredentialState::Offered => entity::credential_state::CredentialState::Offered,
            CredentialState::Accepted => entity::credential_state::CredentialState::Accepted,
            CredentialState::Rejected => entity::credential_state::CredentialState::Rejected,
            CredentialState::Revoked => entity::credential_state::CredentialState::Revoked,
            CredentialState::Error => entity::credential_state::CredentialState::Error,
        }
    }
}

pub(crate) fn detail_credential_claim_response_from_model(
    value: ClaimClaimSchemaCombined,
) -> DetailCredentialClaimResponse {
    DetailCredentialClaimResponse {
        schema: CredentialClaimSchemaResponse {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            key: value.key,
            datatype: value.datatype,
        },
        value: value.value,
    }
}

#[derive(Debug, FromQueryResult, Clone)]
pub(crate) struct CredentialDidCredentialSchemaCombined {
    // credential table
    pub id: String,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub issuance_date: OffsetDateTime,
    pub credential: Vec<u8>,

    // did table
    pub did: Option<String>,

    // credential_state table
    pub state: credential_state::CredentialState,

    // credential_schema table
    pub schema_id: String,
    pub schema_name: String,
    pub schema_format: String,
    pub schema_revocation_method: String,
    pub schema_organisation_id: String,
    pub schema_created_date: OffsetDateTime,
    pub schema_last_modified: OffsetDateTime,
}

fn list_credential_schema_response_from_model_combined(
    value: CredentialDidCredentialSchemaCombined,
) -> ListCredentialSchemaResponse {
    ListCredentialSchemaResponse {
        id: value.schema_id,
        created_date: value.schema_created_date,
        last_modified: value.schema_last_modified,
        name: value.schema_name,
        format: value.schema_format,
        revocation_method: value.schema_revocation_method,
        organisation_id: value.schema_organisation_id,
    }
}

#[derive(Debug, Clone, FromQueryResult)]
pub(crate) struct ClaimClaimSchemaCombined {
    pub credential_id: String,
    pub id: String,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub value: String,
    pub key: String,
    pub datatype: String,
}

pub(crate) fn detail_credential_from_combined_credential_did_and_credential_schema(
    value: CredentialDidCredentialSchemaCombined,
    claims: &[ClaimClaimSchemaCombined],
) -> Result<DetailCredentialResponse, DataLayerError> {
    Ok(DetailCredentialResponse {
        id: value.id.to_owned(),
        created_date: value.created_date,
        issuance_date: value.issuance_date,
        state: convert_credential_state(value.state),
        last_modified: value.last_modified,
        issuer_did: value.did.to_owned(),
        claims: claims
            .iter()
            .filter(|claim| claim.credential_id == value.id)
            .cloned()
            .map(detail_credential_claim_response_from_model)
            .collect(),
        schema: list_credential_schema_response_from_model_combined(value.clone()),
        credential: value.credential,
    })
}
