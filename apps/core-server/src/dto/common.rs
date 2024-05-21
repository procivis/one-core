use dto_mapper::{From, Into};
use serde::{Deserialize, Serialize};
use shared_types::OrganisationId;
use std::fmt;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::endpoint::{
    credential::dto::CredentialListItemResponseRestDTO,
    credential_schema::dto::CredentialSchemaListItemResponseRestDTO,
    did::dto::DidListItemResponseRestDTO, history::dto::HistoryResponseRestDTO,
    key::dto::KeyListItemResponseRestDTO, proof::dto::ProofListItemResponseRestDTO,
    proof_schema::dto::GetProofSchemaListItemResponseRestDTO,
};

#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
// ToSchema is properly generated thanks to that
#[aliases(
    GetProofsResponseRestDTO = GetListResponseRestDTO<ProofListItemResponseRestDTO>,
    GetCredentialSchemasResponseDTO = GetListResponseRestDTO<CredentialSchemaListItemResponseRestDTO>,
    GetDidsResponseRestDTO = GetListResponseRestDTO<DidListItemResponseRestDTO>,
    GetCredentialsResponseDTO = GetListResponseRestDTO<CredentialListItemResponseRestDTO>,
    GetProofSchemaListResponseRestDTO = GetListResponseRestDTO<GetProofSchemaListItemResponseRestDTO>,
    GetKeyListResponseRestDTO = GetListResponseRestDTO<KeyListItemResponseRestDTO>,
    GetHistoryListResponseRestDTO = GetListResponseRestDTO<HistoryResponseRestDTO>
)]
pub struct GetListResponseRestDTO<T>
where
    T: Clone + fmt::Debug + Serialize,
{
    pub values: Vec<T>,
    pub total_pages: u64,
    pub total_items: u64,
}

#[derive(Clone, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(rename_all = "camelCase")]
pub struct GetListQueryParams<T: for<'a> ToSchema<'a>> {
    // pagination
    pub page: u32,
    pub page_size: u32,

    // sorting
    #[param(inline)]
    pub sort: Option<T>,
    pub sort_direction: Option<SortDirection>,

    // filtering
    pub name: Option<String>,
    pub organisation_id: OrganisationId,
    // It is required to rename fields in swagger which are of type vector to <name>[]
    #[param(rename = "exact[]", value_type = Option::<Vec::<String>>)]
    pub exact: Option<Vec<ExactColumn>>,

    #[param(inline, rename = "ids[]")]
    pub ids: Option<Vec<Uuid>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema)]
pub struct NoIncludesSupported {}

impl From<NoIncludesSupported> for one_core::model::list_query::NoInclude {
    fn from(_: NoIncludesSupported) -> Self {
        Self {}
    }
}

#[derive(Clone, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ListQueryParamsRest<
    Filter: IntoParams,
    SortColumn: for<'a> ToSchema<'a>,
    Include: for<'a> ToSchema<'a> = NoIncludesSupported,
> {
    // pagination
    pub page: u32,
    pub page_size: u32,

    // sorting
    pub sort: Option<SortColumn>,
    pub sort_direction: Option<SortDirection>,

    // filtering
    #[serde(flatten)]
    pub filter: Filter,

    pub include: Option<Vec<Include>>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, ToSchema, Into)]
#[into("one_core::model::common::SortDirection")]
pub enum SortDirection {
    #[serde(rename = "ASC")]
    Ascending,
    #[serde(rename = "DESC")]
    Descending,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, ToSchema, Into)]
#[into("one_core::model::common::ExactColumn")]
pub enum ExactColumn {
    #[serde(rename = "name")]
    Name,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct EntityResponseRestDTO {
    pub id: Uuid,
}

impl From<Uuid> for EntityResponseRestDTO {
    fn from(id: Uuid) -> Self {
        EntityResponseRestDTO { id }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[from("one_core::model::common::EntityShareResponseDTO")]
#[serde(rename_all = "camelCase")]
pub struct EntityShareResponseRestDTO {
    pub url: String,
}
