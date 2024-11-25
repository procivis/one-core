use std::fmt;

use one_dto_mapper::{From, Into};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::endpoint::credential::dto::CredentialListItemResponseRestDTO;
use crate::endpoint::credential_schema::dto::CredentialSchemaListItemResponseRestDTO;
use crate::endpoint::did::dto::DidListItemResponseRestDTO;
use crate::endpoint::history::dto::HistoryResponseRestDTO;
use crate::endpoint::key::dto::KeyListItemResponseRestDTO;
use crate::endpoint::proof::dto::ProofListItemResponseRestDTO;
use crate::endpoint::proof_schema::dto::GetProofSchemaListItemResponseRestDTO;
use crate::endpoint::trust_anchor::dto::ListTrustAnchorsResponseItemRestDTO;
use crate::endpoint::trust_entity::dto::ListTrustEntitiesResponseItemRestDTO;

#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GetListResponseRestDTO<T>
where
    T: Clone + fmt::Debug + Serialize,
{
    pub values: Vec<T>,
    pub total_pages: u64,
    pub total_items: u64,
}

pub type GetProofsResponseRestDTO = GetListResponseRestDTO<ProofListItemResponseRestDTO>;
pub type GetCredentialSchemasResponseDTO =
    GetListResponseRestDTO<CredentialSchemaListItemResponseRestDTO>;
pub type GetDidsResponseRestDTO = GetListResponseRestDTO<DidListItemResponseRestDTO>;
pub type GetCredentialsResponseDTO = GetListResponseRestDTO<CredentialListItemResponseRestDTO>;
pub type GetProofSchemaListResponseRestDTO =
    GetListResponseRestDTO<GetProofSchemaListItemResponseRestDTO>;
pub type GetKeyListResponseRestDTO = GetListResponseRestDTO<KeyListItemResponseRestDTO>;
pub type GetHistoryListResponseRestDTO = GetListResponseRestDTO<HistoryResponseRestDTO>;
pub type GetTrustAnchorListResponseRestDTO =
    GetListResponseRestDTO<ListTrustAnchorsResponseItemRestDTO>;
pub type GetTrustEntityListResponseRestDTO =
    GetListResponseRestDTO<ListTrustEntitiesResponseItemRestDTO>;

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema)]
pub struct NoIncludesSupported {}

impl From<NoIncludesSupported> for one_core::model::list_query::NoInclude {
    fn from(_: NoIncludesSupported) -> Self {
        Self {}
    }
}

#[derive(Clone, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ListQueryParamsRest<Filter, SortColumn, Include = NoIncludesSupported> {
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

impl<T> From<T> for EntityResponseRestDTO
where
    T: Into<Uuid>,
{
    fn from(id: T) -> Self {
        EntityResponseRestDTO { id: id.into() }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[from("one_core::model::common::EntityShareResponseDTO")]
#[serde(rename_all = "camelCase")]
pub struct EntityShareResponseRestDTO {
    pub url: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub enum Boolean {
    True,
    False,
}

impl From<Boolean> for bool {
    fn from(boolean: Boolean) -> Self {
        matches!(boolean, Boolean::True)
    }
}
