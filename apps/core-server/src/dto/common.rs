use std::fmt;

use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::{
    data_model::{DetailCredentialResponseDTO, ProofsDetailResponseDTO},
    endpoint::{
        credential_schema::dto::CredentialSchemaListValueResponseRestDTO,
        did::dto::GetDidResponseRestDTO, proof_schema::dto::GetProofSchemaListItemResponseRestDTO,
    },
};

#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
// ToSchema is properly generated thanks to that
#[aliases(
    GetProofsResponseDTO = GetListResponseRestDTO<ProofsDetailResponseDTO>,
    GetCredentialSchemaResponseDTO = GetListResponseRestDTO<CredentialSchemaListValueResponseRestDTO>,
    GetDidsResponseRestDTO = GetListResponseRestDTO<GetDidResponseRestDTO>,
    GetCredentialsResponseDTO = GetListResponseRestDTO<DetailCredentialResponseDTO>,
    GetProofSchemaListResponseRestDTO = GetListResponseRestDTO<GetProofSchemaListItemResponseRestDTO>)]
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
    pub organisation_id: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, ToSchema)]
pub enum SortDirection {
    #[serde(rename = "ASC")]
    Ascending,
    #[serde(rename = "DESC")]
    Descending,
}
