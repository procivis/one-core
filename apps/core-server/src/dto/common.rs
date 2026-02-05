use std::collections::HashMap;
use std::fmt;

use one_dto_mapper::Into;
use serde::{Deserialize, Deserializer, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::endpoint::credential::dto::CredentialListItemResponseRestDTO;
use crate::endpoint::credential_schema::dto::CredentialSchemaListItemResponseRestDTO;
use crate::endpoint::did::dto::DidListItemResponseRestDTO;
use crate::endpoint::history::dto::HistoryResponseRestDTO;
use crate::endpoint::key::dto::KeyListItemResponseRestDTO;
use crate::endpoint::organisation::dto::OrganisationListItemResponseRestDTO;
use crate::endpoint::proof::dto::ProofListItemResponseRestDTO;
use crate::endpoint::proof_schema::dto::GetProofSchemaListItemResponseRestDTO;
use crate::endpoint::trust_anchor::dto::ListTrustAnchorsResponseItemRestDTO;
use crate::endpoint::trust_entity::dto::ListTrustEntitiesResponseItemRestDTO;

#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GetListResponseRestDTO<T>
where
    T: fmt::Debug + Serialize,
{
    pub values: Vec<T>,
    pub total_pages: u64,
    pub total_items: u64,
}

pub(crate) type GetProofsResponseRestDTO = GetListResponseRestDTO<ProofListItemResponseRestDTO>;
pub(crate) type GetCredentialSchemasResponseDTO =
    GetListResponseRestDTO<CredentialSchemaListItemResponseRestDTO>;
pub(crate) type GetDidsResponseRestDTO = GetListResponseRestDTO<DidListItemResponseRestDTO>;
pub(crate) type GetCredentialsResponseDTO =
    GetListResponseRestDTO<CredentialListItemResponseRestDTO>;
pub(crate) type GetProofSchemaListResponseRestDTO =
    GetListResponseRestDTO<GetProofSchemaListItemResponseRestDTO>;
pub(crate) type GetKeyListResponseRestDTO = GetListResponseRestDTO<KeyListItemResponseRestDTO>;
pub(crate) type GetHistoryListResponseRestDTO = GetListResponseRestDTO<HistoryResponseRestDTO>;
pub(crate) type GetOrganisationListResponseRestDTO =
    GetListResponseRestDTO<OrganisationListItemResponseRestDTO>;
pub(crate) type GetTrustAnchorListResponseRestDTO =
    GetListResponseRestDTO<ListTrustAnchorsResponseItemRestDTO>;
pub(crate) type GetTrustEntityListResponseRestDTO =
    GetListResponseRestDTO<ListTrustEntitiesResponseItemRestDTO>;

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema)]
pub(crate) struct NoIncludesSupported {}

impl From<NoIncludesSupported> for one_core::model::list_query::NoInclude {
    fn from(_: NoIncludesSupported) -> Self {
        Self {}
    }
}

#[derive(Clone, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ListQueryParamsRest<Filter, SortColumn, Include = NoIncludesSupported> {
    // pagination
    pub page: u32,
    pub page_size: PageSize<1000>,

    // sorting
    pub sort: Option<SortColumn>,
    pub sort_direction: Option<SortDirection>,

    // filtering
    #[serde(flatten)]
    pub filter: Filter,

    pub include: Option<Vec<Include>>,

    // "deny_unknown_fields" cannot be used with "flatten", replaced with custom logic
    #[serde(flatten, deserialize_with = "refuse_unknown_params")]
    _refuse_unknown_params: (),
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, ToSchema, Into)]
#[into("one_core::model::common::SortDirection")]
pub(crate) enum SortDirection {
    #[serde(rename = "ASC")]
    Ascending,
    #[serde(rename = "DESC")]
    Descending,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, ToSchema, Into)]
#[into("one_core::model::common::ExactColumn")]
pub(crate) enum ExactColumn {
    #[serde(rename = "name")]
    Name,
}

#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EntityResponseRestDTO {
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) enum Boolean {
    False,
    True,
}

impl From<Boolean> for bool {
    fn from(boolean: Boolean) -> Self {
        matches!(boolean, Boolean::True)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct PageSize<const MAX: u32>(u32);

impl<const MAX: u32> PageSize<MAX> {
    pub fn inner(&self) -> u32 {
        self.0
    }
}

impl<'de, const MAX: u32> Deserialize<'de> for PageSize<MAX> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let size = u32::deserialize(deserializer)?;

        if size > MAX {
            return Err(serde::de::Error::custom(format!(
                "expected maximum pageSize of {MAX} got {size}"
            )));
        }

        Ok(PageSize(size))
    }
}

fn refuse_unknown_params<'de, D>(deserializer: D) -> Result<(), D::Error>
where
    D: Deserializer<'de>,
{
    let unknown_params = HashMap::<String, serde_json::Value>::deserialize(deserializer)?;
    if unknown_params.is_empty() {
        return Ok(());
    }

    let extra_keys: Vec<_> = unknown_params.keys().map(|k| k.as_str()).collect();
    Err(serde::de::Error::custom(format!(
        "Unknown query params: {}",
        extra_keys.join(", ")
    )))
}

#[cfg(test)]
mod test {
    use serde_json::json;
    use similar_asserts::assert_eq;

    use super::ListQueryParamsRest;

    #[test]
    fn test_page_size_deserialization_is_limited_to_1000() {
        let query: ListQueryParamsRest<(), ()> = serde_json::from_value(json!({
            "page": 0,
            "pageSize": 1000
        }))
        .unwrap();

        assert_eq!(0, query.page);
        assert_eq!(1000, query.page_size.inner());

        let result: serde_json::Result<ListQueryParamsRest<(), ()>> =
            serde_json::from_value(json!({
                "page": 0,
                "pageSize": 1001
            }));

        assert_eq!(
            "expected maximum pageSize of 1000 got 1001",
            result.err().unwrap().to_string()
        )
    }
}
