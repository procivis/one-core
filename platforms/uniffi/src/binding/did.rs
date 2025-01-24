use std::collections::HashMap;

use one_core::model::did::{DidFilterValue, DidListQuery, DidType, KeyRole, SortableDidColumn};
use one_core::model::list_filter::{ListFilterValue, StringMatch, StringMatchType};
use one_core::model::list_query::{ListPagination, ListSorting};
use one_core::service::did::dto::{DidListItemResponseDTO, GetDidListResponseDTO};
use one_dto_mapper::{convert_inner, From, Into};

use super::common::SortDirection;
use crate::error::BindingError;
use crate::utils::{into_id, TimestampFormat};
use crate::OneCoreBinding;

#[uniffi::export(async_runtime = "tokio")]
impl OneCoreBinding {
    #[uniffi::method]
    pub async fn create_did(&self, request: DidRequestBindingDTO) -> Result<String, BindingError> {
        let core = self.use_core().await?;
        Ok(core
            .did_service
            .create_did(request.try_into()?)
            .await?
            .to_string())
    }

    #[uniffi::method]
    pub async fn get_dids(
        &self,
        query: DidListQueryBindingDTO,
    ) -> Result<DidListBindingDTO, BindingError> {
        let core = self.use_core().await?;

        let condition = {
            let exact = query.exact.unwrap_or_default();
            let get_string_match_type = |column| {
                if exact.contains(&column) {
                    StringMatchType::Equals
                } else {
                    StringMatchType::StartsWith
                }
            };

            let organisation =
                DidFilterValue::OrganisationId(into_id(&query.organisation_id)?).condition();

            let name = query.name.map(|name| {
                DidFilterValue::Name(StringMatch {
                    r#match: get_string_match_type(ExactDidFilterColumnBindingEnum::Name),
                    value: name,
                })
            });

            let did_value = query.did.map(|did| {
                DidFilterValue::Name(StringMatch {
                    r#match: get_string_match_type(ExactDidFilterColumnBindingEnum::Did),
                    value: did,
                })
            });

            let r#type = query
                .r#type
                .map(|r#type| DidFilterValue::Type(r#type.into()));

            let deactivated = query.deactivated.map(DidFilterValue::Deactivated);

            let key_algorithms = query.key_algorithms.map(DidFilterValue::KeyAlgorithms);

            let key_roles = query.key_roles.map(|values| {
                DidFilterValue::KeyRoles(values.into_iter().map(|role| role.into()).collect())
            });

            let key_storages = query.key_storages.map(DidFilterValue::KeyStorages);

            let key_ids = match query.key_ids {
                None => None,
                Some(key_ids) => {
                    let ids = key_ids
                        .iter()
                        .map(|id| into_id(id))
                        .collect::<Result<_, _>>()?;
                    Some(DidFilterValue::KeyIds(ids))
                }
            };

            let did_methods = query.did_methods.map(DidFilterValue::DidMethods);

            organisation
                & name
                & did_value
                & r#type
                & deactivated
                & key_algorithms
                & key_roles
                & key_storages
                & key_ids
                & did_methods
        };

        Ok(core
            .did_service
            .get_did_list(DidListQuery {
                pagination: Some(ListPagination {
                    page: query.page,
                    page_size: query.page_size,
                }),
                sorting: query.sort.map(|column| ListSorting {
                    column: column.into(),
                    direction: convert_inner(query.sort_direction),
                }),
                filtering: Some(condition),
                include: None,
            })
            .await?
            .into())
    }
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(DidListItemResponseDTO)]
pub struct DidListItemBindingDTO {
    #[from(with_fn_ref = "ToString::to_string")]
    pub id: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub created_date: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub last_modified: String,
    pub name: String,
    #[from(with_fn_ref = "ToString::to_string")]
    pub did: String,
    pub did_type: DidTypeBindingEnum,
    pub did_method: String,
    pub deactivated: bool,
}

#[derive(Clone, Debug, Into, From, uniffi::Enum)]
#[into(DidType)]
#[from(DidType)]
pub enum DidTypeBindingEnum {
    Local,
    Remote,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct DidListQueryBindingDTO {
    pub page: u32,
    pub page_size: u32,

    pub sort: Option<SortableDidColumnBindingEnum>,
    pub sort_direction: Option<SortDirection>,

    pub organisation_id: String,
    pub name: Option<String>,
    pub did: Option<String>,
    pub r#type: Option<DidTypeBindingEnum>,
    pub deactivated: Option<bool>,
    pub exact: Option<Vec<ExactDidFilterColumnBindingEnum>>,
    pub key_algorithms: Option<Vec<String>>,
    pub key_roles: Option<Vec<KeyRoleBindingEnum>>,
    pub key_storages: Option<Vec<String>>,
    pub key_ids: Option<Vec<String>>,
    pub did_methods: Option<Vec<String>>,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(GetDidListResponseDTO)]
pub struct DidListBindingDTO {
    #[from(with_fn = convert_inner)]
    pub values: Vec<DidListItemBindingDTO>,
    pub total_pages: u64,
    pub total_items: u64,
}

#[derive(Clone, Debug, Into, uniffi::Enum)]
#[into(SortableDidColumn)]
pub enum SortableDidColumnBindingEnum {
    Name,
    CreatedDate,
    Method,
    Type,
    Did,
    Deactivated,
}

#[derive(Clone, Debug, PartialEq, uniffi::Enum)]
pub enum ExactDidFilterColumnBindingEnum {
    Name,
    Did,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct DidRequestBindingDTO {
    pub organisation_id: String,
    pub name: String,
    pub did_method: String,
    pub keys: DidRequestKeysBindingDTO,
    pub params: HashMap<String, String>,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct DidRequestKeysBindingDTO {
    pub authentication: Vec<String>,
    pub assertion_method: Vec<String>,
    pub key_agreement: Vec<String>,
    pub capability_invocation: Vec<String>,
    pub capability_delegation: Vec<String>,
}

#[derive(Clone, Debug, Into, uniffi::Enum)]
#[into(KeyRole)]
pub enum KeyRoleBindingEnum {
    Authentication,
    AssertionMethod,
    KeyAgreement,
    CapabilityInvocation,
    CapabilityDelegation,
}
