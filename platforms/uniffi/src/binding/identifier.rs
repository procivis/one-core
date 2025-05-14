use std::collections::HashMap;

use one_core::model::identifier::{
    IdentifierFilterValue, IdentifierListQuery, IdentifierState, IdentifierType,
    SortableIdentifierColumn,
};
use one_core::model::list_filter::{ListFilterValue, StringMatch, StringMatchType};
use one_core::model::list_query::{ListPagination, ListSorting};
use one_core::service::certificate::dto::CreateCertificateRequestDTO;
use one_core::service::identifier::dto::{
    CreateIdentifierRequestDTO, GetIdentifierListItemResponseDTO, GetIdentifierListResponseDTO,
};
use one_dto_mapper::{
    From, Into, TryInto, convert_inner, try_convert_inner, try_convert_inner_of_inner,
};

use super::common::SortDirection;
use super::did::KeyRoleBindingEnum;
use crate::OneCoreBinding;
use crate::error::{BindingError, ErrorResponseBindingDTO};
use crate::utils::{TimestampFormat, from_id_opt, into_id, into_id_opt};

#[uniffi::export(async_runtime = "tokio")]
impl OneCoreBinding {
    #[uniffi::method]
    pub async fn create_identifier(
        &self,
        request: CreateIdentifierRequestBindingDTO,
    ) -> Result<String, BindingError> {
        let core = self.use_core().await?;
        Ok(core
            .identifier_service
            .create_identifier(request.try_into()?)
            .await?
            .to_string())
    }

    #[uniffi::method]
    pub async fn list_identifiers(
        &self,
        query: IdentifierListQueryBindingDTO,
    ) -> Result<GetIdentifierListBindingDTO, BindingError> {
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
                IdentifierFilterValue::OrganisationId(into_id(&query.organisation_id)?).condition();

            let name = query.name.map(|name| {
                IdentifierFilterValue::Name(StringMatch {
                    r#match: get_string_match_type(ExactIdentifierFilterColumnBindingEnum::Name),
                    value: name,
                })
            });

            let r#type = query
                .r#type
                .map(|r#type| IdentifierFilterValue::Type(r#type.into()));

            let state = query
                .state
                .map(|state| IdentifierFilterValue::State(state.into()));

            let did_methods = query.did_methods.map(IdentifierFilterValue::DidMethods);

            let is_remote = query.is_remote.map(IdentifierFilterValue::IsRemote);

            let key_algorithms = query
                .key_algorithms
                .map(IdentifierFilterValue::KeyAlgorithms);

            let key_roles = query.key_roles.map(|roles| {
                IdentifierFilterValue::KeyRoles(roles.into_iter().map(Into::into).collect())
            });

            let key_storages = query.key_storages.map(IdentifierFilterValue::KeyStorages);

            organisation
                & name
                & r#type
                & state
                & did_methods
                & is_remote
                & key_algorithms
                & key_roles
                & key_storages
        };

        let sorting = query.sort.map(|sort| ListSorting {
            column: sort.into(),
            direction: query.sort_direction.map(Into::into),
        });

        let query = IdentifierListQuery {
            pagination: Some(ListPagination {
                page: query.page,
                page_size: query.page_size,
            }),
            sorting,
            filtering: Some(condition),
            include: None,
        };

        Ok(core
            .identifier_service
            .get_identifier_list(query)
            .await?
            .into())
    }

    #[uniffi::method]
    pub async fn delete_identifier(&self, id: String) -> Result<(), BindingError> {
        let core = self.use_core().await?;
        let id = into_id(&id)?;
        Ok(core.identifier_service.delete_identifier(&id).await?)
    }
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(GetIdentifierListResponseDTO)]
pub struct GetIdentifierListBindingDTO {
    #[from(with_fn = convert_inner)]
    pub values: Vec<GetIdentifierListItemBindingDTO>,
    pub total_pages: u64,
    pub total_items: u64,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(GetIdentifierListItemResponseDTO)]
pub struct GetIdentifierListItemBindingDTO {
    #[from(with_fn_ref = "ToString::to_string")]
    pub id: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub created_date: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub last_modified: String,
    pub name: String,
    pub r#type: IdentifierTypeBindingEnum,
    pub is_remote: bool,
    pub state: IdentifierStateBindingEnum,
    #[from(with_fn = "from_id_opt")]
    pub organisation_id: Option<String>,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct IdentifierListQueryBindingDTO {
    pub page: u32,
    pub page_size: u32,

    pub sort: Option<SortableIdentifierColumnBindingEnum>,
    pub sort_direction: Option<SortDirection>,

    pub organisation_id: String,
    pub name: Option<String>,
    pub r#type: Option<IdentifierTypeBindingEnum>,
    pub state: Option<IdentifierStateBindingEnum>,
    pub exact: Option<Vec<ExactIdentifierFilterColumnBindingEnum>>,
    pub did_methods: Option<Vec<String>>,
    pub is_remote: Option<bool>,
    pub key_algorithms: Option<Vec<String>>,
    pub key_roles: Option<Vec<KeyRoleBindingEnum>>,
    pub key_storages: Option<Vec<String>>,
}

#[derive(Clone, Debug, Into, uniffi::Enum)]
#[into(SortableIdentifierColumn)]
pub enum SortableIdentifierColumnBindingEnum {
    Name,
    CreatedDate,
    Type,
    State,
}

#[derive(Clone, Debug, PartialEq, uniffi::Enum)]
pub enum ExactIdentifierFilterColumnBindingEnum {
    Name,
}

#[derive(Clone, Debug, Into, From, uniffi::Enum)]
#[into(IdentifierType)]
#[from(IdentifierType)]
pub enum IdentifierTypeBindingEnum {
    Key,
    Did,
    Certificate,
}

#[derive(Clone, Debug, Into, From, uniffi::Enum)]
#[into(IdentifierState)]
#[from(IdentifierState)]
pub enum IdentifierStateBindingEnum {
    Active,
    Deactivated,
}

#[derive(Clone, Debug, TryInto, uniffi::Record)]
#[try_into(T = CreateIdentifierRequestDTO, Error = ErrorResponseBindingDTO)]
pub struct CreateIdentifierRequestBindingDTO {
    #[try_into(with_fn_ref = "into_id")]
    pub organisation_id: String,
    #[try_into(infallible)]
    pub name: String,
    #[try_into(with_fn = "into_id_opt")]
    pub key_id: Option<String>,
    #[try_into(with_fn = "try_convert_inner")]
    pub did: Option<CreateIdentifierDidRequestBindingDTO>,
    #[try_into(with_fn = "try_convert_inner_of_inner")]
    pub certificates: Option<Vec<CreateCertificateRequestBindingDTO>>,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct CreateIdentifierDidRequestBindingDTO {
    pub name: Option<String>,
    pub method: String,
    pub keys: super::did::DidRequestKeysBindingDTO,
    pub params: HashMap<String, String>,
}

#[derive(Clone, Debug, TryInto, uniffi::Record)]
#[try_into(T = CreateCertificateRequestDTO, Error = ErrorResponseBindingDTO)]
pub struct CreateCertificateRequestBindingDTO {
    #[try_into(infallible)]
    pub name: Option<String>,
    #[try_into(infallible)]
    pub chain: String,
    #[try_into(with_fn_ref = "into_id")]
    pub key_id: String,
}
