use crate::endpoint::credential_schema::dto::SortableCredentialSchemaColumnRestEnum;
use crate::{
    dto::common::{GetListQueryParams, SortDirection},
    endpoint::did::dto::{DidType, SortableDidColumnRestDTO},
};
use utoipa::ToSchema;

impl<T, K> From<GetListQueryParams<T>> for one_core::model::common::GetListQueryParams<K>
where
    K: From<T>,
    T: for<'a> ToSchema<'a>,
{
    fn from(value: GetListQueryParams<T>) -> Self {
        Self {
            page: value.page,
            page_size: value.page_size,
            sort: value.sort.map(|sort| sort.into()),
            sort_direction: value.sort_direction.map(|dir| dir.into()),
            name: value.name,
            organisation_id: value.organisation_id,
        }
    }
}

impl From<SortDirection> for one_core::model::common::SortDirection {
    fn from(value: SortDirection) -> Self {
        match value {
            SortDirection::Ascending => one_core::model::common::SortDirection::Ascending,
            SortDirection::Descending => one_core::model::common::SortDirection::Descending,
        }
    }
}

impl From<DidType> for one_core::model::did::DidType {
    fn from(value: DidType) -> Self {
        match value {
            DidType::Remote => one_core::model::did::DidType::Remote,
            DidType::Local => one_core::model::did::DidType::Local,
        }
    }
}

impl From<one_core::model::did::DidType> for DidType {
    fn from(value: one_core::model::did::DidType) -> Self {
        match value {
            one_core::model::did::DidType::Remote => DidType::Remote,
            one_core::model::did::DidType::Local => DidType::Local,
        }
    }
}

impl From<SortableDidColumnRestDTO> for one_core::model::did::SortableDidColumn {
    fn from(value: SortableDidColumnRestDTO) -> Self {
        match value {
            SortableDidColumnRestDTO::Name => one_core::model::did::SortableDidColumn::Name,
            SortableDidColumnRestDTO::CreatedDate => {
                one_core::model::did::SortableDidColumn::CreatedDate
            }
        }
    }
}

impl From<SortableCredentialSchemaColumnRestEnum>
    for one_core::model::credential_schema::SortableCredentialSchemaColumn
{
    fn from(value: SortableCredentialSchemaColumnRestEnum) -> Self {
        match value {
            SortableCredentialSchemaColumnRestEnum::Name => {
                one_core::model::credential_schema::SortableCredentialSchemaColumn::Name
            }
            SortableCredentialSchemaColumnRestEnum::Format => {
                one_core::model::credential_schema::SortableCredentialSchemaColumn::Format
            }
            SortableCredentialSchemaColumnRestEnum::CreatedDate => {
                one_core::model::credential_schema::SortableCredentialSchemaColumn::CreatedDate
            }
        }
    }
}
