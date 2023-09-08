use one_core::{model::common::SortDirection, repository::data_provider::GetDidDetailsResponse};
use sea_orm::Order;

use super::entity::did;

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
