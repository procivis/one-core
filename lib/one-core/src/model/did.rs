use time::OffsetDateTime;
use uuid::Uuid;

use super::{
    common::{GetListQueryParams, GetListResponse},
    organisation::OrganisationId,
};

pub type DidId = Uuid;
pub type DidValue = String;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DidType {
    Remote,
    Local,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Did {
    pub id: DidId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub organisation_id: OrganisationId,
    pub did: DidValue,
    pub did_type: DidType,
    pub did_method: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SortableDidColumn {
    Name,
    CreatedDate,
}

pub type GetDidList = GetListResponse<Did>;
pub type GetDidQuery = GetListQueryParams<SortableDidColumn>;
