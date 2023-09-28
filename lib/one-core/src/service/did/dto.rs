use time::OffsetDateTime;
use uuid::Uuid;

use crate::model::{
    common::{GetListQueryParams, GetListResponse},
    did::{DidType, SortableDidColumn},
    organisation::OrganisationId,
};

pub type DidId = Uuid;
pub type DidValue = String;

#[derive(Clone, Debug)]
pub struct GetDidResponseDTO {
    pub id: DidId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub organisation_id: OrganisationId,
    pub did: DidValue,
    pub did_type: DidType,
    pub did_method: String,
}

pub type GetDidListResponseDTO = GetListResponse<GetDidResponseDTO>;
pub type GetDidQueryDTO = GetListQueryParams<SortableDidColumn>;

#[derive(Clone, Debug)]
pub struct CreateDidRequestDTO {
    pub name: String,
    pub organisation_id: OrganisationId,
    pub did: String,
    pub did_method: String,
    pub did_type: DidType,
}

#[derive(Clone, Debug)]
pub struct CreateDidResponseDTO {
    pub id: String,
}
