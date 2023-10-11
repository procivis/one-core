use time::OffsetDateTime;
use uuid::Uuid;

use crate::model::{
    common::{GetListQueryParams, GetListResponse},
    did::{DidType, SortableDidColumn},
    key::KeyId,
    organisation::OrganisationId,
};

pub type DidId = Uuid;
pub type DidValue = String;

#[derive(Clone, Debug)]
pub struct DidResponseDTO {
    pub id: DidId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub organisation_id: OrganisationId,
    pub did: DidValue,
    pub did_type: DidType,
    pub did_method: String,
}

#[derive(Clone, Debug)]
pub struct DidListItemResponseDTO {
    pub id: DidId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub did: DidValue,
    pub did_type: DidType,
    pub did_method: String,
}

pub type GetDidListResponseDTO = GetListResponse<DidListItemResponseDTO>;
pub type GetDidQueryDTO = GetListQueryParams<SortableDidColumn>;

#[derive(Clone, Debug)]
pub struct CreateDidRequestDTO {
    pub name: String,
    pub organisation_id: OrganisationId,
    pub did: String,
    pub did_method: String,
    pub did_type: DidType,
    pub keys: CreateDidRequestKeysDTO,
}

#[derive(Clone, Debug)]
pub struct CreateDidRequestKeysDTO {
    pub authentication: Vec<KeyId>,
    pub assertion: Vec<KeyId>,
    pub key_agreement: Vec<KeyId>,
    pub capability_invocation: Vec<KeyId>,
    pub capability_delegation: Vec<KeyId>,
}

#[derive(Clone, Debug)]
pub struct CreateDidResponseDTO {
    pub id: String,
}
