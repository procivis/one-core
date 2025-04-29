use one_dto_mapper::From;
use serde::{Deserialize, Serialize};
use shared_types::{DidId, DidValue, KeyId, OrganisationId};
use time::OffsetDateTime;

use crate::model::common::{GetListQueryParams, GetListResponse};
use crate::model::did::{Did, DidType, SortableDidColumn};
use crate::service::key::dto::KeyListItemResponseDTO;

#[derive(Clone, Debug)]
pub struct DidResponseDTO {
    pub id: DidId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub organisation_id: Option<OrganisationId>,
    pub did: DidValue,
    pub did_type: DidType,
    pub did_method: String,
    pub keys: DidResponseKeysDTO,
    pub deactivated: bool,
}

#[derive(Clone, Debug)]
pub struct DidResponseKeysDTO {
    pub authentication: Vec<KeyListItemResponseDTO>,
    pub assertion_method: Vec<KeyListItemResponseDTO>,
    pub key_agreement: Vec<KeyListItemResponseDTO>,
    pub capability_invocation: Vec<KeyListItemResponseDTO>,
    pub capability_delegation: Vec<KeyListItemResponseDTO>,
}

#[derive(Clone, Debug, Serialize, Deserialize, From)]
#[serde(rename_all = "camelCase")]
#[from(Did)]
pub struct DidListItemResponseDTO {
    pub id: DidId,
    #[serde(with = "time::serde::rfc3339")]
    pub created_date: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub did: DidValue,
    #[serde(rename = "type")]
    pub did_type: DidType,
    #[serde(rename = "method")]
    pub did_method: String,
    pub deactivated: bool,
}

pub type GetDidListResponseDTO = GetListResponse<DidListItemResponseDTO>;
pub type GetDidQueryDTO = GetListQueryParams<SortableDidColumn>;

#[derive(Clone, Debug)]
pub struct CreateDidRequestDTO {
    pub name: String,
    pub organisation_id: OrganisationId,
    pub did_method: String,
    pub keys: CreateDidRequestKeysDTO,
    pub params: Option<serde_json::Value>,
}

#[derive(Clone, Debug)]
pub struct CreateDidRequestKeysDTO {
    pub authentication: Vec<KeyId>,
    pub assertion_method: Vec<KeyId>,
    pub key_agreement: Vec<KeyId>,
    pub capability_invocation: Vec<KeyId>,
    pub capability_delegation: Vec<KeyId>,
}

#[derive(Clone, Debug)]
pub struct CreateDidResponseDTO {
    pub id: String,
}

#[derive(Clone, Debug)]
pub struct DidPatchRequestDTO {
    pub deactivated: Option<bool>,
}
