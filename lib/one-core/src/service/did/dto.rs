use one_dto_mapper::From;
use serde::{Deserialize, Serialize};
use shared_types::{DidId, DidMethodId, DidValue, KeyId, OrganisationId};
use time::OffsetDateTime;

use crate::model::common::GetListResponse;
use crate::model::did::{Did, DidType, ExactDidFilterColumn, KeyRole};
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
    pub did_method: DidMethodId,
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
    pub did_method: DidMethodId,
    pub deactivated: bool,
}

pub type GetDidListResponseDTO = GetListResponse<DidListItemResponseDTO>;

#[derive(Clone, Debug)]
pub struct DidFilterParamsDTO {
    pub name: Option<String>,
    pub did: Option<String>,
    pub r#type: Option<DidType>,
    pub exact: Option<Vec<ExactDidFilterColumn>>,
    pub deactivated: Option<bool>,
    pub key_algorithms: Option<Vec<String>>,
    pub key_roles: Option<Vec<KeyRole>>,
    pub key_storages: Option<Vec<String>>,
    pub key_ids: Option<Vec<KeyId>>,
    pub did_methods: Option<Vec<DidMethodId>>,
    pub organisation_id: OrganisationId,
}

#[derive(Clone, Debug)]
pub struct CreateDidRequestDTO {
    pub name: String,
    pub organisation_id: OrganisationId,
    pub did_method: DidMethodId,
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
pub struct DidPatchRequestDTO {
    pub deactivated: Option<bool>,
}
