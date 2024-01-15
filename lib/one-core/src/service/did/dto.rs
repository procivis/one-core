use dto_mapper::From;
use serde::Deserialize;
use shared_types::{DidId, DidValue};
use time::OffsetDateTime;

use crate::{
    model::{
        common::{GetListQueryParams, GetListResponse},
        did::{Did, DidType, SortableDidColumn},
        key::KeyId,
        organisation::OrganisationId,
    },
    service::key::dto::KeyListItemResponseDTO,
};

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
    pub keys: DidResponseKeysDTO,
    pub deactivated: bool,
}

#[derive(Clone, Debug)]
pub struct DidResponseKeysDTO {
    pub authentication: Vec<KeyListItemResponseDTO>,
    pub assertion: Vec<KeyListItemResponseDTO>,
    pub key_agreement: Vec<KeyListItemResponseDTO>,
    pub capability_invocation: Vec<KeyListItemResponseDTO>,
    pub capability_delegation: Vec<KeyListItemResponseDTO>,
}

#[derive(Clone, Debug, Deserialize, From)]
#[serde(rename_all = "camelCase")]
#[convert(from = "Did")]
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
    pub did_type: DidType,
    pub keys: CreateDidRequestKeysDTO,
    pub params: Option<serde_json::Value>,
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

#[derive(Clone, Debug)]
pub struct DidPatchRequestDTO {
    pub deactivated: Option<bool>,
}

#[derive(Clone, Debug)]
pub struct DidWebResponseDTO {
    pub context: Vec<String>,
    pub id: DidValue,
    pub verification_method: Vec<DidWebVerificationMethodResponseDTO>,
    pub authentication: Vec<String>,
    pub assertion_method: Vec<String>,
    pub key_agreement: Vec<String>,
    pub capability_invocation: Vec<String>,
    pub capability_delegation: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct DidWebVerificationMethodResponseDTO {
    pub id: String,
    pub r#type: String,
    pub controller: DidValue,
    pub public_key_jwk: PublicKeyJwkResponseDTO,
}

#[derive(Clone, Debug, Default)]
pub struct PublicKeyJwkResponseDTO {
    pub kty: String,
    pub crv: Option<String>,
    pub alg: Option<String>,
    pub x: String,
    pub y: Option<String>,
}
