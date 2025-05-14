use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use shared_types::{IdentifierId, KeyId, OrganisationId};
use time::OffsetDateTime;

use crate::model::common::GetListResponse;
use crate::model::identifier::{IdentifierState, IdentifierType};
use crate::service::certificate::dto::{CertificateResponseDTO, CreateCertificateRequestDTO};
use crate::service::did::dto::{CreateDidRequestKeysDTO, DidResponseDTO};
use crate::service::key::dto::KeyResponseDTO;

#[derive(Clone, Debug)]
pub struct GetIdentifierResponseDTO {
    pub id: IdentifierId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub organisation_id: Option<OrganisationId>,
    pub r#type: IdentifierType,
    pub is_remote: bool,
    pub state: IdentifierState,
    pub did: Option<DidResponseDTO>,
    pub key: Option<KeyResponseDTO>,
    pub certificates: Option<Vec<CertificateResponseDTO>>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetIdentifierListItemResponseDTO {
    pub id: IdentifierId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub r#type: IdentifierType,
    pub is_remote: bool,
    pub state: IdentifierState,
    pub organisation_id: Option<OrganisationId>,
}

pub type GetIdentifierListResponseDTO = GetListResponse<GetIdentifierListItemResponseDTO>;

#[derive(Clone, Debug)]
pub struct CreateIdentifierRequestDTO {
    pub name: String,
    pub did: Option<CreateIdentifierDidRequestDTO>,
    pub key_id: Option<KeyId>,
    pub certificates: Option<Vec<CreateCertificateRequestDTO>>,
    pub organisation_id: OrganisationId,
}

#[derive(Clone, Debug)]
pub struct CreateIdentifierDidRequestDTO {
    pub name: Option<String>,
    pub method: String,
    pub keys: CreateDidRequestKeysDTO,
    pub params: Option<serde_json::Value>,
}
