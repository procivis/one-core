use one_dto_mapper::Into;
use shared_types::{
    CertificateId, IdentifierId, KeyId, OrganisationId, TrustEntryId, TrustListPublicationId,
    TrustListPublisherId,
};
use time::OffsetDateTime;

use crate::model::common::GetListResponse;
use crate::model::trust_entry::TrustEntryStateEnum;
use crate::model::trust_list_role::TrustListRoleEnum;
use crate::provider::trust_list_publisher::etsi_lote::LoteContentType;
use crate::service::identifier::dto::GetIdentifierListItemResponseDTO;

#[derive(Clone, Debug, PartialEq, Into)]
#[into(LoteContentType)]
pub enum TrustListContentTypeDTO {
    Xml,
    Jwt,
}

#[derive(Clone, Debug)]
pub struct CreateTrustListPublicationRequestDTO {
    pub r#type: TrustListPublisherId,
    pub organisation_id: OrganisationId,
    pub identifier_id: IdentifierId,
    pub key_id: Option<KeyId>,
    pub certificate_id: Option<CertificateId>,
    pub name: String,
    pub role: TrustListRoleEnum,
    pub params: Option<serde_json::Value>,
}

#[derive(Clone, Debug)]
pub struct CreateTrustEntryRequestDTO {
    pub identifier_id: IdentifierId,
    pub params: Option<serde_json::Value>,
}

#[derive(Clone, Debug)]
pub struct UpdateTrustEntryRequestDTO {
    pub state: Option<TrustEntryStateEnum>,
    pub params: Option<serde_json::Value>,
}

#[derive(Debug)]
pub struct GetTrustListPublicationResponseDTO {
    pub id: TrustListPublicationId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub deleted_at: Option<OffsetDateTime>,
    pub name: String,
    pub identifier: GetIdentifierListItemResponseDTO,
    pub r#type: TrustListPublisherId,
    pub role: TrustListRoleEnum,
    pub content: Option<Vec<u8>>,
    pub sequence_number: u32,
    pub metadata: Vec<u8>,
    pub organisation_id: OrganisationId,
}

#[derive(Debug, Clone)]
pub struct TrustListPublicationListItemResponseDTO {
    pub id: TrustListPublicationId,
    pub name: String,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub organisation_id: OrganisationId,
    pub r#type: TrustListPublisherId,
    pub role: TrustListRoleEnum,
    pub deleted_at: Option<OffsetDateTime>,
}

pub type GetTrustListPublicationListResponseDTO =
    GetListResponse<TrustListPublicationListItemResponseDTO>;

#[derive(Debug, Clone)]
pub struct TrustEntryListItemResponseDTO {
    pub id: TrustEntryId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub state: TrustEntryStateEnum,
    pub identifier: GetIdentifierListItemResponseDTO,
    pub params: Vec<u8>,
}

pub type GetTrustEntryListResponseDTO = GetListResponse<TrustEntryListItemResponseDTO>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExactTrustListFilterColumn {
    Name,
}

#[derive(Clone, Debug)]
pub struct TrustListPublicationFilterParamsDTO {
    pub name: Option<String>,
    pub exact: Option<Vec<ExactTrustListFilterColumn>>,
    pub organisation_id: OrganisationId,
    pub ids: Option<Vec<TrustListPublicationId>>,
    pub types: Option<Vec<TrustListPublisherId>>,
    pub roles: Option<Vec<TrustListRoleEnum>>,
    pub created_date_after: Option<OffsetDateTime>,
    pub created_date_before: Option<OffsetDateTime>,
    pub last_modified_after: Option<OffsetDateTime>,
    pub last_modified_before: Option<OffsetDateTime>,
}

#[derive(Clone, Debug)]
pub struct TrustEntryFilterParamsDTO {
    pub ids: Option<Vec<TrustEntryId>>,
    pub identifier_ids: Option<Vec<IdentifierId>>,
    pub states: Option<Vec<TrustEntryStateEnum>>,
    pub created_date_after: Option<OffsetDateTime>,
    pub created_date_before: Option<OffsetDateTime>,
    pub last_modified_after: Option<OffsetDateTime>,
    pub last_modified_before: Option<OffsetDateTime>,
}
