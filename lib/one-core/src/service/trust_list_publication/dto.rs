use one_dto_mapper::{From, TryFrom};
use shared_types::{
    CertificateId, IdentifierId, KeyId, OrganisationId, TrustEntryId, TrustListPublicationId,
    TrustListPublisherId,
};
use time::OffsetDateTime;

use crate::model::common::GetListResponse;
use crate::model::identifier::Identifier;
use crate::model::trust_entry::{TrustEntry, TrustEntryStatusEnum};
use crate::model::trust_list_publication::{TrustListPublication, TrustListPublicationRoleEnum};
use crate::service::identifier::dto::GetIdentifierListItemResponseDTO;
use crate::service::trust_list_publication::error::TrustListPublicationServiceError;

#[derive(Clone, Debug)]
pub struct CreateTrustListPublicationRequestDTO {
    pub r#type: TrustListPublisherId,
    pub organisation_id: OrganisationId,
    pub identifier_id: IdentifierId,
    pub key_id: Option<KeyId>,
    pub certificate_id: Option<CertificateId>,
    pub name: String,
    pub role: TrustListPublicationRoleEnum,
    pub params: Option<serde_json::Value>,
}

#[derive(Clone, Debug)]
pub struct CreateTrustEntryRequestDTO {
    pub identifier_id: IdentifierId,
    pub params: Option<serde_json::Value>,
}

#[derive(Clone, Debug)]
pub struct UpdateTrustEntryRequestDTO {
    pub status: Option<TrustEntryStatusEnum>,
    pub params: Option<serde_json::Value>,
}

#[derive(Debug, TryFrom)]
#[try_from(T = TrustListPublication, Error = TrustListPublicationServiceError)]
pub struct GetTrustListPublicationResponseDTO {
    #[try_from(infallible)]
    pub id: TrustListPublicationId,
    #[try_from(infallible)]
    pub created_date: OffsetDateTime,
    #[try_from(infallible)]
    pub last_modified: OffsetDateTime,
    #[try_from(infallible)]
    pub deleted_at: Option<OffsetDateTime>,
    #[try_from(infallible)]
    pub name: String,
    #[try_from(with_fn = "map_identifier")]
    pub identifier: GetIdentifierListItemResponseDTO,
    #[try_from(infallible)]
    pub r#type: TrustListPublisherId,
    #[try_from(infallible)]
    pub role: TrustListPublicationRoleEnum,
    #[try_from(with_fn = "map_content_option")]
    pub content: Option<serde_json::Value>,
    #[try_from(infallible)]
    pub sequence_number: i64,
    #[try_from(with_fn = "map_content")]
    pub metadata: serde_json::Value,
    #[try_from(infallible)]
    pub organisation_id: OrganisationId,
}

#[derive(Debug, Clone, From)]
#[from(TrustListPublication)]
pub struct TrustListPublicationListItemResponseDTO {
    pub id: TrustListPublicationId,
    pub name: String,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub organisation_id: OrganisationId,
    pub r#type: TrustListPublisherId,
    pub role: TrustListPublicationRoleEnum,
    pub deleted_at: Option<OffsetDateTime>,
}

pub type GetTrustListPublicationListResponseDTO =
    GetListResponse<TrustListPublicationListItemResponseDTO>;

#[derive(Debug, Clone, TryFrom)]
#[try_from(T = TrustEntry, Error = TrustListPublicationServiceError)]
pub struct TrustEntryListItemResponseDTO {
    #[try_from(infallible)]
    pub id: TrustEntryId,
    #[try_from(infallible)]
    pub created_date: OffsetDateTime,
    #[try_from(infallible)]
    pub last_modified: OffsetDateTime,
    #[try_from(infallible)]
    pub status: TrustEntryStatusEnum,
    #[try_from(with_fn = "map_identifier")]
    pub identifier: GetIdentifierListItemResponseDTO,
    #[try_from(rename = "metadata", infallible)]
    pub params: serde_json::Value,
}

pub type GetTrustEntryListResponseDTO = GetListResponse<TrustEntryListItemResponseDTO>;

fn map_content(content: Vec<u8>) -> Result<serde_json::Value, TrustListPublicationServiceError> {
    serde_json::from_slice(&content)
        .map_err(TrustListPublicationServiceError::ContentDeserialization)
}

fn map_content_option(
    content: Option<Vec<u8>>,
) -> Result<Option<serde_json::Value>, TrustListPublicationServiceError> {
    match content {
        None => Ok(None),
        Some(content) => Ok(Some(map_content(content)?)),
    }
}

fn map_identifier(
    identifier: Option<Identifier>,
) -> Result<GetIdentifierListItemResponseDTO, TrustListPublicationServiceError> {
    match identifier {
        None => Err(TrustListPublicationServiceError::MappingError(
            "identifier is None".to_string(),
        )),
        Some(identifier) => Ok(GetIdentifierListItemResponseDTO::from(identifier)),
    }
}
