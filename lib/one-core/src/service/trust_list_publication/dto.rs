use one_dto_mapper::{From, TryFrom};
use shared_types::{
    CertificateId, IdentifierId, KeyId, OrganisationId, TrustEntryId, TrustListPublicationId,
    TrustListPublisherId,
};
use time::OffsetDateTime;

use crate::model::common::GetListResponse;
use crate::model::identifier::Identifier;
use crate::model::trust_entry::{TrustEntry, TrustEntryStatusEnum};
use crate::model::trust_list_publication::TrustListPublication;
use crate::model::trust_list_role::TrustListRoleEnum;
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
    pub role: TrustListRoleEnum,
    #[try_from(infallible)]
    pub content: Option<Vec<u8>>,
    #[try_from(infallible)]
    pub sequence_number: u32,
    #[try_from(infallible)]
    pub metadata: Vec<u8>,
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
    pub role: TrustListRoleEnum,
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
    pub params: Vec<u8>,
}

pub type GetTrustEntryListResponseDTO = GetListResponse<TrustEntryListItemResponseDTO>;

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
