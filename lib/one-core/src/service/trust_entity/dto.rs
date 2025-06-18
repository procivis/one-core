use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use shared_types::{
    DidId, DidValue, IdentifierId, OrganisationId, TrustAnchorId, TrustEntityId, TrustEntityKey,
};
use time::OffsetDateTime;

use crate::model::certificate::CertificateState;
use crate::model::common::GetListResponse;
use crate::model::list_filter::{ListFilterValue, StringMatch};
use crate::model::list_query::ListQuery;
use crate::model::trust_entity::{TrustEntityRole, TrustEntityState, TrustEntityType};
use crate::service::certificate::dto::CertificateX509ExtensionDTO;
use crate::service::common_dto::{BoundedB64Image, KB};
use crate::service::did::dto::DidListItemResponseDTO;
use crate::service::error::ValidationError;
use crate::service::identifier::dto::GetIdentifierListItemResponseDTO;
use crate::service::trust_anchor::dto::GetTrustAnchorDetailResponseDTO;

pub type TrustListLogo = BoundedB64Image<{ 50 * KB }>;
pub type TrustEntityContent = String;

#[derive(Clone, Debug)]
pub struct CreateTrustEntityRequestDTO {
    pub name: String,
    pub logo: Option<TrustListLogo>,
    pub website: Option<String>,
    pub terms_url: Option<String>,
    pub privacy_url: Option<String>,
    pub role: TrustEntityRole,
    pub trust_anchor_id: TrustAnchorId,
    pub r#type: Option<TrustEntityType>,
    pub did_id: Option<DidId>,
    pub identifier_id: Option<IdentifierId>,
    pub content: Option<TrustEntityContent>,
}

impl TryFrom<CreateTrustEntityRequestDTO>
    for (CreateTrustEntityTypeDTO, CreateTrustEntityParamsDTO)
{
    type Error = ValidationError;

    fn try_from(value: CreateTrustEntityRequestDTO) -> Result<Self, Self::Error> {
        let key = match (
            value.r#type,
            value.did_id,
            value.identifier_id,
            value.content,
        ) {
            (Some(TrustEntityType::CertificateAuthority), None, None, Some(content)) => {
                CreateTrustEntityTypeDTO::Certificate(content)
            }
            (Some(TrustEntityType::Did), None, Some(identifier_id), None) => {
                CreateTrustEntityTypeDTO::Identifier(identifier_id)
            }
            (Some(TrustEntityType::Did), Some(did_id), None, None)
            | (None, Some(did_id), None, None) => CreateTrustEntityTypeDTO::Did(did_id),
            (None, _, _, _) => return Err(ValidationError::TrustEntityTypeNotSpecified),
            (Some(_), _, _, _) => return Err(ValidationError::TrustEntityAmbiguousIds),
        };
        let params = CreateTrustEntityParamsDTO {
            name: value.name,
            logo: value.logo,
            website: value.website,
            terms_url: value.terms_url,
            privacy_url: value.privacy_url,
            role: value.role,
        };

        Ok((key, params))
    }
}

#[derive(Clone, Debug)]
pub(super) enum CreateTrustEntityTypeDTO {
    Identifier(IdentifierId),
    Did(DidId),
    Certificate(TrustEntityContent),
}

pub(super) struct CreateTrustEntityParamsDTO {
    pub name: String,
    pub logo: Option<TrustListLogo>,
    pub website: Option<String>,
    pub terms_url: Option<String>,
    pub privacy_url: Option<String>,
    pub role: TrustEntityRole,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateTrustEntityFromDidPublisherRequestDTO {
    pub trust_anchor_id: Option<TrustAnchorId>,
    pub did: DidValue,
    pub name: String,
    pub logo: Option<TrustListLogo>,
    pub terms_url: Option<String>,
    pub privacy_url: Option<String>,
    pub website: Option<String>,
    pub role: TrustEntityRole,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateTrustEntityFromDidPublisherResponseDTO {
    pub id: TrustEntityId,
}

#[derive(Clone, Debug)]
pub struct CreateRemoteTrustEntityRequestDTO {
    pub did_id: DidId,
    pub trust_anchor_id: Option<TrustAnchorId>,
    pub name: String,
    pub logo: Option<TrustListLogo>,
    pub terms_url: Option<String>,
    pub privacy_url: Option<String>,
    pub website: Option<String>,
    pub role: TrustEntityRole,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetTrustEntityResponseDTO {
    pub id: TrustEntityId,
    pub organisation_id: Option<OrganisationId>,
    pub name: String,

    #[serde(deserialize_with = "time::serde::rfc3339::deserialize")]
    pub created_date: OffsetDateTime,
    #[serde(deserialize_with = "time::serde::rfc3339::deserialize")]
    pub last_modified: OffsetDateTime,

    pub logo: Option<String>,
    pub website: Option<String>,
    pub terms_url: Option<String>,
    pub privacy_url: Option<String>,
    pub role: TrustEntityRole,
    pub trust_anchor: GetTrustAnchorDetailResponseDTO,
    pub did: Option<DidListItemResponseDTO>,
    pub state: TrustEntityState,
    pub entity_key: TrustEntityKey,
    pub r#type: TrustEntityType,
    pub identifier: Option<GetIdentifierListItemResponseDTO>,
    pub content: Option<String>,
    #[serde(skip)]
    pub ca: Option<TrustEntityCertificateResponseDTO>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetRemoteTrustEntityResponseDTO {
    pub id: TrustEntityId,
    pub organisation_id: Option<OrganisationId>,
    pub name: String,

    #[serde(deserialize_with = "time::serde::rfc3339::deserialize")]
    pub created_date: OffsetDateTime,
    #[serde(deserialize_with = "time::serde::rfc3339::deserialize")]
    pub last_modified: OffsetDateTime,

    pub logo: Option<String>,
    pub website: Option<String>,
    pub terms_url: Option<String>,
    pub privacy_url: Option<String>,
    pub role: TrustEntityRole,
    pub trust_anchor: GetTrustAnchorDetailResponseDTO,
    pub did: Option<DidListItemResponseDTO>,
    pub state: TrustEntityState,
}

#[derive(Clone, Debug)]
pub struct TrustEntityCertificateResponseDTO {
    pub state: CertificateState,
    pub public_key: String,
    pub serial_number: String,
    pub common_name: Option<String>,
    pub not_before: OffsetDateTime,
    pub not_after: OffsetDateTime,
    pub issuer: String,
    pub subject: String,
    pub fingerprint: String,
    pub extensions: Vec<CertificateX509ExtensionDTO>,
}

pub type GetTrustEntitiesResponseDTO = GetListResponse<TrustEntitiesResponseItemDTO>;

pub type ListTrustEntitiesQueryDTO =
    ListQuery<SortableTrustEntityColumnEnum, TrustEntityFilterValue>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SortableTrustEntityColumnEnum {
    Name,
    Role,
    LastModified,
    State,
    EntityKey,
    Type,
}

#[derive(Clone, Debug)]
pub struct TrustEntitiesResponseItemDTO {
    pub id: TrustEntityId,
    pub name: String,

    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,

    pub logo: Option<String>,
    pub website: Option<String>,
    pub terms_url: Option<String>,
    pub privacy_url: Option<String>,
    pub role: TrustEntityRole,
    pub state: TrustEntityState,
    pub trust_anchor: GetTrustAnchorDetailResponseDTO,
    pub did: Option<DidListItemResponseDTO>,
    pub entity_key: String,
    pub r#type: TrustEntityType,
    pub content: Option<String>,
    pub organisation_id: Option<OrganisationId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TrustEntityFilterValue {
    Name(StringMatch),
    Role(TrustEntityRole),
    DidId(DidId),
    TrustAnchor(TrustAnchorId),
    OrganisationId(OrganisationId),
    EntityKey(TrustEntityKey),
    Type(Vec<TrustEntityType>),
}

impl ListFilterValue for TrustEntityFilterValue {}

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateTrustEntityFromDidRequestDTO {
    pub action: Option<UpdateTrustEntityActionFromDidRequestDTO>,
    pub name: Option<String>,
    #[serde(with = "::serde_with::rust::double_option")]
    pub logo: Option<Option<TrustListLogo>>,
    #[serde(with = "::serde_with::rust::double_option")]
    pub website: Option<Option<String>>,
    #[serde(with = "::serde_with::rust::double_option")]
    pub terms_url: Option<Option<String>>,
    #[serde(with = "::serde_with::rust::double_option")]
    pub privacy_url: Option<Option<String>>,
    pub role: Option<TrustEntityRole>,
    pub content: Option<TrustEntityContent>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UpdateTrustEntityActionFromDidRequestDTO {
    AdminActivate,
    Activate,
    Withdraw,
    Remove,
}
