use one_core::model::trust_entity::{TrustEntityRole, TrustEntityState, TrustEntityType};
use one_core::service::error::ServiceError;
use one_core::service::trust_entity::dto::{
    CreateRemoteTrustEntityRequestDTO, GetRemoteTrustEntityResponseDTO, GetTrustEntityResponseDTO,
    SortableTrustEntityColumnEnum, TrustEntitiesResponseItemDTO, TrustEntityCertificateResponseDTO,
};
use one_dto_mapper::{From, Into, TryInto, convert_inner, try_convert_inner};
use proc_macros::options_not_nullable;
use serde::{Deserialize, Serialize};
use shared_types::{
    DidId, IdentifierId, OrganisationId, TrustAnchorId, TrustEntityId, TrustEntityKey,
};
use time::OffsetDateTime;
use utoipa::{IntoParams, ToSchema};

use crate::deserialize::deserialize_timestamp;
use crate::dto::common::{ExactColumn, ListQueryParamsRest};
use crate::endpoint::certificate::dto::{CertificateStateRest, CertificateX509ExtensionRestDTO};
use crate::endpoint::did::dto::DidListItemResponseRestDTO;
use crate::endpoint::identifier::dto::GetIdentifierListItemResponseRestDTO;
use crate::endpoint::trust_anchor::dto::{
    GetTrustAnchorDetailResponseRestDTO, GetTrustAnchorResponseRestDTO,
};
use crate::serialize::front_time;

#[options_not_nullable]
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CreateTrustEntityRequestRestDTO {
    /// Specify the entity name.
    pub(super) name: String,
    /// base64 encoded image. Maximum size = 50kb.
    pub(super) logo: Option<String>,
    /// Specify the entity's domain name.
    pub(super) website: Option<String>,
    /// Specify a Terms of Service URL.
    pub(super) terms_url: Option<String>,
    /// Specify the Privacy Policy URL.
    pub(super) privacy_url: Option<String>,
    /// Whether the entity is a trusted issuer, verifier, or both. For certificates,
    /// whether the CA is trusted to sign for an issuer, a verifier, or both.
    pub(super) role: TrustEntityRoleRest,
    /// Specify which trust anchor to add the entity to.
    pub(super) trust_anchor_id: TrustAnchorId,
    /// Specify DID ID.
    pub(super) did_id: Option<DidId>,
    /// Specify the identifier to add to the trust list.
    pub(super) identifier_id: Option<IdentifierId>,
    /// For certificates, put the PEM content here.
    pub(super) content: Option<String>,
    /// If passing an identifier via `identifierId` or a certificate via `content`,
    /// specify the type of entity. If no type is specified the system expects a
    /// `didId`.
    pub(super) r#type: Option<TrustEntityTypeRest>,
    pub(super) organisation_id: OrganisationId,
}

/// Whether the trust entity issues credentials, verifies credentials, or both.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema, Into, From)]
#[into(TrustEntityRole)]
#[from(TrustEntityRole)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TrustEntityRoleRest {
    Issuer,
    Verifier,
    Both,
}

/// Trust entity state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, ToSchema, Into, From)]
#[into(TrustEntityState)]
#[from(TrustEntityState)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum TrustEntityStateRest {
    Active,
    Removed,
    Withdrawn,
    RemovedAndWithdrawn,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(GetTrustEntityResponseDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GetTrustEntityResponseRestDTO {
    /// Trust entity ID.
    pub id: TrustEntityId,
    pub organisation_id: Option<OrganisationId>,
    #[serde(serialize_with = "front_time")]
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,
    #[serde(serialize_with = "front_time")]
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub logo: Option<String>,
    pub website: Option<String>,
    pub terms_url: Option<String>,
    pub privacy_url: Option<String>,
    /// The role the entity is trusted to perform.
    pub role: TrustEntityRoleRest,
    /// Trust anchor details.
    pub trust_anchor: GetTrustAnchorDetailResponseRestDTO,
    /// DID details.
    #[from(with_fn=convert_inner)]
    pub did: Option<DidListItemResponseRestDTO>,
    /// The entity's status on the trust anchor.
    pub state: TrustEntityStateRest,
    /// DID value or certificate's `subject`.
    pub entity_key: TrustEntityKey,
    pub r#type: TrustEntityTypeRest,
    /// Identifier details.
    #[from(with_fn=convert_inner)]
    pub identifier: Option<GetIdentifierListItemResponseRestDTO>,
    /// If `type` is `CA`, the certificate in PEM format.
    pub content: Option<String>,
    /// Human-readable X.509 certificate details.
    #[from(with_fn=convert_inner)]
    pub ca: Option<TrustEntityCertificateResponseRestDTO>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(TrustEntityCertificateResponseDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TrustEntityCertificateResponseRestDTO {
    pub state: CertificateStateRest,
    pub public_key: String,
    pub common_name: Option<String>,
    pub serial_number: String,
    #[serde(serialize_with = "front_time")]
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    pub not_before: OffsetDateTime,
    #[serde(serialize_with = "front_time")]
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    pub not_after: OffsetDateTime,
    pub issuer: String,
    pub subject: String,
    pub fingerprint: String,
    #[from(with_fn=convert_inner)]
    pub extensions: Vec<CertificateX509ExtensionRestDTO>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(GetRemoteTrustEntityResponseDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GetRemoteTrustEntityResponseRestDTO {
    pub id: TrustEntityId,
    pub organisation_id: Option<OrganisationId>,
    #[serde(serialize_with = "front_time")]
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,
    #[serde(serialize_with = "front_time")]
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub logo: Option<String>,
    pub website: Option<String>,
    pub terms_url: Option<String>,
    pub privacy_url: Option<String>,
    pub role: TrustEntityRoleRest,
    pub trust_anchor: GetTrustAnchorDetailResponseRestDTO,
    pub state: TrustEntityStateRest,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase")]
#[into(SortableTrustEntityColumnEnum)]
pub(crate) enum SortableTrustEntityColumnRestEnum {
    Name,
    Role,
    LastModified,
    State,
    EntityKey,
    Type,
    CreatedDate,
}

pub(crate) type ListTrustEntitiesQuery =
    ListQueryParamsRest<TrustEntityFilterQueryParamsRestDto, SortableTrustEntityColumnRestEnum>;

#[derive(Clone, Debug, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TrustEntityFilterQueryParamsRestDto {
    /// Return only entities with a name starting with this string. Not case-sensitive.
    #[param(nullable = false)]
    pub name: Option<String>,
    /// Return only entities of the specified type.
    #[param(rename = "type[]", inline, nullable = false)]
    pub r#type: Option<Vec<TrustEntityTypeRest>>,
    /// Specify entities to return by their DID value or their certificate `subject`.
    #[param(nullable = false)]
    pub entity_key: Option<TrustEntityKey>,
    /// Return only entities that are issuers, or verifiers, or both.
    #[param(nullable = false)]
    pub role: Option<TrustEntityRoleRest>,
    /// Return only entities from the specified trust anchor.
    #[param(nullable = false)]
    pub trust_anchor_id: Option<TrustAnchorId>,
    /// Specify entities to return by their DID UUID.
    #[param(nullable = false)]
    pub did_id: Option<DidId>,
    /// Set which filters apply in an exact way.
    #[param(rename = "exact[]", inline, nullable = false)]
    pub exact: Option<Vec<ExactColumn>>,
    pub organisation_id: Option<OrganisationId>,

    /// Return only entities which were created after this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    pub created_date_after: Option<OffsetDateTime>,
    /// Return only entities which were created before this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    pub created_date_before: Option<OffsetDateTime>,
    /// Return only entities which were last modified after this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    pub last_modified_after: Option<OffsetDateTime>,
    /// Return only entities which were last modified before this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    pub last_modified_before: Option<OffsetDateTime>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(TrustEntitiesResponseItemDTO)]
pub(crate) struct ListTrustEntitiesResponseItemRestDTO {
    pub id: TrustEntityId,
    pub name: String,

    #[serde(serialize_with = "front_time")]
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,
    #[serde(serialize_with = "front_time")]
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,

    pub logo: Option<String>,
    pub website: Option<String>,
    pub terms_url: Option<String>,
    pub state: TrustEntityStateRest,
    pub privacy_url: Option<String>,
    pub role: TrustEntityRoleRest,
    pub trust_anchor: GetTrustAnchorResponseRestDTO,
    pub r#type: TrustEntityTypeRest,
    pub entity_key: TrustEntityKey,
}

#[derive(Clone, Debug, Deserialize, ToSchema, TryInto)]
#[try_into(T = CreateRemoteTrustEntityRequestDTO, Error = ServiceError)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CreateRemoteTrustEntityRequestRestDTO {
    /// Specify trust anchor ID.
    #[serde(default)]
    #[schema(nullable = false)]
    #[try_into(with_fn = convert_inner, infallible)]
    pub trust_anchor_id: Option<TrustAnchorId>,
    /// Specify local DID.
    #[try_into(infallible)]
    pub did_id: DidId,
    /// Specify the entity name.
    #[try_into(infallible)]
    pub name: String,
    /// base64 encoded image. Maximum size = 50kb.
    #[schema(nullable = false)]
    #[try_into(with_fn = try_convert_inner)]
    pub logo: Option<String>,
    /// Specify the entity's domain name.
    #[schema(nullable = false)]
    #[try_into(with_fn = convert_inner, infallible)]
    pub website: Option<String>,
    /// Specify a Terms of Service URL.
    #[schema(nullable = false)]
    #[try_into(with_fn = convert_inner, infallible)]
    pub terms_url: Option<String>,
    /// Specify the Privacy Policy URL.
    #[schema(nullable = false)]
    #[try_into(with_fn = convert_inner, infallible)]
    pub privacy_url: Option<String>,
    #[try_into(infallible)]
    pub role: TrustEntityRoleRest,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, ToSchema, Into, From)]
#[into(TrustEntityType)]
#[from(TrustEntityType)]
pub enum TrustEntityTypeRest {
    #[serde(rename = "DID")]
    Did,
    #[serde(rename = "CA")]
    CertificateAuthority,
}
