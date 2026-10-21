use one_core::model::trust_entry::{SortableTrustEntryColumn, TrustEntryStateEnum};
use one_core::model::trust_list_publication::SortableTrustListPublicationColumn;
use one_core::model::trust_list_role::TrustListRoleEnum;
use one_core::service::error::ServiceError;
use one_core::service::trust_list_publication::dto::{
    CreateTrustEntryRequestDTO, CreateTrustListPublicationRequestDTO, ExactTrustListFilterColumn,
    GetTrustListPublicationResponseDTO, TrustEntryFilterParamsDTO, TrustEntryListItemResponseDTO,
    TrustListPublicationFilterParamsDTO, TrustListPublicationListItemResponseDTO,
    UpdateTrustEntryRequestDTO,
};
use one_dto_mapper::{From, Into, TryInto, convert_inner, convert_inner_of_inner};
use proc_macros::options_not_nullable;
use serde::{Deserialize, Serialize};
use shared_types::{
    CertificateId, IdentifierId, KeyId, OrganisationId, TrustEntryId, TrustListPublicationId,
    TrustListPublisherId,
};
use time::OffsetDateTime;
use utoipa::{IntoParams, ToSchema};

use crate::deserialize::deserialize_timestamp;
use crate::dto::common::{GetListResponseRestDTO, ListQueryParamsRest};
use crate::dto::mapper::fallback_organisation_id_from_session;
use crate::endpoint::identifier::dto::GetIdentifierListItemResponseRestDTO;
use crate::serialize::{front_time, front_time_option};

#[options_not_nullable]
#[derive(Debug, Deserialize, ToSchema, TryInto)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[try_into(T = CreateTrustListPublicationRequestDTO, Error = ServiceError)]
pub struct CreateTrustListRequestRestDTO {
    /// Reference a configured `trustListPublisher` instance.
    #[try_into(infallible)]
    pub r#type: String,
    /// Required when not using STS authentication mode. Specifies the
    /// organizational context for this operation. When using STS mode
    /// this value is derived from the token.
    #[try_into(with_fn = fallback_organisation_id_from_session)]
    pub organisation_id: Option<OrganisationId>,
    /// ID of identifier used to sign each publication of the list.
    #[try_into(infallible)]
    pub identifier_id: IdentifierId,
    /// Specify key to use from publisher identifier. Omit for
    /// automatic selection.
    #[try_into(with_fn = convert_inner, infallible)]
    pub key_id: Option<KeyId>,
    /// Specify certificate to use from publisher identifier. Omit
    /// for automatic selection.
    #[try_into(with_fn = convert_inner, infallible)]
    pub certificate_id: Option<CertificateId>,
    /// Provide an internal label for this trust list publication.
    #[try_into(infallible)]
    pub name: String,
    /// The profile this trust list conforms to. Determines the
    /// profile-specific URIs and requirements applied to the
    /// published list.
    #[try_into(infallible)]
    pub role: TrustListRoleRestEnum,
    /// Optional scheme information fields that cannot be derived
    /// from the profile type or signing certificate. See the
    /// [Scheme Operators Guide](https://docs.procivis.ch/trust/etsi/scheme-operators)
    /// for details.
    #[try_into(infallible)]
    pub params: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[into(CreateTrustEntryRequestDTO)]
pub struct CreateTrustEntryRequestRestDTO {
    /// ID of the identifier holding the trusted entity's certificate.
    /// The entity's digital identity in the published list is derived
    /// from this certificate.
    pub identifier_id: IdentifierId,
    /// Optional entity and service information fields. See the
    /// [Scheme Operators Guide](https://docs.procivis.ch/trust/etsi/scheme-operators)
    /// for details.
    pub params: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[into(UpdateTrustEntryRequestDTO)]
pub struct UpdateTrustEntryRequestRestDTO {
    /// Update the entry's state on the trust list publication.
    #[into(with_fn = "convert_inner")]
    pub state: Option<TrustEntryStateRestEnum>,
    /// Optional entity and service information fields. See the
    /// [Scheme Operators Guide](https://docs.procivis.ch/trust/etsi/scheme-operators)
    /// for details.
    pub params: Option<serde_json::Value>,
}

pub(crate) type GetTrustListPublicationListResponseRestDTO =
    GetListResponseRestDTO<TrustListPublicationListItemResponseRestDTO>;

#[options_not_nullable]
#[derive(Debug, Clone, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(TrustListPublicationListItemResponseDTO)]
pub(crate) struct TrustListPublicationListItemResponseRestDTO {
    pub id: TrustListPublicationId,
    /// Internal label for the trust list publication.
    pub name: String,
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    #[serde(serialize_with = "front_time")]
    pub created_date: OffsetDateTime,
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    #[serde(serialize_with = "front_time")]
    pub last_modified: OffsetDateTime,
    pub organisation_id: OrganisationId,
    /// The configured `trustListPublisher` instance used to
    /// publish the list.
    pub r#type: TrustListPublisherId,
    /// The profile this trust list conforms to.
    pub role: TrustListRoleRestEnum,
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    #[serde(serialize_with = "front_time_option")]
    pub deleted_at: Option<OffsetDateTime>,
    /// Public URL where the published trust list can be retrieved.
    pub public_url: String,
}

#[options_not_nullable]
#[derive(Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(GetTrustListPublicationResponseDTO)]
pub(crate) struct GetTrustListPublicationResponseRestDTO {
    pub id: TrustListPublicationId,
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    #[serde(serialize_with = "front_time")]
    pub created_date: OffsetDateTime,
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    #[serde(serialize_with = "front_time")]
    pub last_modified: OffsetDateTime,
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    #[serde(serialize_with = "front_time_option")]
    pub deleted_at: Option<OffsetDateTime>,
    /// Internal label for the trust list publication.
    pub name: String,
    /// Identifier used for signing the trust list.
    pub identifier: GetIdentifierListItemResponseRestDTO,
    /// The configured `trustListPublisher` instance used to
    /// publish this list.
    pub r#type: TrustListPublisherId,
    /// The profile this trust list conforms to.
    pub role: TrustListRoleRestEnum,
    /// Public URL where the published trust list can be retrieved.
    pub public_url: String,
    /// The sequence number increments with each publication of
    /// the list.
    pub sequence_number: u32,
    /// Scheme information, originally passed as `params` in the
    /// API call to create the trust list.
    #[from(with_fn_ref = "map_raw_str")]
    pub metadata: String,
    pub organisation_id: OrganisationId,
}

pub(crate) type GetTrustEntryListResponseRestDTO =
    GetListResponseRestDTO<TrustEntryListItemResponseRestDTO>;

#[options_not_nullable]
#[derive(Debug, Clone, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(TrustEntryListItemResponseDTO)]
pub(crate) struct TrustEntryListItemResponseRestDTO {
    pub id: TrustEntryId,
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    #[serde(serialize_with = "front_time")]
    pub created_date: OffsetDateTime,
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    #[serde(serialize_with = "front_time")]
    pub last_modified: OffsetDateTime,
    /// The entry's current state on the trust list publication.
    pub state: TrustEntryStateRestEnum,
    /// Identifier of the trusted entity.
    pub identifier: GetIdentifierListItemResponseRestDTO,
    /// Entity and service information for the trusted entity.
    #[from(with_fn_ref = "map_raw_str")]
    pub params: String,
}

pub(crate) type ListTrustListPublicationsEntitiesQuery = ListQueryParamsRest<
    TrustListPublicationFilterQueryParamsRestDTO,
    SortableTrustListPublicationColumnRestEnum,
>;

#[derive(Clone, Debug, Deserialize, ToSchema, IntoParams, TryInto)]
#[try_into(T = TrustListPublicationFilterParamsDTO, Error = ServiceError)]
#[serde(rename_all = "camelCase")] // No deny_unknown_fields because of flattening inside GetTrustListQuery
pub(crate) struct TrustListPublicationFilterQueryParamsRestDTO {
    /// Filter by one or more UUIDs.
    #[param(rename = "ids[]", nullable = false)]
    #[try_into(infallible)]
    pub ids: Option<Vec<TrustListPublicationId>>,
    /// Return only trust lists with a name starting with this string.
    /// Not case-sensitive.
    #[param(nullable = false)]
    #[try_into(infallible)]
    pub name: Option<String>,
    /// Filter by one or more trust list types.
    #[try_into(infallible, with_fn = convert_inner_of_inner)]
    #[param(rename = "types[]", nullable = false)]
    pub types: Option<Vec<String>>,
    /// Filter by one or more trust list roles.
    #[try_into(infallible, with_fn = convert_inner_of_inner)]
    #[param(rename = "roles[]", nullable = false)]
    pub roles: Option<Vec<TrustListRoleRestEnum>>,
    /// Required when not using STS authentication mode. Specifies the
    /// organizational context for this operation. When using STS
    /// authentication, this value is derived from the token.
    #[param(nullable = false)]
    #[try_into(with_fn = fallback_organisation_id_from_session)]
    pub organisation_id: Option<OrganisationId>,
    /// Set which filters apply in an exact way.
    #[try_into(infallible, with_fn = convert_inner_of_inner)]
    #[param(rename = "exact[]", inline, nullable = false)]
    pub exact: Option<Vec<ExactTrustListFilterColumnRestEnum>>,
    /// Return only trust lists created after this time.
    /// Timestamp in RFC3339 format (for example '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    #[try_into(infallible)]
    pub created_date_after: Option<OffsetDateTime>,
    /// Return only trust lists created before this time.
    /// Timestamp in RFC3339 format (for example '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    #[try_into(infallible)]
    pub created_date_before: Option<OffsetDateTime>,
    /// Return only trust lists last modified after this time.
    /// Timestamp in RFC3339 format (for example '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    #[try_into(infallible)]
    pub last_modified_after: Option<OffsetDateTime>,
    /// Return only trust lists last modified before this time.
    /// Timestamp in RFC3339 format (for example '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    #[try_into(infallible)]
    pub last_modified_before: Option<OffsetDateTime>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase")]
#[into(SortableTrustListPublicationColumn)]
pub(crate) enum SortableTrustListPublicationColumnRestEnum {
    Role,
    Type,
    Name,
    LastModified,
    CreatedDate,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase")]
#[into(ExactTrustListFilterColumn)]
pub(crate) enum ExactTrustListFilterColumnRestEnum {
    Name,
}

pub(crate) type ListTrustEntryEntitiesQuery =
    ListQueryParamsRest<TrustEntryFilterQueryParamsRestDTO, SortableTrustEntryColumnRestEnum>;

#[derive(Clone, Debug, Deserialize, ToSchema, IntoParams, TryInto)]
#[try_into(T = TrustEntryFilterParamsDTO, Error = ServiceError)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TrustEntryFilterQueryParamsRestDTO {
    /// Filter by one or more UUIDs.
    #[param(rename = "ids[]", nullable = false)]
    #[try_into(infallible)]
    pub ids: Option<Vec<TrustEntryId>>,
    /// Filter by one or more identifier UUIDs.
    #[param(rename = "identifierIds[]", nullable = false)]
    #[try_into(infallible)]
    pub identifier_ids: Option<Vec<IdentifierId>>,
    /// Filter by one or more trust entry states.
    #[try_into(infallible, with_fn = convert_inner_of_inner)]
    #[param(rename = "states[]", nullable = false)]
    pub states: Option<Vec<TrustEntryStateRestEnum>>,
    /// Return only trust entries created after this time.
    /// Timestamp in RFC3339 format (for example '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    #[try_into(infallible)]
    pub created_date_after: Option<OffsetDateTime>,
    /// Return only trust entries created before this time.
    /// Timestamp in RFC3339 format (for example '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    #[try_into(infallible)]
    pub created_date_before: Option<OffsetDateTime>,
    /// Return only trust entries last modified after this time.
    /// Timestamp in RFC3339 format (for example '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    #[try_into(infallible)]
    pub last_modified_after: Option<OffsetDateTime>,
    /// Return only trust entries last modified before this time.
    /// Timestamp in RFC3339 format (for example '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    #[try_into(infallible)]
    pub last_modified_before: Option<OffsetDateTime>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema, Into)]
#[into(SortableTrustEntryColumn)]
#[serde(rename_all = "camelCase")]
pub(crate) enum SortableTrustEntryColumnRestEnum {
    Identifier,
    State,
    LastModified,
    CreatedDate,
}

#[derive(Clone, Debug, Eq, PartialEq, Into, From, Deserialize, Serialize, ToSchema)]
#[into(TrustEntryStateEnum)]
#[from(TrustEntryStateEnum)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TrustEntryStateRestEnum {
    Active,
    Suspended,
    Removed,
}

#[derive(Clone, Debug, Eq, PartialEq, Into, From, Deserialize, Serialize, ToSchema)]
#[into(TrustListRoleEnum)]
#[from(TrustListRoleEnum)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TrustListRoleRestEnum {
    PidProvider,
    WalletProvider,
    WrpAcProvider,
    PubEeaProvider,
    QeaaProvider,
    QesrcProvider,
    WrpRcProvider,
    NationalRegistryRegistrar,
    Issuer,
    Verifier,
}

fn map_raw_str(raw: &[u8]) -> String {
    String::from_utf8_lossy(raw).into_owned()
}
