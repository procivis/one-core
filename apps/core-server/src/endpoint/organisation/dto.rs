use one_core::service::error::ServiceError;
use one_core::service::organisation::dto::{
    CreateOrganisationRequestDTO, EcosystemInfoDTO, GetOrganisationDetailsResponseDTO,
    GetOrganisationListItemResponseDTO, InstanceDetailResponseDTO, OrganisationFilterParamsDTO,
    TrustCollectionInfoDTO, VerifierProviderDetailResponseDTO, WalletProviderDetailResponseDTO,
};
use one_dto_mapper::{From, Into, TryInto, convert_inner};
use proc_macros::{ModifySchema, options_not_nullable};
use serde::{Deserialize, Serialize};
use shared_types::{EcosystemId, IdentifierId, InstanceId, OrganisationId, TrustCollectionId};
use time::OffsetDateTime;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::deserialize::deserialize_timestamp;
use crate::dto::common::{Boolean, ListQueryParamsRest};
use crate::endpoint::identifier::dto::GetIdentifierListItemResponseRestDTO;
use crate::endpoint::ssi::wallet_provider::dto::{
    DisplayNameRestDTO, ProviderTrustCollectionRestDTO,
};
use crate::serialize::{front_time, front_time_option};

#[options_not_nullable]
#[derive(Clone, Debug, Default, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[into(CreateOrganisationRequestDTO)]
pub(crate) struct CreateOrganisationRequestRestDTO {
    #[into(with_fn = convert_inner)]
    pub id: Option<OrganisationId>,
    /// Optionally assign a parent organization to share policy-level
    /// configuration, such as trust collections, across a one-level hierarchy.
    /// The provided organization must not have a parent organization.
    #[into(with_fn = convert_inner)]
    pub parent_organisation: Option<OrganisationId>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Default, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct UpsertOrganisationRequestRestDTO {
    #[schema(value_type = bool, example = true)]
    pub deactivate: Option<bool>,
    /// Specify which configured wallet provider this organization will use
    /// to issue attestations to wallet units, and the identifier used to
    /// sign them. Sending `null` clears the wallet provider association.
    #[serde(default, with = "::serde_with::rust::double_option")]
    pub wallet_provider: Option<Option<UpsertProviderRequestRestDTO>>,
    /// Specify which configured verifier provider this organization will
    /// use, and the identifier used to authenticate to it. Sending `null`
    /// clears the verifier provider association.
    #[serde(default, with = "::serde_with::rust::double_option")]
    pub verifier_provider: Option<Option<UpsertProviderRequestRestDTO>>,
    /// Policy-level configuration for this organization.
    pub configuration: Option<UpsertOrganisationConfigurationRestDTO>,
    /// The trust collections this organization's wallet subscribes to,
    /// selected from those made available by the Wallet Provider. Omit to
    /// leave the current selection unchanged.
    #[deprecated = "use configuration.selectedEcosystems instead"]
    pub trust_collections: Option<Vec<TrustCollectionId>>,
    /// Optionally assign a parent organization to share policy-level
    /// configuration, such as trust collections, across a one-level hierarchy.
    /// The provided organization must not have a parent organization.
    #[serde(default, with = "::serde_with::rust::double_option")]
    pub parent_organisation: Option<Option<OrganisationId>>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct UpsertProviderRequestRestDTO {
    #[schema(example = "PROCIVIS_ONE")]
    pub name: Option<String>,
    /// Identifier used by this organization to authenticate to the
    /// provider. This can be any type of identifier but it must be backed
    /// by an ECDSA key.
    pub issuer: Option<IdentifierId>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Deserialize, ToSchema, ModifySchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct UpsertOrganisationConfigurationRestDTO {
    /// The ecosystems this organization participates in.
    #[modify_schema(field = ecosystem)]
    pub selected_ecosystems: Option<Vec<String>>,
    /// When true, the verifier will only validate presentations of
    /// credentials issued by trusted issuers.
    #[deprecated = "use enforceEcosystemAsVerifier instead"]
    pub trusted_issuer_required: Option<bool>,
    /// When true, the wallet only accepts presentation requests from
    /// trusted relying parties.
    #[deprecated = "use enforceEcosystemAsHolder instead"]
    pub trusted_rp_required: Option<bool>,
    /// When true, the issuer will only issue credentials requiring wallet
    /// attestations to wallets of trusted wallet providers.
    #[deprecated = "use enforceEcosystemAsIssuer instead"]
    pub trusted_wallet_provider_required: Option<bool>,
    /// When true, the issuer will only issue credentials to wallet units of one of
    /// the selected ecosystems.
    pub enforce_ecosystem_as_issuer: Option<bool>,
    /// When true, the wallet only accepts issuance and presentation requests
    /// from members of one of the selected ecosystems.
    pub enforce_ecosystem_as_holder: Option<bool>,
    /// When true, the verifier will only accept presentations of credentials
    /// issued by issuers of the selected ecosystems. Ecosystems must be consistent
    /// across presentations belonging to the same proof request.
    pub enforce_ecosystem_as_verifier: Option<bool>,
}

#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CreateOrganisationResponseRestDTO {
    pub id: OrganisationId,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(GetOrganisationDetailsResponseDTO)]
pub(crate) struct GetOrganisationDetailsResponseRestDTO {
    pub id: Uuid,
    #[serde(serialize_with = "front_time")]
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,
    #[serde(serialize_with = "front_time")]
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,
    #[schema(nullable = false, example = "2023-06-09T14:19:57.000Z")]
    #[serde(serialize_with = "front_time_option")]
    pub deactivated_at: Option<OffsetDateTime>,
    /// The parent organization this organization inherits policy-level
    /// configuration from, if any.
    pub parent_organisation: Option<OrganisationId>,
    /// Policy-level configuration for this organization.
    #[from(with_fn = convert_inner)]
    pub configuration: Option<OrganisationConfigurationRestDTO>,
    /// The ecosystems offered to this organization by its wallet or verifier
    /// provider, annotated with whether the organization currently selected
    /// each one. Ecosystems this system is not configured for are omitted.
    /// If there is no wallet or verifier provider, the ecosystems configured
    /// in the local system are returned.
    #[from(with_fn = convert_inner)]
    pub ecosystems: Vec<OrganisationEcosystemRestDTO>,
    #[from(with_fn = convert_inner)]
    pub wallet_provider: Option<WalletProviderDetailResponseRestDTO>,
    #[from(with_fn = convert_inner)]
    pub verifier_provider: Option<VerifierProviderDetailResponseRestDTO>,
    /// Wallet registration details for this organization's Business
    /// Wallet.
    #[from(with_fn = convert_inner)]
    pub wallet_instance: Option<InstanceDetailResponseRestDTO>,
    /// Verifier registration details for this organization's Business
    /// Verifier.
    #[from(with_fn = convert_inner)]
    pub verifier_instance: Option<InstanceDetailResponseRestDTO>,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(InstanceDetailResponseDTO)]
pub(crate) struct InstanceDetailResponseRestDTO {
    pub id: InstanceId,
    pub provider_name: String,
    pub provider_url: String,
    pub authentication_key_type: String,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(WalletProviderDetailResponseDTO)]
pub(crate) struct WalletProviderDetailResponseRestDTO {
    /// Wallet Provider configuration used by this organization to provide
    /// wallets.
    pub provider_name: Option<String>,
    /// Identifier used by this organization to provide wallets.
    #[from(with_fn = convert_inner)]
    pub issuer: Option<GetIdentifierListItemResponseRestDTO>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(VerifierProviderDetailResponseDTO)]
pub(crate) struct VerifierProviderDetailResponseRestDTO {
    /// Verifier Provider configuration used by this organization.
    pub provider_name: Option<String>,
    /// Identifier used by this organization to authenticate to the
    /// verifier provider.
    #[from(with_fn = convert_inner)]
    pub issuer: Option<GetIdentifierListItemResponseRestDTO>,
}

// The deprecated `trusted*` flags are kept as aliases of their
// `enforceEcosystemAs*` replacements for backwards compatibility; both
// generations always report the same values, see the `From` impl in `mapper`.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OrganisationConfigurationRestDTO {
    /// When true, the verifier will only validate presentations of
    /// credentials issued by trusted issuers.
    #[deprecated = "use enforceEcosystemAsVerifier instead"]
    pub trusted_issuer_required: bool,
    /// When true, the wallet only accepts presentation requests from
    /// trusted relying parties.
    #[deprecated = "use enforceEcosystemAsHolder instead"]
    pub trusted_rp_required: bool,
    /// When true, the issuer will only issue credentials requiring wallet
    /// attestations to wallets of trusted wallet providers.
    #[deprecated = "use enforceEcosystemAsIssuer instead"]
    pub trusted_wallet_provider_required: bool,
    /// When true, the issuer will only issue credentials to holders of one of
    /// the selected ecosystems.
    pub enforce_ecosystem_as_issuer: bool,
    /// When true, the wallet only accepts issuance and presentation requests
    /// from members of one of the selected ecosystems.
    pub enforce_ecosystem_as_holder: bool,
    /// When true, the verifier will only validate presentations of credentials
    /// issued within one of the selected ecosystems.
    pub enforce_ecosystem_as_verifier: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase")]
#[into("one_core::model::organisation::SortableOrganisationColumn")]
pub(crate) enum SortableOrganisationColumnRestDTO {
    CreatedDate,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, IntoParams, TryInto)]
#[try_into(T = OrganisationFilterParamsDTO, Error = ServiceError)]
#[serde(rename_all = "camelCase")] // No deny_unknown_fields because of flattening inside GetOrganisationQuery
pub(crate) struct OrganisationFilterQueryParamsRest {
    /// Return only organizations created after this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    #[try_into(infallible)]
    pub created_date_after: Option<OffsetDateTime>,
    /// Return only organizations created before this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    #[try_into(infallible)]
    pub created_date_before: Option<OffsetDateTime>,
    /// Return only organizations last modified after this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    #[try_into(infallible)]
    pub last_modified_after: Option<OffsetDateTime>,
    /// Return only organizations last modified before this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    #[try_into(infallible)]
    pub last_modified_before: Option<OffsetDateTime>,
    /// If true, return only organizations that have a parent organization.
    /// If false, return only root organizations.
    #[param(inline, nullable = false)]
    #[try_into(infallible, with_fn = convert_inner)]
    pub has_parent_organisation: Option<Boolean>,
    /// Return only organizations that are children of the given
    /// organization IDs.
    #[param(rename = "parentOrganisations[]", nullable = false)]
    #[try_into(infallible)]
    pub parent_organisations: Option<Vec<OrganisationId>>,
}

pub(crate) type GetOrganisationsQuery =
    ListQueryParamsRest<OrganisationFilterQueryParamsRest, SortableOrganisationColumnRestDTO>;

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(GetOrganisationListItemResponseDTO)]
pub(crate) struct OrganisationListItemResponseRestDTO {
    pub id: Uuid,
    #[serde(serialize_with = "front_time")]
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,
    #[serde(serialize_with = "front_time")]
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,
    #[schema(nullable = false, example = "2023-06-09T14:19:57.000Z")]
    #[serde(serialize_with = "front_time_option")]
    pub deactivated_at: Option<OffsetDateTime>,
    #[from(with_fn = convert_inner)]
    pub wallet_provider: Option<WalletProviderDetailResponseRestDTO>,
    #[from(with_fn = convert_inner)]
    pub verifier_provider: Option<VerifierProviderDetailResponseRestDTO>,
    /// The parent organization this organization inherits policy-level
    /// configuration from, if any.
    pub parent_organisation: Option<OrganisationId>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(TrustCollectionInfoDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OrganisationTrustCollectionRestDTO {
    /// When true, the organization has selected the ecosystem this trust
    /// collection belongs to.
    pub selected: bool,
    /// When true, the trust collection is selected by provider default (if any).
    pub default_selected: bool,
    #[serde(flatten)]
    pub collection: ProviderTrustCollectionRestDTO,
}

#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OrganisationEcosystemListResponseRestDTO {
    pub ecosystems: Vec<OrganisationEcosystemRestDTO>,
}

impl From<Vec<EcosystemInfoDTO>> for OrganisationEcosystemListResponseRestDTO {
    fn from(value: Vec<EcosystemInfoDTO>) -> Self {
        Self {
            ecosystems: convert_inner(value),
        }
    }
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(EcosystemInfoDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OrganisationEcosystemRestDTO {
    /// When true, the organization has selected this ecosystem.
    pub selected: bool,
    /// When true, the ecosystem should be selected by provider default (if any).
    pub default_selected: bool,
    /// Ecosystem provider name.
    pub name: EcosystemId,
    #[from(with_fn = convert_inner)]
    pub display_name: Vec<DisplayNameRestDTO>,
    #[from(with_fn = convert_inner)]
    pub description: Vec<DisplayNameRestDTO>,
    pub logo: String,
}
