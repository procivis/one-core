use one_dto_mapper::From;
use shared_types::{EcosystemId, IdentifierId, InstanceId, OrganisationId, TrustCollectionId};
use time::OffsetDateTime;

use crate::model::common::GetListResponse;
use crate::model::organisation::OrganisationConfiguration;
use crate::service::identifier::dto::GetIdentifierListItemResponseDTO;
use crate::service::managed_instance::dto::{DisplayNameDTO, ProviderTrustCollectionDTO};

#[derive(Clone, Debug)]
pub struct TrustCollectionInfoDTO {
    pub selected: bool,
    pub default_selected: bool,
    pub collection: ProviderTrustCollectionDTO,
}

/// An ecosystem offered to an organisation by its wallet and/or verifier
/// provider, annotated with whether the organisation currently selected it.
#[derive(Clone, Debug)]
pub struct EcosystemInfoDTO {
    pub selected: bool,
    pub default_selected: bool,
    /// Ecosystem provider name
    pub name: EcosystemId,
    pub display_name: Vec<DisplayNameDTO>,
    pub description: Vec<DisplayNameDTO>,
    pub logo: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CreateOrganisationRequestDTO {
    pub id: Option<OrganisationId>,
    pub parent_organisation: Option<OrganisationId>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpsertOrganisationRequestDTO {
    pub id: OrganisationId,
    pub deactivate: Option<bool>,
    pub wallet_provider: Option<Option<String>>,
    pub wallet_provider_issuer: Option<Option<IdentifierId>>,
    pub verifier_provider: Option<Option<String>>,
    pub verifier_provider_issuer: Option<Option<IdentifierId>>,
    pub configuration: Option<UpsertOrganisationConfigurationDTO>,
    pub trust_collections: Option<Vec<TrustCollectionId>>,
    pub parent_organisation: Option<Option<OrganisationId>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetOrganisationDetailsResponseDTO {
    pub id: OrganisationId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub deactivated_at: Option<OffsetDateTime>,
    pub parent_organisation: Option<OrganisationId>,
    pub configuration: Option<OrganisationConfigurationDTO>,
    pub wallet_instance: Option<InstanceDetailResponseDTO>,
    pub verifier_instance: Option<InstanceDetailResponseDTO>,
    pub wallet_provider: Option<WalletProviderDetailResponseDTO>,
    pub verifier_provider: Option<VerifierProviderDetailResponseDTO>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetOrganisationListItemResponseDTO {
    pub id: OrganisationId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub deactivated_at: Option<OffsetDateTime>,
    pub parent_organisation: Option<OrganisationId>,
    pub wallet_provider: Option<WalletProviderDetailResponseDTO>,
    pub verifier_provider: Option<VerifierProviderDetailResponseDTO>,
}

/// Instance registration details, shared by an organization's wallet and
/// verifier instance (both are the same underlying `Instance`, distinguished
/// only by which slot on the organization they're linked from).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstanceDetailResponseDTO {
    pub id: InstanceId,
    pub provider_name: String,
    pub provider_url: String,
    pub authentication_key_type: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalletProviderDetailResponseDTO {
    pub provider_name: Option<String>,
    pub issuer: Option<GetIdentifierListItemResponseDTO>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifierProviderDetailResponseDTO {
    pub provider_name: Option<String>,
    pub issuer: Option<GetIdentifierListItemResponseDTO>,
}

#[derive(Clone, Debug, PartialEq, Eq, Default, From)]
#[from(OrganisationConfiguration)]
pub struct OrganisationConfigurationDTO {
    pub selected_ecosystems: Vec<EcosystemId>,
    pub enforce_ecosystem_as_issuer: bool,
    pub enforce_ecosystem_as_holder: bool,
    pub enforce_ecosystem_as_verifier: bool,
}

/// Partial update for `OrganisationConfiguration`: fields left `None` keep their current value.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct UpsertOrganisationConfigurationDTO {
    pub selected_ecosystems: Option<Vec<EcosystemId>>,
    pub enforce_ecosystem_as_issuer: Option<bool>,
    pub enforce_ecosystem_as_holder: Option<bool>,
    pub enforce_ecosystem_as_verifier: Option<bool>,
}

pub type GetOrganisationListResponseDTO = GetListResponse<GetOrganisationListItemResponseDTO>;

#[derive(Clone, Debug, Default)]
pub struct OrganisationFilterParamsDTO {
    pub created_date_after: Option<OffsetDateTime>,
    pub created_date_before: Option<OffsetDateTime>,
    pub last_modified_after: Option<OffsetDateTime>,
    pub last_modified_before: Option<OffsetDateTime>,
    pub has_parent_organisation: Option<bool>,
    pub parent_organisations: Option<Vec<OrganisationId>>,
}
