use proc_macros::Model;
use shared_types::{EcosystemId, IdentifierId, OrganisationId};
use time::OffsetDateTime;

use super::common::GetListResponse;
use super::list_filter::{ListFilterValue, ValueComparison};
use super::list_query::ListQuery;
use super::relation::Related;

#[derive(Clone, Debug, Model)]
#[cfg_attr(any(test, feature = "mock"), derive(PartialEq))]
pub struct Organisation {
    #[model(id)]
    pub id: OrganisationId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub deactivated_at: Option<OffsetDateTime>,
    pub wallet_provider: Option<String>,
    pub wallet_provider_issuer: Option<IdentifierId>,
    pub parent_organisation: Option<Related<Organisation>>,
    pub verifier_provider: Option<String>,
    pub verifier_provider_issuer: Option<IdentifierId>,
    pub configuration: OrganisationConfiguration,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct OrganisationConfiguration {
    pub selected_ecosystems: Vec<EcosystemId>,
    pub enforce_ecosystem_as_issuer: bool,
    pub enforce_ecosystem_as_holder: bool,
    pub enforce_ecosystem_as_verifier: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct UpdateOrganisationRequest {
    pub deactivate: Option<bool>,
    pub wallet_provider: Option<Option<String>>,
    pub wallet_provider_issuer: Option<Option<IdentifierId>>,
    pub parent_organisation: Option<Option<OrganisationId>>,
    pub verifier_provider: Option<Option<String>>,
    pub verifier_provider_issuer: Option<Option<IdentifierId>>,
    pub configuration: Option<OrganisationConfiguration>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SortableOrganisationColumn {
    CreatedDate,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OrganisationFilterValue {
    CreatedDate(ValueComparison<OffsetDateTime>),
    LastModified(ValueComparison<OffsetDateTime>),
    HasParentOrganisation(bool),
    ParentOrganisations(Vec<OrganisationId>),
}

impl ListFilterValue for OrganisationFilterValue {}

pub type OrganisationListQuery = ListQuery<SortableOrganisationColumn, OrganisationFilterValue>;

pub type GetOrganisationList<Count = Option<u64>> = GetListResponse<Organisation, Count>;
