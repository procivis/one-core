use one_dto_mapper::{From, Into};
use serde::{Deserialize, Serialize};
use shared_types::{InstanceId, KeyId, ManagedInstanceId, OrganisationId};
use strum::{AsRefStr, Display};
use time::OffsetDateTime;

use crate::config;
use crate::model::common::GetListResponse;
use crate::model::key::Key;
use crate::model::list_filter::ListFilterValue;
use crate::model::list_query::ListQuery;
use crate::model::organisation::Organisation;
use crate::model::relation::{Related, RelatedVec};
use crate::model::wallet_attestation::WalletAttestation;

#[derive(Clone, Debug)]
#[cfg_attr(any(test, feature = "mock"), derive(PartialEq))]
pub struct Instance {
    pub id: InstanceId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub provider_type: WalletProviderType,
    pub provider_name: String,
    pub provider_url: String,
    pub provider_instance_id: ManagedInstanceId,
    pub status: InstanceStatus,
    /// Integrity-check nonce issued by the server during registration; used in `holder_activate`.
    pub nonce: Option<String>,
    /// User-auth nonce issued by the server during registration; passed to the IdP during activation.
    pub user_nonce: Option<String>,
    pub role: InstanceRole,

    // Relations:
    pub organisation: Related<Organisation>,
    pub authentication_key: Option<Related<Key>>,
    pub wallet_attestations: RelatedVec<WalletAttestation>,
}

#[derive(
    Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, Display, AsRefStr, Into, From,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[into(config::core_config::WalletProviderType)]
#[from(config::core_config::WalletProviderType)]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
pub enum WalletProviderType {
    ProcivisOne,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, Display)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[strum(ascii_case_insensitive, serialize_all = "UPPERCASE")]
pub enum InstanceRole {
    Wallet,
    Verifier,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, Display)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InstanceStatus {
    Pending,
    Active,
    Revoked,
    Unattested,
    Error,
}

#[derive(Clone, Debug, Default)]
#[cfg_attr(any(test, feature = "mock"), derive(PartialEq))]
pub struct UpdateInstanceRequest {
    pub status: Option<InstanceStatus>,
    pub authentication_key_id: Option<KeyId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SortableInstanceColumn {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InstanceFilterValue {
    OrganisationIds(Vec<OrganisationId>),
    Role(InstanceRole),
    Status(InstanceStatus),
}

impl ListFilterValue for InstanceFilterValue {}

pub type InstanceListQuery = ListQuery<SortableInstanceColumn, InstanceFilterValue>;

pub type InstanceList = GetListResponse<Instance>;
