use serde::Serialize;
use shared_types::ManagedInstanceAttestationId;
use time::Duration;

use crate::config::core_config::IdentifierType;
use crate::service::managed_instance::dto::{IntegrityCheck, UserAuthenticationParams};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletProviderCapabilities {
    pub signer_identifier_types: Vec<IdentifierType>,
}

#[derive(Debug, Clone)]
pub(crate) struct WalletProviderRegistrationParams {
    pub name_label: String,
    pub integrity_check: IntegrityCheck,
    pub device_auth_leeway: Duration,
    pub user_authentication: Option<UserAuthenticationParams>,
}

#[derive(Debug, Clone)]
pub(crate) struct CreatedAttestation {
    pub jwt: String,
    pub id: ManagedInstanceAttestationId,
}
