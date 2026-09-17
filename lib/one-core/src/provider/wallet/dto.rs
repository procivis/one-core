use serde::Serialize;
use shared_types::ManagedInstanceAttestationId;

use crate::config::core_config::IdentifierType;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletProviderCapabilities {
    pub signer_identifier_types: Vec<IdentifierType>,
}

#[derive(Debug, Clone)]
pub(crate) struct CreatedAttestation {
    pub jwt: String,
    pub id: ManagedInstanceAttestationId,
}
