use serde::Serialize;

use crate::config::core_config::IdentifierType;

#[derive(Debug, Clone, Serialize)]
pub struct SignerCapabilities {
    pub supported_identifiers: Vec<IdentifierType>,
    pub sign_required_permissions: Vec<&'static str>,
    pub revoke_required_permissions: Vec<&'static str>,
}
