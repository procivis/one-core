use serde::Serialize;
use shared_types::Permission;

use crate::config::core_config::{IdentifierType, KeyAlgorithmType, RevocationType};

#[derive(Debug, Clone, Serialize)]
pub struct SignerCapabilities {
    pub features: Vec<Feature>,
    pub supported_identifiers: Vec<IdentifierType>,
    pub sign_required_permissions: Vec<Permission>,
    pub revoke_required_permissions: Vec<Permission>,
    pub signing_key_algorithms: Vec<KeyAlgorithmType>,
    pub revocation_methods: Vec<RevocationType>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Feature {
    SupportsSelfSigned,
}
