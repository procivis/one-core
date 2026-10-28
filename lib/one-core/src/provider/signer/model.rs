use serde::Serialize;
use shared_types::Permission;

use crate::config::core_config::{IdentifierType, KeyAlgorithmType, RevocationType};

/// What a signer supports and requires. Serialized into the signer's
/// capabilities in the configuration output.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignerCapabilities {
    /// Optional behaviors this signer instance supports. May depend on
    /// configuration; empty when the signer is disabled.
    pub features: Vec<Feature>,
    /// Identifier types accepted as issuer. Checked by the signature
    /// service and by the `CapabilityChecked` wrapper.
    pub supported_identifiers: Vec<IdentifierType>,
    /// Permissions of which the caller needs at least one to sign.
    /// Enforced by the `PermissionChecked` wrapper, in STS authentication
    /// mode only.
    pub sign_required_permissions: Vec<Permission>,
    /// Permissions of which the caller needs at least one to revoke.
    /// Enforced by the signature service, in STS authentication mode only.
    pub revoke_required_permissions: Vec<Permission>,
    /// Key algorithms the signer can sign with. Checked by the
    /// `CapabilityChecked` wrapper for key issuers only; for identifier
    /// issuers, an unsupported algorithm fails during signing.
    pub signing_key_algorithms: Vec<KeyAlgorithmType>,
    /// Revocation types compatible with this signer. The configured
    /// revocation method is validated against this list at initialization.
    pub revocation_methods: Vec<RevocationType>,
}

/// Optional signer behaviors, reported in [`SignerCapabilities::features`].
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Feature {
    SupportsSelfSigned,
    SupportsCaSigned,
}
