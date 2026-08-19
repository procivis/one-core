use serde::Serialize;
use shared_types::CredentialId;

/// Ecosystem-specific summary of one `ECOSYSTEM_LIFECYCLE_CHECK` run, surfaced as-is in the
/// task result.
#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct EudiLifecycleResultDTO {
    /// issued PIDs whose wallet attestations were inspected
    pub total_checks: u64,
    /// revoked through the credential's revocation method
    pub revoked_credential_ids: Vec<CredentialId>,
    /// could not be revoked
    pub failed_credential_ids: Vec<CredentialId>,
}
