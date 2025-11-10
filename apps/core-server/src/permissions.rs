use serde::Deserialize;

use crate::dto::response::ErrorResponse;
use crate::middleware::Authorized;
use crate::{AuthMode, ServerConfig};

#[derive(Debug, Clone, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Permission {
    CacheDelete,
    CredentialDelete,
    CredentialDetail,
    CredentialEdit,
    CredentialIssue,
    CredentialList,
    CredentialReactivate,
    CredentialRevoke,
    CredentialSchemaCreate,
    CredentialSchemaDelete,
    CredentialSchemaDetail,
    CredentialSchemaList,
    CredentialSchemaShare,
    CredentialShare,
    CredentialSuspend,
    DidCreate,
    DidDeactivate,
    DidDetail,
    DidList,
    DidResolve,
    HistoryDetail,
    HistoryList,
    HolderCredentialList,
    IdentifierCreate,
    IdentifierDelete,
    IdentifierDetail,
    IdentifierList,
    InteractionIssuance,
    InteractionProof,
    KeyCreate,
    KeyDetail,
    KeyGenerateCsr,
    KeyList,
    ProofClaimsDelete,
    ProofDelete,
    ProofDetail,
    ProofIssue,
    ProofList,
    ProofSchemaCreate,
    ProofSchemaDelete,
    ProofSchemaDetail,
    ProofSchemaList,
    ProofSchemaShare,
    ProofShare,
    StsOrganisationCreate,
    StsOrganisationDelete,
    StsOrganisationDetail,
    StsOrganisationEdit,
    StsOrganisationList,
    TaskCreate,
    TrustAnchorCreate,
    TrustAnchorDelete,
    TrustAnchorDetail,
    TrustAnchorList,
    TrustEntityActivate,
    TrustEntityCreate,
    TrustEntityDetail,
    TrustEntityEdit,
    TrustEntityList,
    TrustEntityRemove,
    TrustEntityWithdraw,
    HolderWalletUnitRegister,
    HolderWalletUnitDetail,
    WalletUnitDetail,
    WalletUnitList,
    WalletUnitRevoke,
    WalletUnitDelete,
    #[serde(untagged)]
    Unknown(String),
}

pub fn permission_check(
    authorized: &Authorized,
    config: &ServerConfig,
    required_permissions: &[Permission],
) -> Result<(), ErrorResponse> {
    let AuthMode::SecurityTokenService { .. } = config.auth else {
        return Ok(());
    };
    if !authorized
        .permissions
        .iter()
        .any(|p| required_permissions.contains(p))
    {
        tracing::trace!(
            "Permission check failed: authorized permissions are {:?}, required are any of {required_permissions:?}",
            authorized.permissions
        );
        return Err(ErrorResponse::Forbidden);
    };
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{AuthMode, StsTokenValidation};

    #[test]
    fn check_permissions_success() {
        let authorized = Authorized {
            permissions: vec![Permission::HistoryDetail, Permission::HistoryList],
        };
        let required = vec![Permission::HistoryDetail];

        assert!(permission_check(&authorized, &dummy_server_config(sts_auth()), &required).is_ok());
    }

    #[test]
    fn check_permissions_failure_mismatch() {
        let authorized = Authorized {
            permissions: vec![Permission::HistoryDetail],
        };
        let required = vec![Permission::HistoryList];

        assert!(
            permission_check(&authorized, &dummy_server_config(sts_auth()), &required).is_err()
        );
    }

    #[test]
    fn check_permissions_failure_empty_required() {
        let authorized = Authorized {
            permissions: vec![Permission::HistoryDetail],
        };
        let required = vec![];

        assert!(
            permission_check(&authorized, &dummy_server_config(sts_auth()), &required).is_err()
        );
    }

    #[test]
    fn check_permissions_failure_empty_authorized() {
        let authorized = Authorized {
            permissions: vec![],
        };
        let required = vec![Permission::HistoryList];

        assert!(
            permission_check(&authorized, &dummy_server_config(sts_auth()), &required).is_err()
        );
    }

    #[test]
    fn check_permissions_success_none_auth() {
        let authorized = Authorized {
            permissions: vec![],
        };
        let required = vec![Permission::HistoryList];

        // ok despite having fewer than required permissions, due to auth mode
        assert!(
            permission_check(
                &authorized,
                &dummy_server_config(AuthMode::InsecureNone),
                &required
            )
            .is_ok()
        );
    }

    #[test]
    fn check_permissions_success_static_auth() {
        let authorized = Authorized {
            permissions: vec![],
        };
        let required = vec![Permission::HistoryList];

        // ok despite having fewer than required permissions, due to auth mode
        assert!(
            permission_check(
                &authorized,
                &dummy_server_config(AuthMode::Static {
                    static_token: "test".to_string()
                }),
                &required
            )
            .is_ok()
        );
    }

    fn sts_auth() -> AuthMode {
        AuthMode::SecurityTokenService {
            sts_token_validation: StsTokenValidation {
                aud: "".to_string(),
                iss: "".to_string(),
                jwks_uri: "".to_string(),
                ttl_jwks: 0,
                leeway: 0,
            },
        }
    }

    fn dummy_server_config(auth: AuthMode) -> ServerConfig {
        ServerConfig {
            database_url: "".to_string(),
            server_ip: None,
            server_port: None,
            trace_json: None,
            core_base_url: "".to_string(),
            sentry_dsn: None,
            sentry_environment: None,
            trace_level: None,
            hide_error_response_cause: false,
            allow_insecure_http_transport: false,
            insecure_vc_api_endpoints_enabled: false,
            enable_metrics: false,
            enable_server_info: false,
            enable_open_api: false,
            enable_external_endpoints: false,
            enable_management_endpoints: false,
            enable_wallet_provider: false,
            auth,
        }
    }
}
