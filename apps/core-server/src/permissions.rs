use crate::ServerConfig;
use crate::dto::response::ErrorResponse;
use crate::middleware::Authorized;

#[derive(Debug, Clone, Eq, PartialEq)]
#[allow(dead_code)]
pub enum Permission {
    DummyPermission,
    DummyPermission2,
}

#[allow(dead_code)]
pub fn permission_check(
    authorized: &Authorized,
    _config: &ServerConfig,
    required_permissions: &[Permission],
) -> Result<(), ErrorResponse> {
    // TODO: Skip permission check if not in STS-Mode
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

    #[test]
    fn check_permissions_success() {
        let authorized = Authorized {
            permissions: vec![Permission::DummyPermission, Permission::DummyPermission2],
        };
        let required = vec![Permission::DummyPermission];

        assert!(permission_check(&authorized, &dummy_server_config(), &required).is_ok());
    }

    #[test]
    fn check_permissions_failure_mismatch() {
        let authorized = Authorized {
            permissions: vec![Permission::DummyPermission],
        };
        let required = vec![Permission::DummyPermission2];

        assert!(permission_check(&authorized, &dummy_server_config(), &required).is_err());
    }

    #[test]
    fn check_permissions_failure_empty_required() {
        let authorized = Authorized {
            permissions: vec![Permission::DummyPermission],
        };
        let required = vec![];

        assert!(permission_check(&authorized, &dummy_server_config(), &required).is_err());
    }

    #[test]
    fn check_permissions_failure_empty_authorized() {
        let authorized = Authorized {
            permissions: vec![],
        };
        let required = vec![Permission::DummyPermission2];

        assert!(permission_check(&authorized, &dummy_server_config(), &required).is_err());
    }

    fn dummy_server_config() -> ServerConfig {
        ServerConfig {
            database_url: "".to_string(),
            server_ip: None,
            server_port: None,
            trace_json: None,
            auth_token: "".to_string(),
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
        }
    }
}
