use shared_types::Permission;

use crate::proto::session_provider::SessionProvider;
use crate::service::error::{ServiceError, ValidationError};

pub(crate) struct RequiredPermssions {
    /// At least one of the permissions must be present
    pub at_least_one: Vec<Permission>,
    /// All permissions must be present
    pub all: Vec<Permission>,
}

impl RequiredPermssions {
    #[expect(unused)]
    pub(crate) fn all(permissions: Vec<Permission>) -> Self {
        Self {
            at_least_one: vec![],
            all: permissions,
        }
    }

    pub(crate) fn at_least_one(permissions: Vec<Permission>) -> Self {
        Self {
            at_least_one: permissions,
            all: vec![],
        }
    }

    pub(crate) fn check(&self, session_provider: &dyn SessionProvider) -> Result<(), ServiceError> {
        check_permissions(self, session_provider)
    }
}

/// Checks if the current session (if any) has the required permissions.
pub(crate) fn check_permissions(
    permission_check: &RequiredPermssions,
    session_provider: &dyn SessionProvider,
) -> Result<(), ServiceError> {
    let Some(session) = session_provider.session() else {
        return Ok(());
    };
    if !permission_check
        .at_least_one
        .iter()
        .any(|p| session.permissions.contains(p))
    {
        return Err(ValidationError::Forbidden.into());
    }
    if !permission_check
        .all
        .iter()
        .all(|p| session.permissions.contains(p))
    {
        return Err(ValidationError::Forbidden.into());
    }
    Ok(())
}
