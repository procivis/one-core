use shared_types::Permission;

use crate::dto::response::ErrorResponse;
use crate::middleware::{Authorized, Permissions};

pub fn permission_check(
    authorized: &Authorized,
    required_permissions: &[Permission],
) -> Result<(), ErrorResponse> {
    if required_permissions.is_empty() {
        tracing::error!("Required permissions are empty.");
        return Err(ErrorResponse::Forbidden);
    }

    match &authorized.permissions {
        Permissions::All => Ok(()),
        Permissions::Subset(permissions) => {
            if !permissions.iter().any(|p| required_permissions.contains(p)) {
                tracing::info!(
                    "Permission check failed: authorized permissions are {:?}, required are any of {required_permissions:?}",
                    authorized.permissions
                );
                Err(ErrorResponse::Forbidden)
            } else {
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn check_permissions_success_subset_exactly_one_match() {
        let authorized = Authorized {
            permissions: Permissions::Subset(vec![
                Permission::HistoryDetail,
                Permission::HistoryList,
            ]),
        };
        let required = vec![Permission::HistoryDetail];

        assert!(permission_check(&authorized, &required).is_ok());
    }

    #[test]
    fn check_permissions_success_subset_at_least_one_match() {
        let authorized = Authorized {
            permissions: Permissions::Subset(vec![
                Permission::HistoryDetail,
                Permission::HistoryList,
            ]),
        };
        let required = vec![Permission::HistoryDetail, Permission::HistoryCreate];

        assert!(permission_check(&authorized, &required).is_ok());
    }

    #[test]
    fn check_permissions_failure_subset_mismatch() {
        let authorized = Authorized {
            permissions: Permissions::Subset(vec![Permission::HistoryDetail]),
        };
        let required = vec![Permission::HistoryList];

        assert!(permission_check(&authorized, &required).is_err());
    }

    #[test]
    fn check_permissions_success_all_permissions() {
        let authorized = Authorized {
            permissions: Permissions::All,
        };
        let required = vec![Permission::HistoryList];

        assert!(permission_check(&authorized, &required).is_ok());
    }

    #[test]
    fn check_permissions_failure_subset_empty_required() {
        let authorized = Authorized {
            permissions: Permissions::Subset(vec![Permission::HistoryDetail]),
        };
        let required = vec![];

        assert!(permission_check(&authorized, &required).is_err());
    }

    #[test]
    fn check_permissions_failure_all_permissions_empty_required() {
        let authorized = Authorized {
            permissions: Permissions::All,
        };
        let required = vec![];

        assert!(permission_check(&authorized, &required).is_err());
    }
}
