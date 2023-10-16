use crate::{revocation::RevocationMethod, service::error::ServiceError};
use mockall::*;
use std::sync::Arc;

#[derive(Default)]
struct RevocationMethodProvider;

mock! {
    pub(crate) RevocationMethodProvider {
        pub fn get_revocation_method(
            &self,
            revocation_method_id: &str,
        ) -> Result<Arc<dyn RevocationMethod + Send + Sync>, ServiceError>;
    }
}

impl crate::revocation::provider::RevocationMethodProvider for MockRevocationMethodProvider {
    fn get_revocation_method(
        &self,
        revocation_method_id: &str,
    ) -> Result<Arc<dyn RevocationMethod + Send + Sync>, ServiceError> {
        self.get_revocation_method(revocation_method_id)
    }
}
