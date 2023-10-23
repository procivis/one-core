use crate::{
    dto::CredentialRevocationCheckResponseBindingDTO,
    utils::{into_uuid, run_sync},
    OneCoreBinding,
};
use one_core::{common_mapper::vector_into, service::error::ServiceError};

impl OneCoreBinding {
    pub fn check_revocation(
        &self,
        credential_ids: Vec<String>,
    ) -> Result<Vec<CredentialRevocationCheckResponseBindingDTO>, ServiceError> {
        run_sync(async {
            Ok(vector_into(
                self.inner
                    .credential_service
                    .check_revocation(
                        credential_ids
                            .iter()
                            .map(|id| into_uuid(id))
                            .collect::<Result<Vec<_>, _>>()?,
                    )
                    .await?,
            ))
        })
    }
}
