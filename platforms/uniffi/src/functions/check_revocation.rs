use crate::{
    dto::CredentialRevocationCheckResponseBindingDTO, error::BindingError, utils::into_uuid,
    OneCoreBinding,
};
use one_core::common_mapper::convert_inner;

impl OneCoreBinding {
    pub fn check_revocation(
        &self,
        credential_ids: Vec<String>,
    ) -> Result<Vec<CredentialRevocationCheckResponseBindingDTO>, BindingError> {
        self.block_on(async {
            let core = self.use_core().await?;
            Ok(convert_inner(
                core.credential_service
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
