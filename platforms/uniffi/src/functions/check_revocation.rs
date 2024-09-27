use one_dto_mapper::convert_inner;

use crate::dto::CredentialRevocationCheckResponseBindingDTO;
use crate::error::BindingError;
use crate::utils::into_id;
use crate::OneCoreBinding;

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
                            .map(|id| into_id(id))
                            .collect::<Result<Vec<_>, _>>()?,
                    )
                    .await?,
            ))
        })
    }
}
