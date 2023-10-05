use crate::{
    dto::KeyRequestBindingDTO,
    mapper::from_generate_key_request,
    utils::{into_uuid, run_sync},
    OneCoreBinding,
};
use one_core::service::error::ServiceError;

impl OneCoreBinding {
    pub fn generate_key(
        &self,
        organisation_id: String,
        request: &KeyRequestBindingDTO,
    ) -> Result<String, ServiceError> {
        run_sync(async {
            Ok(self
                .inner
                .key_service
                .generate_key(from_generate_key_request(
                    into_uuid(&organisation_id)?,
                    request,
                ))
                .await?
                .to_string())
        })
    }
}
