use crate::{
    utils::{into_uuid, run_sync},
    OneCoreBinding,
};
use one_core::{
    model::did::DidType,
    service::{did::dto::CreateDidRequestDTO, error::ServiceError},
};

impl OneCoreBinding {
    pub fn create_local_did(
        &self,
        did: String,
        organisation_id: String,
    ) -> Result<String, ServiceError> {
        run_sync(async {
            self.inner
                .did_service
                .create_did(CreateDidRequestDTO {
                    name: "local".to_string(),
                    organisation_id: into_uuid(&organisation_id)?,
                    did,
                    did_type: DidType::Local,
                    did_method: "KEY".to_string(),
                })
                .await
                .map(|id| id.to_string())
        })
    }
}
