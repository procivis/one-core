use std::sync::Arc;

use serde::Deserialize;
use serde_json::Value;
use shared_types::OrganisationId;

use crate::error::ContextWithErrorCode;
use crate::model::credential::{
    CredentialFilterValue, CredentialListQuery, CredentialRole, CredentialType,
};
use crate::model::list_filter::ListFilterValue;
use crate::proto::credential_validity_manager::CredentialValidityManager;
use crate::provider::task::Task;
use crate::repository::credential_repository::CredentialRepository;
use crate::service::error::ServiceError;

mod dto;

#[cfg(test)]
mod test;

pub struct HolderCheckCredentialStatus {
    credential_repository: Arc<dyn CredentialRepository>,
    credential_validity_manager: Arc<dyn CredentialValidityManager>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct Params {
    pub organisation_id: Option<OrganisationId>,
    #[serde(default)]
    pub force_refresh: bool,
}

impl HolderCheckCredentialStatus {
    pub(crate) fn new(
        credential_repository: Arc<dyn CredentialRepository>,
        credential_validity_manager: Arc<dyn CredentialValidityManager>,
    ) -> Self {
        Self {
            credential_repository,
            credential_validity_manager,
        }
    }
}

#[async_trait::async_trait]
impl Task for HolderCheckCredentialStatus {
    async fn run(&self, params: Option<Value>) -> Result<Value, ServiceError> {
        let params: Params = if let Some(params) = params {
            serde_json::from_value(params)
                .map_err(|e| ServiceError::ValidationError(e.to_string()))?
        } else {
            Default::default()
        };

        let organisation_id = params
            .organisation_id
            .map(CredentialFilterValue::OrganisationId);

        let credentials = self
            .credential_repository
            .get_credential_list(CredentialListQuery {
                include_count: false,
                filtering: Some(
                    CredentialFilterValue::Roles(vec![CredentialRole::Holder]).condition()
                        & CredentialFilterValue::Types(vec![
                            CredentialType::Single,
                            CredentialType::BatchParent,
                        ])
                        & organisation_id
                        & CredentialFilterValue::Deleted(false),
                ),
                ..Default::default()
            })
            .await
            .error_while("getting certificates")?;

        for credential in credentials.values.iter() {
            self.credential_validity_manager
                .check_holder_credential_validity(credential.id, params.force_refresh)
                .await
                .error_while("checking credential validity")?;
        }

        let result = dto::HolderCheckCredentialStatusResultDTO {
            total_checks: credentials.values.len() as u64,
        };

        serde_json::to_value(result).map_err(|e| ServiceError::MappingError(e.to_string()))
    }
}
