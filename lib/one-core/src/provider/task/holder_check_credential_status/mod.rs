mod dto;

#[cfg(test)]
mod test;

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use shared_types::OrganisationId;

use crate::error::ContextWithErrorCode;
use crate::model::credential::{CredentialFilterValue, CredentialRole, GetCredentialQuery};
use crate::model::list_filter::ListFilterValue;
use crate::provider::task::Task;
use crate::repository::credential_repository::CredentialRepository;
use crate::service::credential::CredentialService;
use crate::service::error::ServiceError;

pub struct HolderCheckCredentialStatus {
    params: Option<Params>,
    credential_repository: Arc<dyn CredentialRepository>,
    credential_service: CredentialService,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Params {
    pub organisation_id: Option<OrganisationId>,
    pub force_refresh: Option<bool>,
}

impl HolderCheckCredentialStatus {
    pub(crate) fn new(
        params: Option<Params>,
        credential_repository: Arc<dyn CredentialRepository>,
        credential_service: CredentialService,
    ) -> Self {
        Self {
            params,
            credential_repository,
            credential_service,
        }
    }
}

#[async_trait::async_trait]
impl Task for HolderCheckCredentialStatus {
    async fn run(&self) -> Result<Value, ServiceError> {
        let option = self
            .params
            .clone()
            .and_then(|p| p.organisation_id)
            .map(|id| CredentialFilterValue::OrganisationId(id).condition());

        let credentials = self
            .credential_repository
            .get_credential_list(GetCredentialQuery {
                filtering: Some(
                    CredentialFilterValue::Roles(vec![CredentialRole::Holder]).condition() & option,
                ),
                ..Default::default()
            })
            .await
            .error_while("getting certificates")?;

        let force_refresh = self
            .params
            .as_ref()
            .and_then(|p| p.force_refresh)
            .unwrap_or(false);
        self.credential_service
            .check_revocation(
                credentials.values.iter().map(|c| c.id).collect(),
                force_refresh,
            )
            .await?;

        let result = dto::HolderCheckCredentialStatusResultDTO {
            total_checks: credentials.total_items,
        };

        serde_json::to_value(result).map_err(|e| ServiceError::MappingError(e.to_string()))
    }
}
