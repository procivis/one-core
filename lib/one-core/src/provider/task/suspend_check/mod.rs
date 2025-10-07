use std::sync::Arc;

use serde_json::Value;
use time::OffsetDateTime;

use self::dto::SuspendCheckResultDTO;
use super::Task;
use crate::model::credential::{
    CredentialFilterValue, CredentialRole, CredentialStateEnum, GetCredentialQuery,
};
use crate::model::list_filter::{ComparisonType, ListFilterValue, ValueComparison};
use crate::repository::credential_repository::CredentialRepository;
use crate::service::credential::CredentialService;
use crate::service::error::ServiceError;

pub mod dto;

pub(crate) struct SuspendCheckProvider {
    credential_repository: Arc<dyn CredentialRepository>,
    credential_service: CredentialService,
}

impl SuspendCheckProvider {
    pub fn new(
        credential_repository: Arc<dyn CredentialRepository>,
        credential_service: CredentialService,
    ) -> Self {
        SuspendCheckProvider {
            credential_repository,
            credential_service,
        }
    }
}

#[async_trait::async_trait]
impl Task for SuspendCheckProvider {
    async fn run(&self) -> Result<Value, ServiceError> {
        let credential_list = self
            .credential_repository
            .get_credential_list(GetCredentialQuery {
                filtering: Some(
                    CredentialFilterValue::States(vec![CredentialStateEnum::Suspended]).condition()
                        & CredentialFilterValue::Roles(vec![CredentialRole::Issuer])
                        & CredentialFilterValue::SuspendEndDate(ValueComparison {
                            comparison: ComparisonType::LessThan,
                            value: OffsetDateTime::now_utc(),
                        }),
                ),
                ..Default::default()
            })
            .await?;

        let credentials = credential_list.values;

        for credential in &credentials {
            self.credential_service
                .reactivate_credential(&credential.id)
                .await?;
        }

        let result = SuspendCheckResultDTO {
            updated_credential_ids: credentials.iter().map(|credential| credential.id).collect(),
            total_checks: credential_list.total_items,
        };

        serde_json::to_value(result).map_err(|e| ServiceError::MappingError(e.to_string()))
    }
}
