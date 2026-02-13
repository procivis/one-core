use std::sync::Arc;

use serde_json::Value;
use time::OffsetDateTime;

use self::dto::SuspendCheckResultDTO;
use super::Task;
use crate::error::ContextWithErrorCode;
use crate::model::credential::{
    CredentialFilterValue, CredentialRole, CredentialStateEnum, GetCredentialQuery,
};
use crate::model::list_filter::{ComparisonType, ListFilterValue, ValueComparison};
use crate::proto::credential_validity_manager::CredentialValidityManager;
use crate::provider::revocation::model::RevocationState;
use crate::repository::credential_repository::CredentialRepository;
use crate::service::error::ServiceError;

pub mod dto;

pub(crate) struct SuspendCheckProvider {
    credential_repository: Arc<dyn CredentialRepository>,
    credential_validity_manager: Arc<dyn CredentialValidityManager>,
}

impl SuspendCheckProvider {
    pub fn new(
        credential_repository: Arc<dyn CredentialRepository>,
        credential_validity_manager: Arc<dyn CredentialValidityManager>,
    ) -> Self {
        SuspendCheckProvider {
            credential_repository,
            credential_validity_manager,
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
            .await
            .error_while("getting credentials")?;

        let credentials = credential_list.values;

        for credential in &credentials {
            self.credential_validity_manager
                .change_credential_validity_state(&credential.id, RevocationState::Valid)
                .await
                .error_while("reactivating credential")?;
        }

        let result = SuspendCheckResultDTO {
            updated_credential_ids: credentials.iter().map(|credential| credential.id).collect(),
            total_checks: credential_list.total_items,
        };

        serde_json::to_value(result).map_err(|e| ServiceError::MappingError(e.to_string()))
    }
}
