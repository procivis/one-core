use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use uuid::Uuid;

use crate::model::revocation_list::RevocationListEntityInfo;
use crate::provider::signer::Signer;
use crate::repository::revocation_list_repository::RevocationListRepository;
use crate::service::error::{EntityNotFoundError, MissingProviderError, ServiceError};

#[async_trait]
pub(crate) trait SignerProvider: Send + Sync {
    async fn get_for_signature_id(&self, id: Uuid) -> Result<Arc<dyn Signer>, ServiceError>;

    fn get_from_type(&self, r#type: &str) -> Option<Arc<dyn Signer>>;
}

pub(crate) struct SignerProviderImpl {
    signers: HashMap<String, Arc<dyn Signer>>,
    revocation_list_repository: Arc<dyn RevocationListRepository>,
}

impl SignerProviderImpl {
    pub(crate) fn new(
        signers: HashMap<String, Arc<dyn Signer>>,
        revocation_list_repository: Arc<dyn RevocationListRepository>,
    ) -> Self {
        Self {
            signers,
            revocation_list_repository,
        }
    }
}

#[async_trait]
impl SignerProvider for SignerProviderImpl {
    async fn get_for_signature_id(&self, id: Uuid) -> Result<Arc<dyn Signer>, ServiceError> {
        let entry = self
            .revocation_list_repository
            .get_entry_by_id(id.into())
            .await?
            .ok_or(ServiceError::EntityNotFound(
                EntityNotFoundError::RevocationListEntry(id.into()),
            ))?;

        match entry.entity_info {
            RevocationListEntityInfo::Signature(sig_type) => self
                .get_from_type(sig_type.as_str())
                .ok_or(ServiceError::MissingProvider(MissingProviderError::Signer(
                    sig_type,
                ))),
            _ => Err(ServiceError::MappingError(
                "Invalid revocation list entry type".to_string(),
            )),
        }
    }

    fn get_from_type(&self, r#type: &str) -> Option<Arc<dyn Signer>> {
        self.signers.get(r#type).cloned()
    }
}
