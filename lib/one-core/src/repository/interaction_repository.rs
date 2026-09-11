use std::sync::Arc;

use shared_types::{CredentialId, InteractionId, NonceId, ProofId};

use super::error::DataLayerError;
use crate::model::common::LockType;
use crate::model::interaction::{Interaction, UpdateInteractionRequest};
use crate::model::relation::AsyncModelLoader;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait InteractionRepository: Send + Sync {
    async fn create_interaction(
        &self,
        request: Interaction,
    ) -> Result<InteractionId, DataLayerError>;

    async fn update_interaction(
        &self,
        id: InteractionId,
        request: UpdateInteractionRequest,
    ) -> Result<(), DataLayerError>;

    /// Loads an interaction from the database, including the specified relations.
    /// If a lock type is specified, it will lock the given row. The lock only takes effect if
    /// loaded **within a transaction**.
    async fn get_interaction(
        &self,
        id: &InteractionId,
        lock: Option<LockType>,
    ) -> Result<Interaction, DataLayerError>;

    async fn mark_nonces_as_used(
        &self,
        interaction_id: &InteractionId,
        nonce_ids: Vec<NonceId>,
    ) -> Result<(), DataLayerError>;

    async fn delete_interaction(&self, id: &InteractionId) -> Result<(), DataLayerError>;

    // interaction expiration check
    async fn update_expired_credentials(&self) -> Result<Vec<CredentialId>, DataLayerError>;
    async fn update_expired_proofs(&self) -> Result<Vec<ProofId>, DataLayerError>;
}

#[async_trait::async_trait]
impl AsyncModelLoader<Interaction> for Arc<dyn InteractionRepository> {
    async fn load(&self, id: &InteractionId) -> Result<Interaction, DataLayerError> {
        self.get_interaction(id, None).await
    }
}
