use shared_types::{CredentialId, NonceId, ProofId};

use super::error::DataLayerError;
use crate::model::common::LockType;
use crate::model::interaction::{
    Interaction, InteractionId, InteractionRelations, UpdateInteractionRequest,
};

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
        relations: &InteractionRelations,
        lock: Option<LockType>,
    ) -> Result<Option<Interaction>, DataLayerError>;

    async fn mark_nonce_as_used(
        &self,
        interaction_id: &InteractionId,
        nonce_id: NonceId,
    ) -> Result<(), DataLayerError>;

    async fn delete_interaction(&self, id: &InteractionId) -> Result<(), DataLayerError>;

    // interaction expiration check
    async fn update_expired_credentials(&self) -> Result<Vec<CredentialId>, DataLayerError>;
    async fn update_expired_proofs(&self) -> Result<Vec<ProofId>, DataLayerError>;
}
