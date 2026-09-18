use std::sync::Arc;

use shared_types::WalletAttestationId;
use uuid::Uuid;

use crate::model::history::{
    History, HistoryAction, HistoryEntityType, HistoryMetadata, HistorySource,
};
use crate::model::wallet_attestation::{
    AttestationType, WalletAttestation, WalletAttestationList, WalletAttestationListQuery,
};
use crate::proto::session_provider::{SessionExt, SessionProvider};
use crate::repository::error::DataLayerError;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::instance_repository::InstanceRepository;
use crate::repository::wallet_attestation_repository::WalletAttestationRepository;

pub struct WalletAttestationHistoryDecorator {
    pub history_repository: Arc<dyn HistoryRepository>,
    pub inner: Arc<dyn WalletAttestationRepository>,
    pub instance_repository: Arc<dyn InstanceRepository>,
    pub session_provider: Arc<dyn SessionProvider>,
}

#[async_trait::async_trait]
impl WalletAttestationRepository for WalletAttestationHistoryDecorator {
    async fn create(
        &self,
        wallet_attestation: WalletAttestation,
    ) -> Result<WalletAttestationId, DataLayerError> {
        let instance_id = wallet_attestation.instance_id;
        let history = History {
            id: Uuid::new_v4().into(),
            created_date: crate::clock::now_utc(),
            action: match wallet_attestation.r#type {
                AttestationType::WalletInstanceAttestation => HistoryAction::WiaCreated,
                AttestationType::KeyAttestation => HistoryAction::KaCreated,
            },
            source: HistorySource::Core,
            target: None,
            entity_id: Some(instance_id.into()),
            entity_type: HistoryEntityType::Instance,
            metadata: Some(HistoryMetadata::WalletAttestation(wallet_attestation.id)),
            metadata_blob_id: None,
            user: self.session_provider.session().user(),

            // will be filled from instance
            name: Default::default(),
            organisation_id: Default::default(),
        };

        let id = self.inner.create(wallet_attestation).await?;

        match self.instance_repository.get(&instance_id).await {
            Err(error) => {
                tracing::warn!(%error, "failed to load wallet attestation instance");
            }
            Ok(instance) => {
                if let Err(error) = self
                    .history_repository
                    .create_history(History {
                        name: instance.provider_name.clone(),
                        organisation_id: Some(instance.organisation.id()),
                        ..history
                    })
                    .await
                {
                    tracing::warn!(%error, "failed to insert wallet attestation history event");
                }
            }
        };

        Ok(id)
    }

    async fn get_attestations(
        &self,
        query: WalletAttestationListQuery,
    ) -> Result<WalletAttestationList, DataLayerError> {
        self.inner.get_attestations(query).await
    }
}
