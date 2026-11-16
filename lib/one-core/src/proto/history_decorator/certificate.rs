use std::sync::Arc;

use shared_types::{CertificateId, HistoryId, IdentifierId, OrganisationId};

use crate::model::certificate::{
    Certificate, CertificateListQuery, CertificateState, GetCertificateList,
    UpdateCertificateRequest,
};
use crate::model::history::{History, HistoryAction, HistoryEntityType, HistorySource};
use crate::proto::session_provider::{SessionExt, SessionProvider};
use crate::repository::certificate_repository::CertificateRepository;
use crate::repository::error::DataLayerError;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::identifier_repository::IdentifierRepository;

pub struct CertificateHistoryDecorator {
    pub history_repository: Arc<dyn HistoryRepository>,
    pub session_provider: Arc<dyn SessionProvider>,
    pub inner: Arc<dyn CertificateRepository>,
    pub identifier_repository: Arc<dyn IdentifierRepository>,
}

impl CertificateHistoryDecorator {
    async fn get_organisation_id_from_identifier_id(
        &self,
        identifier_id: IdentifierId,
    ) -> Result<OrganisationId, DataLayerError> {
        Ok(self
            .identifier_repository
            .get(identifier_id)
            .await?
            .organisation
            .id())
    }

    async fn create_history(
        &self,
        id: CertificateId,
        name: String,
        action: HistoryAction,
        identifier_id: IdentifierId,
    ) {
        let organisation_id = match self
            .get_organisation_id_from_identifier_id(identifier_id)
            .await
        {
            Ok(organisation_id) => organisation_id,
            Err(error) => {
                tracing::warn!(%error, "identifier_id (id: {identifier_id}) fetch failure");
                return;
            }
        };

        let result = self
            .history_repository
            .create_history(History {
                id: HistoryId::new(),
                created_date: crate::clock::now_utc(),
                action,
                name,
                source: HistorySource::Core,
                target: None,
                entity_id: Some(id.into()),
                entity_type: HistoryEntityType::Certificate,
                metadata: None,
                metadata_blob_id: None,
                organisation_id: Some(organisation_id),
                user: self.session_provider.session().user(),
            })
            .await;

        if let Err(error) = result {
            tracing::warn!(%error, "failed to insert certificate history event");
        }
    }
}

#[async_trait::async_trait]
impl CertificateRepository for CertificateHistoryDecorator {
    async fn get(&self, id: CertificateId) -> Result<Certificate, DataLayerError> {
        self.inner.get(id).await
    }

    async fn list(
        &self,
        query_params: CertificateListQuery,
    ) -> Result<GetCertificateList, DataLayerError> {
        self.inner.list(query_params).await
    }

    async fn create(&self, request: Certificate) -> Result<CertificateId, DataLayerError> {
        let name = request.name.clone();
        let identifier_id = request.identifier_id;
        let certificate_id = self.inner.create(request).await?;

        self.create_history(certificate_id, name, HistoryAction::Created, identifier_id)
            .await;

        Ok(certificate_id)
    }

    async fn update(
        &self,
        id: &CertificateId,
        request: UpdateCertificateRequest,
    ) -> Result<(), DataLayerError> {
        self.inner.update(id, request.clone()).await?;

        let Some(new_state) = request.state else {
            return Ok(());
        };

        let history_action = match new_state {
            CertificateState::NotYetActive => HistoryAction::Deactivated,
            CertificateState::Active => HistoryAction::Activated,
            CertificateState::Revoked => HistoryAction::Revoked,
            CertificateState::Expired => HistoryAction::Expired,
        };

        let certificate = self.inner.get(*id).await?;

        self.create_history(
            *id,
            certificate.name,
            history_action,
            certificate.identifier_id,
        )
        .await;

        Ok(())
    }

    async fn delete(&self, certificate: &Certificate) -> Result<(), DataLayerError> {
        let id = certificate.id;
        let name = certificate.name.clone();
        let identifier_id = certificate.identifier_id;

        self.inner.delete(certificate).await?;

        self.create_history(id, name, HistoryAction::Deleted, identifier_id)
            .await;

        Ok(())
    }
}
