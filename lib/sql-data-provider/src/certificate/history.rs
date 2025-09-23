use std::sync::Arc;

use anyhow::Context;
use one_core::model::certificate::{
    Certificate, CertificateListQuery, CertificateRelations, CertificateState, GetCertificateList,
    UpdateCertificateRequest,
};
use one_core::model::history::{History, HistoryAction, HistoryEntityType};
use one_core::repository::certificate_repository::CertificateRepository;
use one_core::repository::error::DataLayerError;
use one_core::repository::history_repository::HistoryRepository;
use sea_orm::{DatabaseConnection, EntityTrait};
use shared_types::{CertificateId, IdentifierId, OrganisationId};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::entity::identifier;

pub struct CertificateHistoryDecorator {
    pub history_repository: Arc<dyn HistoryRepository>,
    pub inner: Arc<dyn CertificateRepository>,
    pub db: DatabaseConnection,
}

impl CertificateHistoryDecorator {
    async fn get_organisation_id_from_identifier_id(
        &self,
        identifier_id: IdentifierId,
    ) -> Option<OrganisationId> {
        identifier::Entity::find_by_id(identifier_id)
            .one(&self.db)
            .await
            .ok()
            .flatten()
            .and_then(|identifier| identifier.organisation_id)
    }

    async fn create_history(
        &self,
        id: CertificateId,
        name: String,
        action: HistoryAction,
        organisation_id: OrganisationId,
    ) {
        let result = self
            .history_repository
            .create_history(History {
                id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                action,
                name,
                target: None,
                entity_id: Some(id.into()),
                entity_type: HistoryEntityType::Certificate,
                metadata: None,
                organisation_id: Some(organisation_id),
                //TODO: pass user
                user: None,
            })
            .await;

        if let Err(error) = result {
            tracing::warn!(%error, "failed to insert certificate history event");
        }
    }
}

#[async_trait::async_trait]
impl CertificateRepository for CertificateHistoryDecorator {
    async fn get(
        &self,
        id: CertificateId,
        relations: &CertificateRelations,
    ) -> Result<Option<Certificate>, DataLayerError> {
        self.inner.get(id, relations).await
    }

    async fn list(
        &self,
        query_params: CertificateListQuery,
    ) -> Result<GetCertificateList, DataLayerError> {
        self.inner.list(query_params).await
    }

    async fn create(&self, request: Certificate) -> Result<CertificateId, DataLayerError> {
        let id = request.id;
        let name = request.name.clone();
        let organisation_id = self
            .get_organisation_id_from_identifier_id(request.identifier_id)
            .await;
        let certificate_id = self.inner.create(request).await?;

        if let Some(organisation_id) = organisation_id {
            self.create_history(id, name, HistoryAction::Created, organisation_id)
                .await;
        } else {
            tracing::warn!("certificate (id: {certificate_id}) missing organisation");
        }

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

        let certificate = self
            .inner
            .get(*id, &Default::default())
            .await?
            .context("certificate is missing")?;

        let organisation_id = self
            .get_organisation_id_from_identifier_id(certificate.identifier_id)
            .await;

        if let Some(organisation_id) = organisation_id {
            self.create_history(*id, certificate.name, history_action, organisation_id)
                .await;
        } else {
            tracing::warn!("certificate (id: {id}) missing organisation");
        }

        Ok(())
    }
}
