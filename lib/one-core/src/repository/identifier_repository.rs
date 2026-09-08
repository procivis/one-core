use std::sync::Arc;

use async_trait::async_trait;
use shared_types::{DidId, IdentifierId};

use crate::model::certificate::{
    Certificate, CertificateFilterValue, CertificateListQuery, SortableCertificateColumn,
};
use crate::model::common::SortDirection;
use crate::model::identifier::{
    GetIdentifierList, Identifier, IdentifierListQuery, UpdateIdentifierRequest,
};
use crate::model::identifier_trust_information::IdentifierTrustInformation;
use crate::model::list_filter::ListFilterValue;
use crate::model::list_query::ListSorting;
use crate::model::localized_text::LocalizedText;
use crate::model::relation::{AsyncModelLoader, AsyncVecLoader};
use crate::repository::certificate_repository::CertificateRepository;
use crate::repository::error::DataLayerError;
use crate::repository::identifier_trust_information_repository::IdentifierTrustInformationRepository;
use crate::repository::localized_text_repository::LocalizedTextRepository;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait]
pub trait IdentifierRepository: Send + Sync {
    async fn create(&self, request: Identifier) -> Result<IdentifierId, DataLayerError>;
    async fn get(&self, id: IdentifierId) -> Result<Identifier, DataLayerError>;
    async fn get_from_did_id(&self, did_id: DidId) -> Result<Option<Identifier>, DataLayerError>;
    async fn update(
        &self,
        id: &IdentifierId,
        request: UpdateIdentifierRequest,
    ) -> Result<(), DataLayerError>;
    async fn delete(&self, id: &IdentifierId) -> Result<(), DataLayerError>;

    async fn hard_delete(&self, id: &IdentifierId) -> Result<(), DataLayerError>;

    async fn get_identifier_list(
        &self,
        query_params: IdentifierListQuery,
    ) -> Result<GetIdentifierList, DataLayerError>;
}

#[async_trait]
impl AsyncModelLoader<Identifier> for Arc<dyn IdentifierRepository> {
    async fn load(&self, id: &IdentifierId) -> Result<Identifier, DataLayerError> {
        self.get(*id).await
    }
}

pub struct IdentifierCertificatesLoader {
    pub id: IdentifierId,
    pub certificate_repository: Arc<dyn CertificateRepository>,
}

#[async_trait::async_trait]
impl AsyncVecLoader<Certificate> for IdentifierCertificatesLoader {
    async fn load(&self) -> Result<Vec<Certificate>, DataLayerError> {
        let certificates = self
            .certificate_repository
            .list(CertificateListQuery {
                pagination: None,
                sorting: Some(ListSorting {
                    column: SortableCertificateColumn::ExpiryDate,
                    direction: Some(SortDirection::Descending),
                }),
                filtering: Some(CertificateFilterValue::IdentifierId(self.id).condition()),
                include: None,
            })
            .await?
            .values;
        Ok(certificates)
    }
}

pub struct IdentifierTrustInformationLoader {
    pub id: IdentifierId,
    pub trust_information_repository: Arc<dyn IdentifierTrustInformationRepository>,
}

#[async_trait::async_trait]
impl AsyncVecLoader<IdentifierTrustInformation> for IdentifierTrustInformationLoader {
    async fn load(&self) -> Result<Vec<IdentifierTrustInformation>, DataLayerError> {
        self.trust_information_repository
            .get_by_identifier_id(&self.id)
            .await
    }
}

pub struct IdentifierLocalizedTextLoader {
    pub id: IdentifierId,
    pub localized_text_repository: Arc<dyn LocalizedTextRepository>,
}

#[async_trait::async_trait]
impl AsyncVecLoader<LocalizedText> for IdentifierLocalizedTextLoader {
    async fn load(&self) -> Result<Vec<LocalizedText>, DataLayerError> {
        self.localized_text_repository.get(&self.id.into()).await
    }
}
