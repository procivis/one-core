use async_trait::async_trait;
use shared_types::CertificateId;

use crate::model::certificate::{Certificate, CertificateRelations, UpdateCertificateRequest};
use crate::repository::error::DataLayerError;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait]
pub trait CertificateRepository: Send + Sync {
    async fn create(&self, request: Certificate) -> Result<CertificateId, DataLayerError>;
    async fn get(
        &self,
        id: CertificateId,
        relations: &CertificateRelations,
    ) -> Result<Option<Certificate>, DataLayerError>;
    async fn update(
        &self,
        id: &CertificateId,
        request: UpdateCertificateRequest,
    ) -> Result<(), DataLayerError>;
}
