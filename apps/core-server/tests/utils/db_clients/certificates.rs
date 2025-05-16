use std::sync::Arc;

use one_core::model::certificate::{Certificate, CertificateRelations, CertificateState};
use one_core::model::key::Key;
use one_core::repository::certificate_repository::CertificateRepository;
use shared_types::{CertificateId, IdentifierId};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::fixtures::unwrap_or_random;

#[derive(Debug, Default)]
pub struct TestingCertificateParams {
    pub id: Option<CertificateId>,
    pub created_date: Option<OffsetDateTime>,
    pub last_modified: Option<OffsetDateTime>,
    pub expiry_date: Option<OffsetDateTime>,
    pub name: Option<String>,
    pub chain: Option<String>,
    pub state: Option<CertificateState>,
    pub key: Option<Key>,
}

pub struct CertificatesDB {
    repository: Arc<dyn CertificateRepository>,
}

impl CertificatesDB {
    pub fn new(repository: Arc<dyn CertificateRepository>) -> Self {
        Self { repository }
    }

    pub async fn create(
        &self,
        identifier_id: IdentifierId,
        params: TestingCertificateParams,
    ) -> Certificate {
        let now = OffsetDateTime::now_utc();

        let certificate = Certificate {
            id: params.id.unwrap_or(Uuid::new_v4().into()),
            identifier_id,
            created_date: params.created_date.unwrap_or(now),
            last_modified: params.last_modified.unwrap_or(now),
            expiry_date: params.expiry_date.unwrap_or(now),
            name: unwrap_or_random(params.name),
            chain: unwrap_or_random(params.chain),
            state: params.state.unwrap_or(CertificateState::Active),
            key: params.key,
            organisation: None,
        };

        self.repository.create(certificate.clone()).await.unwrap();

        certificate
    }

    pub async fn get(&self, certificate_id: CertificateId) -> Certificate {
        self.repository
            .get(
                certificate_id,
                &CertificateRelations {
                    key: Some(Default::default()),
                    organisation: Some(Default::default()),
                },
            )
            .await
            .unwrap()
            .unwrap()
    }
}
