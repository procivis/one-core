use std::sync::Arc;

use one_core::model::certificate::{
    Certificate, CertificateRole, CertificateState, UpdateCertificateRequest,
};
use one_core::model::key::Key;
use one_core::model::organisation::Organisation;
use one_core::model::relation::Related;
use one_core::repository::certificate_repository::CertificateRepository;
use shared_types::{CertificateId, IdentifierId};
use time::OffsetDateTime;

use crate::fixtures::unwrap_or_random;

#[derive(Debug, Default)]
pub struct TestingCertificateParams {
    pub id: Option<CertificateId>,
    pub created_date: Option<OffsetDateTime>,
    pub last_modified: Option<OffsetDateTime>,
    pub expiry_date: Option<OffsetDateTime>,
    pub name: Option<String>,
    pub chain: Option<String>,
    pub fingerprint: Option<String>,
    pub state: Option<CertificateState>,
    pub key: Option<Key>,
    pub roles: Option<Vec<CertificateRole>>,
}

impl TestingCertificateParams {
    pub(crate) async fn from(certificate: Certificate) -> Self {
        let key = match certificate.key {
            None => None,
            Some(key) => Some(key.as_ref().await.unwrap().to_owned()),
        };
        Self {
            id: Some(certificate.id),
            created_date: Some(certificate.created_date),
            last_modified: Some(certificate.last_modified),
            expiry_date: Some(certificate.expiry_date),
            name: Some(certificate.name),
            chain: Some(certificate.chain),
            fingerprint: Some(certificate.fingerprint),
            state: Some(certificate.state),
            key,
            roles: Some(certificate.roles),
        }
    }
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
        organisation: impl Into<Related<Organisation>>,
        params: TestingCertificateParams,
    ) -> Certificate {
        let now = one_core::clock::now_utc();

        let certificate = Certificate {
            id: params.id.unwrap_or(CertificateId::new()),
            identifier_id,
            created_date: params.created_date.unwrap_or(now),
            last_modified: params.last_modified.unwrap_or(now),
            expiry_date: params.expiry_date.unwrap_or(now),
            name: unwrap_or_random(params.name),
            chain: unwrap_or_random(params.chain),
            fingerprint: unwrap_or_random(params.fingerprint),
            state: params.state.unwrap_or(CertificateState::Active),
            roles: params.roles.unwrap_or(vec![
                CertificateRole::Authentication,
                CertificateRole::AssertionMethod,
            ]),
            key: params.key.map(Into::into),
            organisation: organisation.into(),
            deleted_at: None,
        };

        self.repository.create(certificate.clone()).await.unwrap();

        certificate
    }

    pub async fn get(&self, certificate_id: CertificateId) -> Certificate {
        self.repository.get(certificate_id).await.unwrap()
    }

    pub async fn update(&self, certificate_id: &CertificateId, request: UpdateCertificateRequest) {
        self.repository
            .update(certificate_id, request)
            .await
            .unwrap();
    }
}
