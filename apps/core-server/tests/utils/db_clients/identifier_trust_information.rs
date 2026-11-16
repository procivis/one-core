use std::sync::Arc;

use one_core::model::identifier_trust_information::{IdentifierTrustInformation, SchemaFormat};
use one_core::repository::identifier_trust_information_repository::IdentifierTrustInformationRepository;
use shared_types::{BlobId, IdentifierId, IdentifierTrustInformationId};

#[derive(Debug, Default)]
pub struct TestingIdentifierTrustInformationParams {
    pub id: Option<IdentifierTrustInformationId>,
    pub valid_from: Option<time::OffsetDateTime>,
    pub valid_to: Option<time::OffsetDateTime>,
    pub intended_use: Option<String>,
    pub allowed_issuance_types: Option<Vec<SchemaFormat>>,
    pub allowed_verification_types: Option<Vec<SchemaFormat>>,
}

pub struct IdentifierTrustInformationDB {
    repository: Arc<dyn IdentifierTrustInformationRepository>,
}

impl IdentifierTrustInformationDB {
    pub fn new(repository: Arc<dyn IdentifierTrustInformationRepository>) -> Self {
        Self { repository }
    }

    pub async fn create(
        &self,
        identifier_id: IdentifierId,
        blob_id: BlobId,
        params: TestingIdentifierTrustInformationParams,
    ) -> IdentifierTrustInformation {
        let now = one_core::clock::now_utc();

        let trust_info = IdentifierTrustInformation {
            id: params.id.unwrap_or(IdentifierTrustInformationId::new()),
            created_date: now,
            last_modified: now,
            valid_from: params.valid_from,
            valid_to: params.valid_to,
            intended_use: params.intended_use,
            allowed_issuance_types: params.allowed_issuance_types.unwrap_or_default(),
            allowed_verification_types: params.allowed_verification_types.unwrap_or_default(),
            identifier_id,
            blob_id,
        };

        self.repository.create(trust_info.clone()).await.unwrap();

        trust_info
    }
}
