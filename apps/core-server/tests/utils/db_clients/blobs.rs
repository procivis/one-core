use std::sync::Arc;

use one_core::model::blob::{Blob, BlobType};
use one_core::repository::blob_repository::BlobRepository;
use shared_types::BlobId;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Default)]
pub struct TestingBlobParams {
    pub id: Option<BlobId>,
    pub created_date: Option<OffsetDateTime>,
    pub last_modified: Option<OffsetDateTime>,
    pub value: Option<Vec<u8>>,
    pub r#type: Option<BlobType>,
}

impl From<Blob> for TestingBlobParams {
    fn from(blob: Blob) -> Self {
        Self {
            id: Some(blob.id),
            created_date: Some(blob.created_date),
            last_modified: Some(blob.last_modified),
            value: Some(blob.value),
            r#type: Some(blob.r#type),
        }
    }
}

pub struct BlobsDB {
    repository: Arc<dyn BlobRepository>,
}

impl BlobsDB {
    pub fn new(repository: Arc<dyn BlobRepository>) -> Self {
        Self { repository }
    }

    pub async fn create(&self, params: TestingBlobParams) -> Blob {
        let now = OffsetDateTime::now_utc();

        let blob = Blob {
            id: params.id.unwrap_or(Uuid::new_v4().into()),
            created_date: params.created_date.unwrap_or(now),
            last_modified: params.last_modified.unwrap_or(now),
            value: params.value.unwrap_or(vec![1, 2, 3, 4, 5]),
            r#type: params.r#type.unwrap_or(BlobType::Credential),
        };

        self.repository.create(blob.clone()).await.unwrap();

        blob
    }

    pub async fn get(&self, blob_id: &BlobId) -> Option<Blob> {
        self.repository.get(blob_id).await.unwrap()
    }
}
