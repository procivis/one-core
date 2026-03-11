use std::sync::Arc;

use one_core::model::identifier::Identifier;
use one_core::model::trust_entry::{TrustEntry, TrustEntryRelations, TrustEntryStatusEnum};
use one_core::model::trust_list_publication::TrustListPublication;
use one_core::repository::trust_entry_repository::TrustEntryRepository;
use shared_types::TrustEntryId;
use sql_data_provider::test_utilities::get_dummy_date;
use uuid::Uuid;

pub struct TrustEntryDB {
    repository: Arc<dyn TrustEntryRepository>,
}

impl TrustEntryDB {
    pub fn new(repository: Arc<dyn TrustEntryRepository>) -> Self {
        Self { repository }
    }

    pub async fn create(
        &self,
        status: TrustEntryStatusEnum,
        metadata: Vec<u8>,
        trust_list_publication: TrustListPublication,
        identifier: Identifier,
    ) -> TrustEntry {
        let trust_entry = TrustEntry {
            id: TrustEntryId::from(Uuid::new_v4()),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            status,
            metadata,
            trust_list_publication_id: trust_list_publication.id,
            identifier_id: identifier.id,
            trust_list_publication: Some(trust_list_publication),
            identifier: Some(identifier),
        };

        self.repository.create(trust_entry.clone()).await.unwrap();

        trust_entry
    }

    pub async fn get(&self, id: TrustEntryId) -> Option<TrustEntry> {
        self.repository
            .get(
                id,
                &TrustEntryRelations {
                    trust_list_publication: Some(Default::default()),
                    identifier: Some(Default::default()),
                },
            )
            .await
            .unwrap()
    }
}
