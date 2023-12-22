use std::sync::Arc;

use one_core::model::did::Did;
use one_core::model::revocation_list::RevocationList;
use one_core::repository::revocation_list_repository::RevocationListRepository;
use sql_data_provider::test_utilities::get_dummy_date;

pub struct RevocationListsDB {
    repository: Arc<dyn RevocationListRepository>,
}

impl RevocationListsDB {
    pub fn new(repository: Arc<dyn RevocationListRepository>) -> Self {
        Self { repository }
    }

    pub async fn create(&self, issuer_did: &Did, credentials: Option<&[u8]>) -> RevocationList {
        let revocation_list = RevocationList {
            id: Default::default(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            credentials: credentials.unwrap_or_default().to_owned(),
            issuer_did: Some(issuer_did.to_owned()),
        };

        self.repository
            .create_revocation_list(revocation_list.to_owned())
            .await
            .unwrap();

        revocation_list
    }
}
