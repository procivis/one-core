use std::sync::Arc;

use one_core::model::identifier::Identifier;
use one_core::model::revocation_list::{
    RevocationList, RevocationListEntityId, RevocationListEntry, RevocationListPurpose,
    RevocationListRelations, StatusListCredentialFormat, StatusListType,
};
use one_core::repository::revocation_list_repository::RevocationListRepository;
use shared_types::{CredentialId, IdentifierId, RevocationListId};
use sql_data_provider::test_utilities::get_dummy_date;
use uuid::Uuid;

pub struct RevocationListsDB {
    repository: Arc<dyn RevocationListRepository>,
}

impl RevocationListsDB {
    pub fn new(repository: Arc<dyn RevocationListRepository>) -> Self {
        Self { repository }
    }

    pub async fn create(
        &self,
        issuer_identifier: Identifier,
        purpose: RevocationListPurpose,
        credentials: Option<&[u8]>,
        status_list_type: Option<StatusListType>,
    ) -> RevocationList {
        let revocation_list = RevocationList {
            id: Uuid::new_v4().into(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            credentials: credentials.unwrap_or_default().to_owned(),
            purpose,
            issuer_identifier: Some(issuer_identifier),
            format: StatusListCredentialFormat::Jwt,
            r#type: status_list_type.unwrap_or(StatusListType::BitstringStatusList),
        };

        self.repository
            .create_revocation_list(revocation_list.to_owned())
            .await
            .unwrap();

        revocation_list
    }

    pub async fn get_revocation_by_issuer_identifier_id(
        &self,
        issuer_identifier_id: IdentifierId,
        purpose: RevocationListPurpose,
        status_list_type: StatusListType,
        relations: &RevocationListRelations,
    ) -> Option<RevocationList> {
        self.repository
            .get_revocation_by_issuer_identifier_id(
                issuer_identifier_id,
                purpose,
                status_list_type,
                relations,
            )
            .await
            .unwrap()
    }

    pub async fn create_credential_entry(
        &self,
        list_id: RevocationListId,
        credential_id: CredentialId,
        index_on_status_list: usize,
    ) {
        self.repository
            .create_entry(
                list_id,
                RevocationListEntityId::Credential(credential_id),
                index_on_status_list,
            )
            .await
            .unwrap()
    }

    pub async fn get_entries(&self, list_id: RevocationListId) -> Vec<RevocationListEntry> {
        self.repository.get_entries(list_id).await.unwrap()
    }
}
