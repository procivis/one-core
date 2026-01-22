use std::sync::Arc;

use one_core::model::certificate::Certificate;
use one_core::model::identifier::Identifier;
use one_core::model::revocation_list::{
    RevocationList, RevocationListEntityId, RevocationListEntry, RevocationListEntryStatus,
    RevocationListPurpose, RevocationListRelations, StatusListCredentialFormat,
    UpdateRevocationListEntryId, UpdateRevocationListEntryRequest,
};
use one_core::repository::revocation_list_repository::RevocationListRepository;
use shared_types::{
    CredentialId, IdentifierId, RevocationListEntryId, RevocationListId, RevocationMethodId,
};
use sql_data_provider::test_utilities::get_dummy_date;
use time::OffsetDateTime;
use uuid::Uuid;

pub struct RevocationListsDB {
    repository: Arc<dyn RevocationListRepository>,
}

#[derive(Debug, Default)]
pub struct TestingRevocationListParams {
    pub id: Option<RevocationListId>,
    pub created_date: Option<OffsetDateTime>,
    pub last_modified: Option<OffsetDateTime>,
    pub formatted_list: Option<Vec<u8>>,
    pub issuer_certificate: Option<Certificate>,
    pub purpose: Option<RevocationListPurpose>,
    pub format: Option<StatusListCredentialFormat>,
    pub r#type: Option<RevocationMethodId>,
}

impl RevocationListsDB {
    pub fn new(repository: Arc<dyn RevocationListRepository>) -> Self {
        Self { repository }
    }

    pub async fn create(
        &self,
        issuer_identifier: Identifier,
        params: Option<TestingRevocationListParams>,
    ) -> RevocationList {
        let params = params.unwrap_or_default();

        let revocation_list = RevocationList {
            id: params.id.unwrap_or(Uuid::new_v4().into()),
            created_date: params.created_date.unwrap_or(get_dummy_date()),
            last_modified: params.last_modified.unwrap_or(get_dummy_date()),
            formatted_list: params.formatted_list.unwrap_or_default(),
            purpose: params.purpose.unwrap_or(RevocationListPurpose::Revocation),
            issuer_identifier: Some(issuer_identifier),
            format: params.format.unwrap_or(StatusListCredentialFormat::Jwt),
            r#type: params.r#type.unwrap_or("BITSTRINGSTATUSLIST".into()),
            issuer_certificate: params.issuer_certificate,
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
        status_list_type: &RevocationMethodId,
        relations: &RevocationListRelations,
    ) -> Option<RevocationList> {
        self.repository
            .get_revocation_by_issuer_identifier_id(
                issuer_identifier_id,
                None,
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
        self.create_entry(
            list_id,
            RevocationListEntityId::Credential(credential_id),
            Some(index_on_status_list),
        )
        .await;
    }

    pub async fn create_entry(
        &self,
        list_id: RevocationListId,
        entity_id: RevocationListEntityId,
        index_on_status_list: Option<usize>,
    ) -> RevocationListEntryId {
        self.repository
            .create_entry(list_id, entity_id, index_on_status_list)
            .await
            .unwrap()
    }

    pub async fn update_entry(
        &self,
        list_id: RevocationListId,
        index_on_status_list: usize,
        status: Option<RevocationListEntryStatus>,
    ) {
        self.repository
            .update_entry(
                UpdateRevocationListEntryId::Index(list_id, index_on_status_list),
                UpdateRevocationListEntryRequest { status },
            )
            .await
            .unwrap();
    }

    pub async fn get_entries(&self, list_id: RevocationListId) -> Vec<RevocationListEntry> {
        self.repository.get_entries(list_id).await.unwrap()
    }
}
