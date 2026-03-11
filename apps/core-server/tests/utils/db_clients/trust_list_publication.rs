use std::sync::Arc;

use one_core::model::identifier::Identifier;
use one_core::model::organisation::Organisation;
use one_core::model::trust_list_publication::{
    TrustListPublication, TrustListPublicationRelations, TrustListPublicationRoleEnum,
};
use one_core::repository::trust_list_publication_repository::TrustListPublicationRepository;
use shared_types::{CertificateId, KeyId, TrustListPublicationId, TrustListPublisherId};
use sql_data_provider::test_utilities::get_dummy_date;
use uuid::Uuid;

pub struct TrustListPublicationDB {
    repository: Arc<dyn TrustListPublicationRepository>,
}

impl TrustListPublicationDB {
    pub fn new(repository: Arc<dyn TrustListPublicationRepository>) -> Self {
        Self { repository }
    }

    #[expect(clippy::too_many_arguments)]
    pub async fn create(
        &self,
        name: &str,
        role: TrustListPublicationRoleEnum,
        r#type: TrustListPublisherId,
        metadata: Vec<u8>,
        organisation: Organisation,
        identifier: Option<Identifier>,
        key_id: Option<KeyId>,
        certificate_id: Option<CertificateId>,
    ) -> TrustListPublication {
        let trust_list_publication = TrustListPublication {
            id: TrustListPublicationId::from(Uuid::new_v4()),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            name: name.to_string(),
            role,
            r#type,
            metadata,
            deleted_at: None,
            content: None,
            sequence_number: 0,
            organisation_id: organisation.id,
            identifier_id: identifier.as_ref().map(|i| i.id),
            key_id,
            certificate_id,
            organisation: Some(organisation),
            identifier,
            key: None,
            certificate: None,
        };

        self.repository
            .create(trust_list_publication.clone())
            .await
            .unwrap();

        trust_list_publication
    }

    pub async fn get(&self, id: TrustListPublicationId) -> Option<TrustListPublication> {
        self.repository
            .get(
                id,
                &TrustListPublicationRelations {
                    organisation: Some(Default::default()),
                    identifier: Some(Default::default()),
                    key: Some(Default::default()),
                    certificate: Some(Default::default()),
                },
            )
            .await
            .unwrap()
    }
}
