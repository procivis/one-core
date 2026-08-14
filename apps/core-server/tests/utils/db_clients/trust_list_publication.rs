use std::sync::Arc;

use one_core::model::certificate::Certificate;
use one_core::model::identifier::Identifier;
use one_core::model::key::Key;
use one_core::model::organisation::Organisation;
use one_core::model::trust_list_publication::TrustListPublication;
use one_core::model::trust_list_role::TrustListRoleEnum;
use one_core::repository::error::DataLayerError;
use one_core::repository::trust_list_publication_repository::TrustListPublicationRepository;
use one_dto_mapper::convert_inner;
use shared_types::{TrustListPublicationId, TrustListPublisherId};
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
        role: TrustListRoleEnum,
        r#type: TrustListPublisherId,
        metadata: Vec<u8>,
        organisation: Organisation,
        identifier: Identifier,
        key: Option<Key>,
        certificate: Option<Certificate>,
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
            content: Vec::new(),
            sequence_number: 0,
            organisation: organisation.into(),
            identifier: identifier.into(),
            key: convert_inner(key),
            certificate: convert_inner(certificate),
        };

        self.repository
            .create(trust_list_publication.clone())
            .await
            .unwrap();

        trust_list_publication
    }

    pub async fn get(&self, id: TrustListPublicationId) -> Option<TrustListPublication> {
        match self.repository.get(id).await {
            Ok(publication) => Some(publication),
            Err(DataLayerError::EntityNotFound { .. }) => None,
            Err(err) => panic!("get trust list publication: {err}"),
        }
    }
}
