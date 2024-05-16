use std::sync::Arc;

use one_core::{
    model::trust_anchor::{TrustAnchor, TrustAnchorRole},
    repository::trust_anchor_repository::TrustAnchorRepository,
};
use shared_types::OrganisationId;
use sql_data_provider::test_utilities::get_dummy_date;
use uuid::Uuid;

pub struct TrustAnchorDB {
    repository: Arc<dyn TrustAnchorRepository>,
}

impl TrustAnchorDB {
    pub fn new(repository: Arc<dyn TrustAnchorRepository>) -> Self {
        Self { repository }
    }

    pub async fn create(
        &self,
        name: &str,
        organisation_id: OrganisationId,
        type_: &str,
        role: TrustAnchorRole,
    ) -> TrustAnchor {
        let trust_anchor = TrustAnchor {
            id: Uuid::new_v4().into(),
            name: name.into(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            type_field: type_.into(),
            publisher_reference: "".into(),
            role,
            priority: 10,
            organisation_id,
        };

        self.repository.create(trust_anchor.clone()).await.unwrap();

        trust_anchor
    }
}
