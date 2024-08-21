use std::sync::Arc;

use shared_types::OrganisationId;

use crate::model::{
    organisation::{Organisation, OrganisationRelations},
    relation::{Related, RelationLoader},
};

use super::error::DataLayerError;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait OrganisationRepository: Send + Sync {
    async fn create_organisation(
        &self,
        request: Organisation,
    ) -> Result<OrganisationId, DataLayerError>;

    async fn get_organisation(
        &self,
        id: &OrganisationId,
        relations: &OrganisationRelations,
    ) -> Result<Option<Organisation>, DataLayerError>;

    async fn get_organisation_list(&self) -> Result<Vec<Organisation>, DataLayerError>;
}

impl Related<Organisation> {
    pub fn from_organisation_id(
        organisation_id: OrganisationId,
        organisation_repository: Arc<dyn OrganisationRepository>,
    ) -> Self {
        struct OrganisationLoader {
            organisation_repository: Arc<dyn OrganisationRepository>,
        }

        #[async_trait::async_trait]
        impl RelationLoader<Organisation> for OrganisationLoader {
            async fn load(
                &self,
                organisation_id: &OrganisationId,
            ) -> Result<Organisation, DataLayerError> {
                let organisation = self
                    .organisation_repository
                    .get_organisation(organisation_id, &Default::default())
                    .await?;

                organisation.ok_or_else(|| DataLayerError::MissingRequiredRelation {
                    relation: "organisation",
                    id: organisation_id.to_string(),
                })
            }
        }

        Self::from_loader(
            organisation_id,
            Box::new(OrganisationLoader {
                organisation_repository,
            }),
        )
    }
}
