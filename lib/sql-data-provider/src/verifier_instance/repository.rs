use async_trait::async_trait;
use one_core::model::verifier_instance::{VerifierInstance, VerifierInstanceRelations};
use one_core::repository::error::DataLayerError;
use one_core::repository::verifier_instance_repository::VerifierInstanceRepository;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter};
use shared_types::{OrganisationId, VerifierInstanceId};

use super::VerifierInstanceProvider;
use crate::entity::verifier_instance;
use crate::mapper::to_data_layer_error;

#[async_trait]
impl VerifierInstanceRepository for VerifierInstanceProvider {
    async fn create(
        &self,
        request: VerifierInstance,
    ) -> Result<VerifierInstanceId, DataLayerError> {
        let model = verifier_instance::ActiveModel::try_from(request)?
            .insert(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        Ok(model.id)
    }

    async fn get(
        &self,
        id: &VerifierInstanceId,
        relations: &VerifierInstanceRelations,
    ) -> Result<Option<VerifierInstance>, DataLayerError> {
        let model = verifier_instance::Entity::find_by_id(id)
            .one(&self.db)
            .await
            .map_err(to_data_layer_error)?;
        let Some(model) = model else { return Ok(None) };

        let org_id = model.organisation_id;
        let mut verifier_instance = VerifierInstance::from(model);

        if let Some(org_relations) = &relations.organisation {
            let org = self
                .organisation_repository
                .get_organisation(&org_id, org_relations)
                .await?
                .ok_or(DataLayerError::MissingRequiredRelation {
                    relation: "verifier_instance-organisation",
                    id: org_id.to_string(),
                })?;
            verifier_instance.organisation = Some(org)
        }

        Ok(Some(verifier_instance))
    }

    async fn get_by_org_id(
        &self,
        organisation_id: &OrganisationId,
    ) -> Result<Option<VerifierInstance>, DataLayerError> {
        let model = verifier_instance::Entity::find()
            .filter(verifier_instance::Column::OrganisationId.eq(organisation_id))
            .one(&self.db)
            .await
            .map_err(to_data_layer_error)?;
        Ok(model.map(Into::into))
    }
}
